"""Single-email LLM classifier.

Supported providers: Groq (primary) and Google Gemma (fallback).
Input: --input-file (JSON with sender/subject/body or Subject/Content text) or CLI fields.
"""

import argparse
import json
import os
import re
import socket
import time
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional

MAX_RATE_LIMIT_WAIT = 120
MAX_RATE_LIMIT_RETRY = 3

DEFAULT_MODELS = {
    "groq": "qwen/qwen3-32b",
    "gemma": "gemma-3-27b-it",
}


DEFAULT_TEMPERATURE = 0.0


@dataclass
class EmailInput:
    sender: str = ""
    subject: str = ""
    body: str = ""


@dataclass
class AnalyzeResult:
    classification: str
    confidence: float
    reasoning: str
    provider: str
    model: str
    status: str = "ok"
    raw_error: str = ""


class APITokenLimitError(Exception):
    """Raised when provider quota/rate-limit is exhausted and cannot be retried."""


class GroqTokenLimitError(APITokenLimitError):
    pass


class GoogleTokenLimitError(APITokenLimitError):
    pass


def _parse_duration(val: str) -> Optional[float]:
    val = str(val).strip()
    try:
        return float(val)
    except ValueError:
        pass
    m = re.match(r"^(?:(\d+)m)?(?:(\d+(?:\.\d+)?)s)?$", val)
    if m and (m.group(1) or m.group(2)):
        return float(int(m.group(1) or 0) * 60 + float(m.group(2) or 0))
    return None


def _retry_after(exc: urllib.error.HTTPError, error_body: str) -> Optional[float]:
    for header in (
        "retry-after",
        "Retry-After",
        "x-ratelimit-reset-tokens",
        "x-ratelimit-reset-requests",
    ):
        raw = exc.headers.get(header, "")
        if raw:
            parsed = _parse_duration(raw)
            if parsed is not None:
                return parsed

    try:
        body_json = json.loads(error_body)
        for detail in body_json.get("error", {}).get("details", []):
            delay = detail.get("retryDelay", "")
            if delay:
                parsed = _parse_duration(str(delay))
                if parsed is not None:
                    return parsed

        for candidate in (
            body_json.get("retryDelay"),
            body_json.get("error", {}).get("retryDelay"),
        ):
            if candidate:
                parsed = _parse_duration(str(candidate))
                if parsed is not None:
                    return parsed
    except (json.JSONDecodeError, AttributeError):
        pass
    return None


def _extract_json_object(text: str) -> Dict[str, Any]:
    text = re.sub(r"<think>.*?</think>", "", text, flags=re.DOTALL).strip()
    text = re.sub(r"```(?:json)?", "", text).strip().rstrip("`").strip()

    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    match = re.search(r"\{.*\}", text, re.DOTALL)
    if match:
        try:
            return json.loads(match.group())
        except json.JSONDecodeError:
            return {}
    return {}


def _normalize_llm_result(parsed: Dict[str, Any], response_text: str) -> Dict[str, Any]:
    """Normalize model output and ensure a concise reasoning is always available."""
    raw_cls = str(parsed.get("classification", "")).strip().lower()
    classification = raw_cls if raw_cls in ("safe", "phishing") else "unknown"

    try:
        confidence = float(parsed.get("confidence", 0.0))
    except (TypeError, ValueError):
        confidence = 0.0
    confidence = max(0.0, min(1.0, confidence))

    reasoning = ""
    for key in ("reasoning", "analysis", "explanation", "rationale"):
        value = parsed.get(key)
        if isinstance(value, str) and value.strip():
            reasoning = value.strip()
            break

    if not reasoning:
        snippet = re.sub(r"\s+", " ", response_text).strip()[:180]
        if classification == "safe":
            reasoning = "Model predicted safe but did not provide explicit reasoning."
        elif classification == "phishing":
            reasoning = "Model predicted phishing but did not provide explicit reasoning."
        else:
            reasoning = "Model response did not include a valid reasoning field."
        if snippet:
            reasoning = f"{reasoning} Raw response: {snippet}"

    # Keep output concise and avoid accidental long thought-like text.
    reasoning = re.sub(r"\s+", " ", reasoning).strip()[:500]

    return {
        "classification": classification,
        "confidence": confidence,
        "reasoning": reasoning,
    }


class BaseAnalyzer:
    provider: str = ""

    def __init__(self, model: str, temperature: float = DEFAULT_TEMPERATURE):
        self.model = model
        self.temperature = float(temperature)

    def analyze(self, email: EmailInput) -> AnalyzeResult:
        raise NotImplementedError


class GroqContentAnalyzer(BaseAnalyzer):
    provider = "groq"

    def __init__(self, api_key: str, model: str, temperature: float = DEFAULT_TEMPERATURE):
        super().__init__(model=model, temperature=temperature)
        self.api_key = api_key
        self.api_url = "https://api.groq.com/openai/v1/chat/completions"
        self.timeout = 30
        self.max_retries = 2
        self.prompt_template = """You are a highly skilled cybersecurity analyst specializing in email threat detection.

Task: Analyze the email fields below and classify it as either "safe" or "phishing".

Classification Criteria:
- "phishing" (Treat this label as a catch-all for ANY malicious, scam, or dangerous email):
    * Emails aiming to steal credentials, fake brand identities, or demand payment.
    * Unsolicited SPAM or SCAM emails offering fake products or lottery wins.
    * Emails containing suspicious links combined with psychological triggers like urgency or fear.
- "safe":
    * Strictly legitimate communications, transactional receipts, meeting reminders, or verified business newsletters.

Sender:
{sender}

Subject:
{subject}

Email Body:
{body}

Important:
- Do not output chain-of-thought.
- Return only a short final reasoning sentence.

Return ONLY a valid JSON object with no extra text:
{{
  "classification": "safe" | "phishing",
  "confidence": <float 0.0-1.0>,
    "reasoning": "<concise explanation>"
}}"""

    def analyze(self, email: EmailInput) -> AnalyzeResult:
        prompt = self.prompt_template.format(
            sender=email.sender[:300],
            subject=email.subject[:500],
            body=email.body[:3000],
        )

        payload = {
            "model": self.model,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": self.temperature,
        }
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            self.api_url,
            data=data,
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self.api_key}",
                "User-Agent": "python-urllib/3.14",
            },
        )

        last_error = None
        net_attempts = 0
        rl_attempts = 0

        while net_attempts <= self.max_retries:
            try:
                with urllib.request.urlopen(req, timeout=self.timeout) as response:
                    result = json.loads(response.read().decode("utf-8"))
                    response_text = result["choices"][0]["message"]["content"]
                    parsed = _extract_json_object(response_text)
                    if parsed:
                        normalized = _normalize_llm_result(parsed, response_text)
                        return AnalyzeResult(
                            classification=normalized["classification"],
                            confidence=normalized["confidence"],
                            reasoning=normalized["reasoning"],
                            provider=self.provider,
                            model=self.model,
                        )
                    return AnalyzeResult(
                        classification="unknown",
                        confidence=0.0,
                        reasoning=f"Failed to parse LLM response: {response_text[:300]}",
                        provider=self.provider,
                        model=self.model,
                        status="parse_error",
                    )
            except urllib.error.HTTPError as e:
                error_body = e.read().decode("utf-8", errors="replace")
                if e.code == 429:
                    wait = _retry_after(e, error_body)
                    if wait is not None and wait <= MAX_RATE_LIMIT_WAIT and rl_attempts < MAX_RATE_LIMIT_RETRY:
                        rl_attempts += 1
                        print(
                            f"\n[~] Groq rate limit - waiting {wait:.0f}s "
                            f"(back-off {rl_attempts}/{MAX_RATE_LIMIT_RETRY}) ..."
                        )
                        time.sleep(wait)
                        continue
                    raise GroqTokenLimitError(
                        f"HTTP 429 from Groq (quota exhausted or retry limit reached): {error_body[:300]}"
                    )
                last_error = f"HTTP {e.code} {e.reason}: {error_body[:200]}"
            except (urllib.error.URLError, socket.timeout, TimeoutError) as e:
                last_error = str(e)

            net_attempts += 1

        return AnalyzeResult(
            classification="unknown",
            confidence=0.0,
            reasoning=f"API request failed after {self.max_retries} retries: {last_error}",
            provider=self.provider,
            model=self.model,
            status="request_error",
            raw_error=str(last_error or ""),
        )


class GoogleGemmaAnalyzer(BaseAnalyzer):
    provider = "gemma"

    def __init__(self, api_key: str, model: str, temperature: float = DEFAULT_TEMPERATURE):
        super().__init__(model=model, temperature=temperature)
        self.api_key = api_key
        self.api_url = (
            "https://generativelanguage.googleapis.com/v1beta/models/"
            f"{model}:generateContent?key={api_key}"
        )
        self.timeout = 30
        self.max_retries = 2
        self.prompt_template = """You are a highly skilled cybersecurity analyst specializing in email threat detection.

Task: Analyze the email fields below and classify it as either "safe" or "phishing".

Classification Criteria:
- "phishing": Emails that exploit psychological triggers to push recipients into action.
- "safe": Legitimate communications that lack high-pressure tactics or suspicious deception.

Sender:
{sender}

Subject:
{subject}

Email Body:
{body}

Return ONLY a valid JSON object with no extra text:
{{
  "classification": "safe" | "phishing",
  "confidence": <float 0.0-1.0>,
  "reasoning": "<concise explanation>"
}}"""
        self.prompt_template += (
            "\nImportant: Do not output chain-of-thought. "
            "Return only a short final reasoning sentence."
        )

    def analyze(self, email: EmailInput) -> AnalyzeResult:
        prompt = self.prompt_template.format(
            sender=email.sender[:300],
            subject=email.subject[:500],
            body=email.body[:3000],
        )

        payload = {
            "contents": [{"parts": [{"text": prompt}]}],
            "generationConfig": {"temperature": self.temperature},
        }

        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            self.api_url,
            data=data,
            headers={"Content-Type": "application/json"},
        )

        last_error = None
        net_attempts = 0
        rl_attempts = 0

        while net_attempts <= self.max_retries:
            try:
                with urllib.request.urlopen(req, timeout=self.timeout) as response:
                    result = json.loads(response.read().decode("utf-8"))
                    response_text = (
                        result.get("candidates", [{}])[0]
                        .get("content", {})
                        .get("parts", [{}])[0]
                        .get("text", "")
                    )
                    parsed = _extract_json_object(response_text)
                    if parsed:
                        normalized = _normalize_llm_result(parsed, response_text)
                        return AnalyzeResult(
                            classification=normalized["classification"],
                            confidence=normalized["confidence"],
                            reasoning=normalized["reasoning"],
                            provider=self.provider,
                            model=self.model,
                        )
                    return AnalyzeResult(
                        classification="unknown",
                        confidence=0.0,
                        reasoning=f"Failed to parse LLM response: {response_text[:300]}",
                        provider=self.provider,
                        model=self.model,
                        status="parse_error",
                    )
            except urllib.error.HTTPError as e:
                error_body = e.read().decode("utf-8", errors="replace")
                if e.code == 429:
                    wait = _retry_after(e, error_body)
                    if wait is not None and wait <= MAX_RATE_LIMIT_WAIT and rl_attempts < MAX_RATE_LIMIT_RETRY:
                        rl_attempts += 1
                        print(
                            f"\n[~] Google rate limit - waiting {wait:.0f}s "
                            f"(back-off {rl_attempts}/{MAX_RATE_LIMIT_RETRY}) ..."
                        )
                        time.sleep(wait)
                        continue
                    raise GoogleTokenLimitError(
                        "HTTP 429 from Google AI (quota exhausted or retry limit reached): "
                        f"{error_body[:300]}"
                    )
                last_error = f"HTTP {e.code} {e.reason}: {error_body[:200]}"
            except (urllib.error.URLError, socket.timeout, TimeoutError) as e:
                last_error = str(e)

            net_attempts += 1

        return AnalyzeResult(
            classification="unknown",
            confidence=0.0,
            reasoning=f"API request failed after {self.max_retries} retries: {last_error}",
            provider=self.provider,
            model=self.model,
            status="request_error",
            raw_error=str(last_error or ""),
        )


def load_config(config_path: Optional[str] = None) -> Dict[str, Any]:
    if config_path:
        path = Path(config_path)
    else:
        path = Path(__file__).with_name("config.json")

    if path.exists():
        with path.open(encoding="utf-8") as f:
            return json.load(f)
    return {}


def resolve_api_key(provider: str, cli_key: str, config: Dict[str, Any]) -> str:
    if cli_key:
        return cli_key

    if provider == "groq":
        return os.environ.get("GROQ_API_KEY", "") or str(config.get("groq_api_key", ""))
    if provider == "gemma":
        return os.environ.get("GOOGLE_API_KEY", "") or str(config.get("google_api_key", ""))
    return ""


def resolve_model(provider: str, model: str) -> str:
    return model or DEFAULT_MODELS[provider]


def get_analyzer(
    provider: str,
    model: str,
    temperature: float,
    api_key: str,
) -> BaseAnalyzer:
    if provider == "groq":
        if not api_key or api_key.startswith("gsk_REPLACE") or api_key == "groq_api_key":
            raise ValueError("Groq API key missing. Use --api-key, GROQ_API_KEY, or config.json groq_api_key.")
        return GroqContentAnalyzer(api_key=api_key, model=model, temperature=temperature)

    if provider == "gemma":
        if not api_key or api_key.startswith("AIza_REPLACE") or api_key == "google_api_key":
            raise ValueError(
                "Google API key missing. Use --api-key, GOOGLE_API_KEY, or config.json google_api_key."
            )
        return GoogleGemmaAnalyzer(api_key=api_key, model=model, temperature=temperature)

    raise ValueError(f"Unsupported provider: {provider}")


def parse_content_file(input_file: str) -> EmailInput:
    path = Path(input_file)
    raw = path.read_text(encoding="utf-8", errors="replace").strip()

    # Preferred format from extractor: JSON with sender/subject/body keys.
    try:
        obj = json.loads(raw)
        if isinstance(obj, dict):
            return EmailInput(
                sender=str(obj.get("sender", "") or ""),
                subject=str(obj.get("subject", "") or ""),
                body=str(obj.get("body", "") or ""),
            )
    except json.JSONDecodeError:
        pass

    subject_match = re.search(r"^Subject:\s*(.*)$", raw, flags=re.IGNORECASE | re.MULTILINE)
    content_match = re.search(r"^Content:\s*(.*)$", raw, flags=re.IGNORECASE | re.MULTILINE | re.DOTALL)

    if subject_match or content_match:
        return EmailInput(
            sender="",
            subject=(subject_match.group(1).strip() if subject_match else ""),
            body=(content_match.group(1).strip() if content_match else ""),
        )

    lines = [line.strip() for line in raw.splitlines() if line.strip()]
    if not lines:
        return EmailInput()

    subject = lines[0][:500]
    body = "\n".join(lines[1:]) if len(lines) > 1 else lines[0]
    return EmailInput(sender="", subject=subject, body=body)


def classify_once(
    email: EmailInput,
    provider: str,
    model: str,
    temperature: float,
    api_key: str,
    fallback_provider: str,
    fallback_model: str,
    fallback_api_key: str,
) -> Dict[str, Any]:
    started_at = datetime.now().isoformat()
    primary = get_analyzer(provider, model, temperature, api_key)

    def _summary() -> Dict[str, int]:
        return {
            "sender_len": len(email.sender),
            "subject_len": len(email.subject),
            "body_len": len(email.body),
        }

    try:
        result = primary.analyze(email)
        return {
            "run_at": started_at,
            "fallback_used": False,
            "input_summary": _summary(),
            "result": asdict(result),
        }
    except APITokenLimitError as e:
        if not fallback_provider:
            return {
                "run_at": started_at,
                "fallback_used": False,
                "result": {
                    "classification": "unknown",
                    "confidence": 0.0,
                    "reasoning": "Primary provider hit quota limit and no fallback was configured.",
                    "provider": provider,
                    "model": model,
                    "status": "quota_error",
                    "raw_error": str(e),
                },
            }

        backup = get_analyzer(fallback_provider, fallback_model, temperature, fallback_api_key)
        backup_result = backup.analyze(email)
        return {
            "run_at": started_at,
            "fallback_used": True,
            "fallback_reason": str(e),
            "input_summary": _summary(),
            "result": asdict(backup_result),
        }


def run_classify(args: argparse.Namespace, config: Dict[str, Any]) -> int:
    if args.input_file:
        email = parse_content_file(args.input_file)
    else:
        email = EmailInput(sender=args.sender or "", subject=args.subject or "", body=args.body or "")

    if not email.body:
        print("[!] Empty body. Provide --body or --input-file with JSON body/content text.")
        return 2

    provider = args.provider
    model = resolve_model(provider, args.model)
    api_key = resolve_api_key(provider, args.api_key, config)

    fallback_provider = args.fallback_provider
    if fallback_provider and fallback_provider == provider:
        print("[!] --fallback-provider must be different from --provider.")
        return 2

    fallback_model = resolve_model(fallback_provider, args.fallback_model) if fallback_provider else ""
    fallback_api_key = (
        resolve_api_key(fallback_provider, args.fallback_api_key, config) if fallback_provider else ""
    )

    result = classify_once(
        email=email,
        provider=provider,
        model=model,
        temperature=args.temperature,
        api_key=api_key,
        fallback_provider=fallback_provider,
        fallback_model=fallback_model,
        fallback_api_key=fallback_api_key,
    )

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(result, f, ensure_ascii=False, indent=2)

    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Single-email classification agent.")
    parser.add_argument("--config", default="", help="Path to config.json (default: same folder as script)")

    parser.add_argument("--provider", choices=["groq", "gemma"], default="groq")
    parser.add_argument("--api-key", default="", help="API key for primary provider")
    parser.add_argument("--model", default="", help="Primary model ID")
    parser.add_argument("--temperature", type=float, default=DEFAULT_TEMPERATURE)

    parser.add_argument("--fallback-provider", choices=["gemma", "groq"], default="")
    parser.add_argument("--fallback-api-key", default="", help="API key for fallback provider")
    parser.add_argument("--fallback-model", default="", help="Fallback model ID")

    parser.add_argument(
        "--input-file",
        default="",
        help="Path to input file: JSON {sender,subject,body} or text with Subject:/Content:",
    )
    parser.add_argument("--sender", default="")
    parser.add_argument("--subject", default="")
    parser.add_argument("--body", default="")
    parser.add_argument("--output", default="", help="Optional output JSON path")

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    config = load_config(args.config or None)
    return run_classify(args, config)


if __name__ == "__main__":
    raise SystemExit(main())
