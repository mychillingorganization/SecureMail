from __future__ import annotations

import asyncio
import json
import time
from typing import Any
from urllib.parse import urlsplit, urlunsplit

import httpx

from ai_agent.config import AIAgentSettings
from ai_agent.schemas import AnalyzeRequest, AnalyzeResponse
from ai_agent.tools import TOOLS
from ai_agent import thresholds


class GeminiProvider:
    provider_name = "gemini"

    def __init__(self, settings: AIAgentSettings) -> None:
        self._settings = settings
        self._last_primary_call_ts = 0.0
        self._last_reviewer_call_ts = 0.0

    async def _respect_rpm_limit(self, *, is_reviewer: bool) -> None:
        rpm = self._settings.gemma_reviewer_rpm_limit if is_reviewer else self._settings.gemini_primary_rpm_limit
        rpm = max(1, int(rpm))
        min_interval = 60.0 / float(rpm)
        now = time.monotonic()

        last_ts = self._last_reviewer_call_ts if is_reviewer else self._last_primary_call_ts
        elapsed = now - last_ts
        if elapsed < min_interval:
            await asyncio.sleep(min_interval - elapsed)

        updated_now = time.monotonic()
        if is_reviewer:
            self._last_reviewer_call_ts = updated_now
        else:
            self._last_primary_call_ts = updated_now

    def _has_file_targets(self, payload: AnalyzeRequest) -> bool:
        return bool(payload.file_agent)

    def _has_url_targets(self, payload: AnalyzeRequest) -> bool:
        return bool(payload.urls)

    def _required_sequence_for_payload(self, payload: AnalyzeRequest) -> list[str]:
        sequence = ["auth_summary", "email_signal"]
        if self._has_file_targets(payload):
            sequence.append("file_signal")
        if self._has_url_targets(payload):
            sequence.extend(["web_signal", "url_domains"])
        sequence.append("risk_rollup")
        return sequence

    def _canonicalize_url(self, raw: str) -> str:
        candidate = str(raw).strip()
        if not candidate:
            return ""
        parsed = urlsplit(candidate)
        scheme = parsed.scheme.lower() or "https"
        netloc = parsed.netloc.lower()
        path = parsed.path or ""
        query = parsed.query or ""
        return urlunsplit((scheme, netloc, path, query, ""))

    def _validate_tool_targets(
        self,
        payload: AnalyzeRequest,
        tool_name: str,
        tool_args: dict[str, Any],
    ) -> tuple[bool, str, dict[str, Any]]:
        sanitized = dict(tool_args)

        if tool_name == "file_signal":
            if not self._has_file_targets(payload):
                return False, "file_signal is not available: payload has no attachments", sanitized
            if "file_indices" in sanitized:
                raw = sanitized.get("file_indices")
                if not isinstance(raw, list):
                    return False, "file_indices must be a list of integers", sanitized
                validated: list[int] = []
                max_idx = len(payload.file_agent) - 1
                for item in raw:
                    try:
                        idx = int(item)
                    except (TypeError, ValueError):
                        return False, f"invalid file index: {item}", sanitized
                    if idx < 0 or idx > max_idx:
                        return False, f"file index out of range: {idx} (0..{max_idx})", sanitized
                    validated.append(idx)
                sanitized["file_indices"] = sorted(set(validated))

        if tool_name in {"web_signal", "url_domains"}:
            if not self._has_url_targets(payload):
                return False, f"{tool_name} is not available: payload has no URLs", sanitized
            if "urls" in sanitized:
                raw_urls = sanitized.get("urls")
                if not isinstance(raw_urls, list):
                    return False, "urls must be a list of strings", sanitized
                allowed = {self._canonicalize_url(url) for url in payload.urls if self._canonicalize_url(url)}
                validated_urls: list[str] = []
                for item in raw_urls:
                    normalized = self._canonicalize_url(str(item))
                    if not normalized:
                        continue
                    if normalized not in allowed:
                        return False, f"url target not in payload: {item}", sanitized
                    validated_urls.append(normalized)
                sanitized["urls"] = sorted(set(validated_urls))

        return True, "", sanitized

    def _build_model_url(self, model_name: str, api_key: str) -> str:
        base_url = self._settings.google_ai_studio_base_url.rstrip("/")
        return f"{base_url}/models/{model_name}:generateContent?key={api_key}"

    def _build_prompt(self, payload: AnalyzeRequest, feedback: str | None = None, tool_history: list[dict[str, Any]] | None = None) -> str:
        required_sequence = self._required_sequence_for_payload(payload)
        completed = [item.get("tool_name") for item in (tool_history or []) if isinstance(item, dict)]
        prompt = (
            "You are an autonomous email security analyst with structured tool-use capability.\n"
            "Follow required tool sequence for THIS email payload (adaptive by available targets).\n"
            f"Required sequence for this request: {' -> '.join(required_sequence)} -> final\n"
            f"Already completed in this request: {completed if completed else 'none'}\n\n"
            "CRITICAL RULE: In each call, action MUST be either 'call_tool' OR 'final'.\n"
            "YOU CANNOT SKIP STEPS. If you try to skip or repeat, the request will be rejected.\n"
            "EACH RESPONSE must contain exactly ONE action: either ONE tool call or the final answer.\n\n"
            "Tool-enabled action schema:\n"
            "{\n"
            '  "action": "call_tool" | "final",\n'
            '  "thought": "short reasoning why this step",\n'
            '  "tool_name": "auth_summary|email_signal|file_signal|web_signal|url_domains|risk_rollup",\n'
            '  "tool_args": {},\n'
            '  "final": {\n'
            '    "classify": "safe|suspicious|dangerous",\n'
            '    "reason": "concise explanation of classification decision",\n'
            '    "summary": "additional context (optional)",\n'
            '    "risk_factors": ["factor1"],\n'
            '    "danger_reasons": ["reason1"],\n'
            '    "safe_reasons": ["reason1"],\n'
            '    "confidence_percent": 0,\n'
            '    "should_escalate": false\n'
            "  }\n"
            "}\n\n"
            "MANDATORY RULES:\n"
            "1) You MUST call only tools in the required sequence shown above, exactly once, in order.\n"
            "2) If there are no file targets, file_signal is not required and must not be called.\n"
            "3) If there are no URL targets, web_signal/url_domains are not required and must not be called.\n"
            "4) You CANNOT return final until all required tools are executed in strict order.\n"
            "4) classify must be exactly one of: safe, suspicious, dangerous.\n"
            "5) reason must be non-empty and concise (1-2 sentences).\n"
            "6) confidence_percent must be integer 0-100.\n\n"
            f"Initial context:\n{json.dumps(payload.model_dump(), ensure_ascii=False)}\n"
        )
        if feedback:
            prompt += (
                "\nPrevious attempt validation FAILED. Reason:\n"
                f"{feedback}\n\n"
                "⚠️ You must comply with the sequence. Do not retry the same tool.\n"
            )
        return prompt

    def _build_followup_prompt(self, payload: AnalyzeRequest, history: list[dict[str, Any]], feedback: str | None = None) -> str:
        status = self._get_required_tool_sequence_status(payload, history)
        next_required = status["next_required"]
        awaiting_final = next_required is None
        
        lines = [
            "Continue autonomous analysis. Follow the required sequence for this payload.",
            f"REQUIRED SEQUENCE: {' -> '.join(status['required_sequence'])} -> final",
            f"Progress completed: {' → '.join(status['called_so_far']) if status['called_so_far'] else 'nothing yet'}",
            f"You are NOW at STEP {status['step_count']}",
            f"ZERO FLEXIBILITY: You MUST call tool_name='{next_required}' in your JSON response" if not awaiting_final else "All required tools are done; return final.",
            f"Remaining tools: {', '.join(status['still_needed']) if status['still_needed'] else 'none, return final'}",
            "",
            "YOUR JSON RESPONSE MUST LOOK EXACTLY LIKE THIS:",
            "{",
            '  "action": "call_tool",' if not awaiting_final else '  "action": "final",',
            f'  "tool_name": "{next_required}",' if not awaiting_final else '  "final": {"classify": "safe|suspicious|dangerous", "reason": "...", "confidence_percent": 0},',
            '  "tool_args": {},' if not awaiting_final else '  "thought": "all required tools completed, returning final"',
            '  "thought": "explanation of why calling this tool now"' if not awaiting_final else '  "summary": "optional"',
            "}",
            "",
            "Do NOT deviate from this format." if awaiting_final else "Do NOT deviate from this format. Do NOT use action='final' yet.",
            "",
            f"Email context:",
            json.dumps(payload.model_dump(), ensure_ascii=False),
            "",
            f"Tools you've already called and their results:",
            json.dumps(history, ensure_ascii=False),
        ]
        
        if feedback:
            lines.extend(["", f"⚠️ System message: {feedback}"])
        
        lines.extend([
            "",
            "🔴 MANDATORY COMPLIANCE RULES (violation = rejection):",
            "✓ Set action to 'final'" if awaiting_final else "✓ Set action to 'call_tool' (not 'final')",
            "✓ Provide final classify/reason fields" if awaiting_final else f"✓ Set tool_name to '{next_required}' (exactly this)",
            f"✓ Never call a tool twice (you've called {status['called_so_far']})",
            "✓ Never skip a tool in the sequence",
            "✓ final is allowed now" if awaiting_final else f"✓ {len(status['still_needed'])} more tools must be called before 'final' is allowed",
        ])
        
        return "\n".join(lines)

    def _normalize(self, parsed: dict[str, Any]) -> AnalyzeResponse:
        # New primary contract: classify + reason
        classify = str(parsed.get("classify", "safe")).strip().lower()
        if classify not in thresholds.VALID_CLASSIFY_VALUES:
            raise ValueError(f"invalid classify value: {classify}")
        
        reason = str(parsed.get("reason", "")).strip()
        if not reason:
            raise ValueError("reason cannot be empty")
        
        # Compatibility fields (derive from primary contract if not provided)
        summary = str(parsed.get("summary", "")).strip()
        if not summary:
            summary = reason  # Fallback summary to reason
        
        raw_conf = parsed.get("confidence_percent", 75 if classify == "safe" else 70)
        try:
            confidence = int(raw_conf)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"invalid confidence_percent: {raw_conf}") from exc

        risk_factors = [str(x).strip() for x in parsed.get("risk_factors", []) if str(x).strip()]
        danger_reasons = [str(x).strip() for x in parsed.get("danger_reasons", []) if str(x).strip()]
        safe_reasons = [str(x).strip() for x in parsed.get("safe_reasons", []) if str(x).strip()]
        
        # Derive should_escalate from classify if not provided
        should_escalate = bool(parsed.get("should_escalate", classify == "dangerous"))
        return AnalyzeResponse(
            available=True,
            classify=classify,
            reason=reason,
            summary=summary,
            risk_factors=risk_factors,
            danger_reasons=danger_reasons,
            safe_reasons=safe_reasons,
            confidence_percent=max(0, min(100, confidence)),
            should_escalate=should_escalate,
            provider=self.provider_name,
            schema_review={},
        )

    def _build_reviewer_prompt(self, candidate_final: dict[str, Any]) -> str:
        return (
            "You are a strict JSON schema reviewer and repair assistant.\n"
            "Your only task: validate and repair the candidate final object so it follows required schema exactly.\n"
            "Return JSON only with this shape:\n"
            "{\n"
            '  "final": {\n'
            '    "classify": "safe|suspicious|dangerous",\n'
            '    "reason": "non-empty short explanation",\n'
            '    "summary": "string",\n'
            '    "risk_factors": ["string"],\n'
            '    "danger_reasons": ["string"],\n'
            '    "safe_reasons": ["string"],\n'
            '    "confidence_percent": 0,\n'
            '    "should_escalate": false\n'
            "  },\n"
            '  "schema_review": {\n'
            '    "reviewer_model": "string",\n'
            '    "valid": true,\n'
            '    "repaired": false,\n'
            '    "issues": ["string"]\n'
            "  }\n"
            "}\n"
            "Rules:\n"
            "- classify must be one of safe/suspicious/dangerous (lowercase).\n"
            "- reason must not be empty.\n"
            "- confidence_percent must be integer 0..100.\n"
            "- Always return all keys above.\n"
            "- If candidate is invalid, repair it minimally and set repaired=true with issues listed.\n"
            f"Candidate JSON:\n{json.dumps(candidate_final, ensure_ascii=False)}"
        )

    async def _review_final_json(
        self,
        client: httpx.AsyncClient,
        api_key: str,
        candidate_final: dict[str, Any],
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        if not self._settings.json_reviewer_enabled:
            return candidate_final, {
                "reviewer_model": None,
                "valid": True,
                "repaired": False,
                "issues": ["json reviewer disabled"],
            }

        reviewer_model = self._settings.google_ai_studio_reviewer_model
        reviewer_url = self._build_model_url(reviewer_model, api_key)
        reviewer_prompt = self._build_reviewer_prompt(candidate_final)
        max_attempts = max(1, int(self._settings.json_reviewer_max_attempts))

        last_error: str | None = None
        for _ in range(max_attempts):
            try:
                await self._respect_rpm_limit(is_reviewer=True)
                reviewer_obj = await self._request_json(client, reviewer_url, reviewer_prompt)
                final_obj = reviewer_obj.get("final")
                if not isinstance(final_obj, dict):
                    raise ValueError("reviewer output missing 'final' object")

                review = reviewer_obj.get("schema_review")
                if not isinstance(review, dict):
                    review = {}

                issues = review.get("issues", [])
                if not isinstance(issues, list):
                    issues = [str(issues)]

                return final_obj, {
                    "reviewer_model": reviewer_model,
                    "valid": bool(review.get("valid", True)),
                    "repaired": bool(review.get("repaired", False)),
                    "issues": [str(x) for x in issues],
                }
            except Exception as exc:
                last_error = self._sanitize_error(str(exc))

        return candidate_final, {
            "reviewer_model": reviewer_model,
            "valid": False,
            "repaired": False,
            "issues": [f"reviewer_failed: {last_error}"],
        }

    def _normalize_action(self, action_obj: dict[str, Any]) -> str:
        action_raw = str(action_obj.get("action", "")).strip().lower()
        if action_raw in {"call_tool", "final"}:
            return action_raw

        # Graceful normalization for model drift in action naming.
        if action_raw in {"respond", "answer", "deliver_email", "deliver", "return"}:
            return "final"

        # If action is missing but final payload-like fields are present, treat as final.
        if any(
            key in action_obj
            for key in (
                "classify",
                "reason",
                "summary",
                "risk_factors",
                "danger_reasons",
                "safe_reasons",
                "should_escalate",
            )
        ):
            return "final"
        if isinstance(action_obj.get("final"), dict):
            return "final"

        return "unknown"

    def _validate_tool_coverage(self, payload: AnalyzeRequest, tool_history: list[dict[str, Any]]) -> tuple[bool, str]:
        """Check if tool history has minimum mandatory coverage."""
        required = self._required_sequence_for_payload(payload)
        called = [item.get("tool_name") for item in tool_history if isinstance(item, dict)]
        called_set = set(called)
        missing = [tool for tool in required if tool not in called_set]
        
        if missing:
            return False, f"Missing required tools for this payload: {', '.join(missing)}"
        
        if thresholds.MANDATORY_SYNTHESIS_TOOL not in called_set:
            return False, f"Must call {thresholds.MANDATORY_SYNTHESIS_TOOL} before final synthesis"
        
        expected_count = len(required)
        if len(called_set) < expected_count:
            return False, f"Insufficient tool coverage: {len(called_set)} tools (required {expected_count})"
        
        return True, ""

    def _get_required_tool_sequence_status(self, payload: AnalyzeRequest, tool_history: list[dict[str, Any]]) -> dict[str, Any]:
        """Get the ordered sequence of required tools and which ones are still needed."""
        required_sequence = self._required_sequence_for_payload(payload)
        
        tools_called_ordered = [item.get("tool_name") for item in tool_history if isinstance(item, dict)]
        tools_called_set = set(tools_called_ordered)
        
        # Find the first required tool not yet called
        next_required = None
        for tool in required_sequence:
            if tool not in tools_called_set:
                next_required = tool
                break
        
        return {
            "required_sequence": required_sequence,
            "called_so_far": tools_called_ordered,
            "still_needed": [t for t in required_sequence if t not in tools_called_set],
            "next_required": next_required,
            "step_count": len(tools_called_ordered) + 1,
        }

    def _heuristic_fallback(self, payload: AnalyzeRequest, tool_history: list[dict[str, Any]], reason: str) -> AnalyzeResponse:
        # Deterministic fallback so downstream still receives schema-stable output.
        auth = TOOLS["auth_summary"](payload, {})
        email = TOOLS["email_signal"](payload, {})
        web = TOOLS["web_signal"](payload, {})
        file_sig = TOOLS["file_signal"](payload, {})
        risk = TOOLS["risk_rollup"](payload, {})

        danger_reasons: list[str] = []
        safe_reasons: list[str] = []

        if not auth.get("auth_all_pass", False):
            danger_reasons.append("Authentication checks are not fully passed")
        else:
            safe_reasons.append("SPF/DKIM/DMARC checks passed")

        if email.get("is_suspicious"):
            danger_reasons.append("Email agent flagged suspicious signal")
        else:
            safe_reasons.append("Email agent did not flag suspicious signal")

        if web.get("is_suspicious"):
            danger_reasons.append("Web agent reported suspicious URL signal")
        else:
            safe_reasons.append("Web agent did not report suspicious URL signal")

        if int(file_sig.get("suspicious_count", 0)) > 0:
            danger_reasons.append("Some attachments were flagged for review")
        else:
            safe_reasons.append("Attachments did not trigger suspicious thresholds")

        composite = float(risk.get("composite_risk", 0.0))
        
        # Derive classify from thresholds config
        if payload.provisional_final_status == "DANGER" or composite >= thresholds.COMPOSITE_RISK_DANGEROUS_THRESHOLD or len(danger_reasons) >= thresholds.MIN_DANGER_REASONS_TO_ESCALATE:
            classify = thresholds.CLASSIFY_DANGEROUS
            confidence = thresholds.DEFAULT_CONFIDENCE_DANGEROUS
        elif composite >= thresholds.COMPOSITE_RISK_SUSPICIOUS_THRESHOLD or len(danger_reasons) >= 1:
            classify = thresholds.CLASSIFY_SUSPICIOUS
            confidence = thresholds.DEFAULT_CONFIDENCE_SUSPICIOUS
        else:
            classify = thresholds.CLASSIFY_SAFE
            confidence = thresholds.DEFAULT_CONFIDENCE_SAFE
        
        should_escalate = classify == thresholds.CLASSIFY_DANGEROUS
        
        # Generate reason from evidence
        fallback_reason = f"Classification: {classify}. {len(danger_reasons)} danger signals, {len(safe_reasons)} safe signals."
        summary = (
            "Fallback autonomous reasoning indicates elevated risk."
            if should_escalate
            else "Fallback autonomous reasoning indicates low-to-moderate risk with no critical signal."
        )

        return AnalyzeResponse(
            available=True,
            classify=classify,
            reason=fallback_reason,
            summary=summary,
            risk_factors=[
                f"Heuristic composite_risk={composite}",
                f"Fallback trigger: {reason}",
                f"Autonomous tool-use steps={len(tool_history)}",
            ],
            danger_reasons=danger_reasons,
            safe_reasons=safe_reasons,
            confidence_percent=confidence,
            should_escalate=should_escalate,
            provider=self.provider_name,
            tool_trace=tool_history,
            schema_review={
                "reviewer_model": self._settings.google_ai_studio_reviewer_model,
                "valid": False,
                "repaired": False,
                "issues": ["skipped: fallback path, no final JSON from model"],
            },
        )

    def _sanitize_error(self, text: str) -> str:
        marker = "key="
        if marker not in text:
            return text
        prefix, suffix = text.split(marker, 1)
        if "&" in suffix:
            _key, rest = suffix.split("&", 1)
            return f"{prefix}{marker}***&{rest}"
        return f"{prefix}{marker}***"

    def _extract_model_text(self, body: dict[str, Any]) -> str:
        return str(body["candidates"][0]["content"]["parts"][0]["text"])

    async def _request_json(self, client: httpx.AsyncClient, url: str, prompt: str) -> dict[str, Any]:
        req_payload = {
            "contents": [{"role": "user", "parts": [{"text": prompt}]}],
            "generationConfig": {
                "temperature": self._settings.autonomous_temperature,
                "responseMimeType": "application/json",
            },
        }
        response = await client.post(url, json=req_payload)
        response.raise_for_status()
        body = response.json()
        text = self._extract_model_text(body)
        parsed = json.loads(text)
        if isinstance(parsed, list):
            first_obj = next((item for item in parsed if isinstance(item, dict)), None)
            if first_obj is None:
                raise ValueError("model output list does not contain object item")
            parsed = first_obj
        if not isinstance(parsed, dict):
            raise ValueError(f"model output must be object, got {type(parsed).__name__}")
        return parsed

    async def analyze(self, payload: AnalyzeRequest) -> AnalyzeResponse:
        api_key = self._settings.google_ai_studio_api_key
        if not api_key:
            return AnalyzeResponse(
                available=False,
                classify="safe",
                reason="LLM deep-dive skipped: API key is not configured.",
                summary="LLM deep-dive skipped: API key is not configured.",
                risk_factors=[],
                danger_reasons=[],
                safe_reasons=["No Gemini API key configured."],
                confidence_percent=0,
                should_escalate=False,
                provider=self.provider_name,
                tool_trace=[],
                schema_review={
                    "reviewer_model": self._settings.google_ai_studio_reviewer_model,
                    "valid": False,
                    "repaired": False,
                    "issues": ["skipped: missing API key"],
                },
            )

        model = self._settings.google_ai_studio_model
        url = self._build_model_url(model, api_key)

        max_attempts = max(1, int(self._settings.autonomous_max_attempts))
        max_tool_steps = max(1, int(self._settings.autonomous_max_tool_steps))
        backoff = max(0.1, float(self._settings.autonomous_retry_backoff_seconds))
        feedback: str | None = None
        last_error: str | None = None
        tool_history: list[dict[str, Any]] = []

        async with httpx.AsyncClient(timeout=self._settings.request_timeout_seconds) as client:
            for attempt in range(1, max_attempts + 1):
                try:
                    if tool_history:
                        action_prompt = self._build_followup_prompt(payload, tool_history, feedback=feedback)
                    else:
                        action_prompt = self._build_prompt(payload, feedback=feedback, tool_history=tool_history)

                    for tool_step in range(1, max_tool_steps + 1):
                        await self._respect_rpm_limit(is_reviewer=False)
                        action_obj = await self._request_json(client, url, action_prompt)
                        action = self._normalize_action(action_obj)

                        if action == "final":
                            # Validate mandatory tool coverage before accepting final
                            coverage_ok, coverage_msg = self._validate_tool_coverage(payload, tool_history)
                            if not coverage_ok:
                                action_prompt = self._build_followup_prompt(
                                    payload,
                                    tool_history,
                                    feedback=f"Cannot return final yet. {coverage_msg}. Continue with mandatory tools.",
                                )
                                continue
                            final_candidate = action_obj.get("final")
                            final_obj = final_candidate if isinstance(final_candidate, dict) else action_obj
                            if not isinstance(final_obj, dict):
                                raise ValueError("final output must be an object")

                            result: AnalyzeResponse
                            schema_review: dict[str, Any]
                            should_review = not bool(self._settings.json_reviewer_on_error_only)
                            if not should_review:
                                try:
                                    result = self._normalize(final_obj)
                                    schema_review = {
                                        "reviewer_model": self._settings.google_ai_studio_reviewer_model,
                                        "valid": True,
                                        "repaired": False,
                                        "issues": ["reviewer skipped: candidate already valid"],
                                    }
                                except Exception:
                                    should_review = True

                            if should_review:
                                reviewed_final, schema_review = await self._review_final_json(
                                    client=client,
                                    api_key=api_key,
                                    candidate_final=final_obj,
                                )
                                result = self._normalize(reviewed_final)

                            result.schema_review = schema_review
                            if tool_history:
                                tools_used = {item.get("tool_name") for item in tool_history if isinstance(item, dict)}
                                result.tool_trace = tool_history
                                result.risk_factors = result.risk_factors + [
                                    f"Autonomous tool-use steps={len(tool_history)}",
                                    f"Tools used: {', '.join(sorted(tools_used))}"
                                ]
                            if attempt > 1:
                                result.risk_factors = result.risk_factors + [f"Autonomous recovery succeeded on attempt {attempt}"]
                            return result

                        if action == "call_tool":
                            tool_name = str(action_obj.get("tool_name", "")).strip()
                            tool_args = action_obj.get("tool_args", {})
                            if not isinstance(tool_args, dict):
                                tool_args = {}
                            if tool_name not in TOOLS:
                                action_prompt = self._build_followup_prompt(
                                    payload,
                                    tool_history,
                                    feedback=f"Unknown tool '{tool_name}'. Use only allowed tools.",
                                )
                                continue

                            status = self._get_required_tool_sequence_status(payload, tool_history)
                            expected_next = status.get("next_required")
                            if expected_next is None:
                                action_prompt = self._build_followup_prompt(
                                    payload,
                                    tool_history,
                                    feedback="All required tools are already completed. Return final now.",
                                )
                                continue
                            if tool_name != expected_next:
                                action_prompt = self._build_followup_prompt(
                                    payload,
                                    tool_history,
                                    feedback=f"Wrong tool order: expected '{expected_next}' next, got '{tool_name}'.",
                                )
                                continue
                            
                            # Check if tool was already called (repeated tool call)
                            tools_already_called = {item.get("tool_name") for item in tool_history if isinstance(item, dict)}
                            if tool_name in tools_already_called:
                                # Reject this repeated call - don't add to history, ask to call correct next tool
                                step_num = next((i for i, item in enumerate(tool_history, 1) if item.get('tool_name') == tool_name), "?")
                                repeated_error = (
                                    f"ERROR: Tool '{tool_name}' was already called in step {step_num}.\n"
                                    f"Cannot call the same tool twice.\n"
                                    f"You MUST call '{status['next_required']}' next."
                                )
                                action_prompt = (
                                    "REJECTED: Repeated tool call detected.\n"
                                    f"{repeated_error}\n"
                                    f"Sequence so far: {' → '.join(status['called_so_far'])}\n"
                                    f"You must call: {status['next_required']}\n\n"
                                    + self._build_followup_prompt(
                                        payload,
                                        tool_history,
                                        feedback=repeated_error,
                                    )
                                )
                                continue

                            targets_ok, targets_msg, validated_args = self._validate_tool_targets(payload, tool_name, tool_args)
                            if not targets_ok:
                                action_prompt = self._build_followup_prompt(
                                    payload,
                                    tool_history,
                                    feedback=f"Target validation failed for '{tool_name}': {targets_msg}",
                                )
                                continue

                            tool_result = TOOLS[tool_name](payload, validated_args)
                            tool_history.append({
                                "step": len(tool_history) + 1,
                                "tool_name": tool_name,
                                "tool_args": validated_args,
                                "tool_result": tool_result,
                            })
                            action_prompt = self._build_followup_prompt(payload, tool_history)
                            continue

                        action_prompt = self._build_followup_prompt(
                            payload,
                            tool_history,
                            feedback=f"Invalid action '{action_obj.get('action')}'. Return JSON with action=call_tool or action=final.",
                        )
                        continue

                    raise ValueError("tool-use loop exhausted before final action")

                except Exception as exc:
                    last_error = self._sanitize_error(str(exc))
                    feedback = f"attempt={attempt}, error={exc}"
                    if attempt < max_attempts:
                        await asyncio.sleep(backoff * attempt)

        if not tool_history:
            # Ensure at least one tool-use trace for observability in fallback mode.
            bootstrap = TOOLS["risk_rollup"](payload, {})
            tool_history.append(
                {
                    "step": 1,
                    "tool_name": "risk_rollup",
                    "tool_args": {},
                    "tool_result": bootstrap,
                }
            )

        return self._heuristic_fallback(
            payload=payload,
            tool_history=tool_history,
            reason=f"LLM deep-dive failed after {max_attempts} autonomous attempts: {last_error}",
        )
