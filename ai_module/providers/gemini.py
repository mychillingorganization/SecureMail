from __future__ import annotations

import asyncio
import json
import time
from typing import Any

import httpx

from ai_module.config import AIAgentSettings
from ai_module.schemas import AnalyzeRequest, AnalyzeResponse
from ai_module.tools import TOOLS
from ai_module import thresholds
from ai_module.agent import get_gemini_tool_definitions


class GeminiProvider:
    provider_name = "gemini"

    def __init__(self, settings: AIAgentSettings) -> None:
        self._settings = settings
        self._last_primary_call_ts = 0.0

    async def _respect_rpm_limit(self) -> None:
        """Respect RPM rate limit for primary LLM calls."""
        rpm = max(1, int(self._settings.gemini_primary_rpm_limit))
        min_interval = 60.0 / float(rpm)
        now = time.monotonic()

        elapsed = now - self._last_primary_call_ts
        if elapsed < min_interval:
            await asyncio.sleep(min_interval - elapsed)

        self._last_primary_call_ts = time.monotonic()

    def _build_model_url(self, model_name: str, api_key: str) -> str:
        """Build Gemini API endpoint URL."""
        base_url = self._settings.google_ai_studio_base_url.rstrip("/")
        return f"{base_url}/models/{model_name}:generateContent?key={api_key}"

    def _normalize(self, parsed: dict[str, Any]) -> AnalyzeResponse:
        """Normalize and validate final decision JSON from LLM."""
        classify = str(parsed.get("classify", "safe")).strip().lower()
        if classify not in thresholds.VALID_CLASSIFY_VALUES:
            raise ValueError(f"invalid classify value: {classify}")
        
        reason = str(parsed.get("reason", "")).strip()
        if not reason:
            raise ValueError("reason cannot be empty")
        
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

    def _heuristic_fallback(self, payload: AnalyzeRequest, tool_history: list[dict[str, Any]], reason: str) -> AnalyzeResponse:
        """Fallback heuristic scoring when LLM analysis fails."""
        email = TOOLS["email_signal"](payload, {})
        web = TOOLS["web_signal"](payload, {})
        file_sig = TOOLS["file_signal"](payload, {})
        risk = TOOLS["risk_rollup"](payload, {})

        danger_reasons: list[str] = []
        safe_reasons: list[str] = []

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
        """Remove sensitive information (API keys) from error messages."""
        marker = "key="
        if marker not in text:
            return text
        prefix, suffix = text.split(marker, 1)
        if "&" in suffix:
            _key, rest = suffix.split("&", 1)
            return f"{prefix}{marker}***&{rest}"
        return f"{prefix}{marker}***"

    def _is_retryable_status(self, status_code: int) -> bool:
        """Check if HTTP status code is retryable."""
        return status_code in {408, 429, 500, 502, 503, 504}

    async def _sleep_for_retry(self, attempt: int, retry_after_header: str | None = None) -> None:
        """Sleep with exponential backoff before retry."""
        if retry_after_header:
            try:
                retry_after_seconds = float(retry_after_header)
                if retry_after_seconds > 0:
                    await asyncio.sleep(retry_after_seconds)
                    return
            except ValueError:
                pass

        base = max(0.1, float(self._settings.transient_retry_base_seconds))
        await asyncio.sleep(base * (2 ** (attempt - 1)))

    async def _request_json_with_tools(
        self,
        client: httpx.AsyncClient,
        url: str,
        api_key: str,
        model: str,
        system_prompt: str,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]],
    ) -> dict[str, Any]:
        """
        Request Gemini API with native function calling support.
        Returns structured response with potential function calls or final decision.
        """
        # Gemini API format: system_instruction for system context
        req_payload = {
            "system_instruction": {
                "parts": [{"text": system_prompt}]
            },
            "contents": messages,
            "tools": [{"function_declarations": tools}],
            "generationConfig": {
                "temperature": self._settings.autonomous_temperature,
                "max_output_tokens": 2048,
            },
        }
        
        max_retries = max(0, int(self._settings.transient_max_retries))
        for attempt in range(1, max_retries + 2):
            try:
                response = await client.post(url, json=req_payload)
                if self._is_retryable_status(response.status_code) and attempt <= max_retries:
                    await self._sleep_for_retry(attempt, response.headers.get("Retry-After"))
                    continue
                
                response.raise_for_status()
                body = response.json()
                
                # Extract function calls and final content
                result: dict[str, Any] = {}
                candidates = body.get("candidates", [])
                if candidates:
                    candidate = candidates[0]
                    content = candidate.get("content", {})
                    parts = content.get("parts", [])
                    
                    # Collect function calls
                    function_calls = []
                    text_output = ""
                    
                    for part in parts:
                        if "functionCall" in part:
                            func_call = part["functionCall"]
                            function_calls.append({
                                "name": func_call.get("name", ""),
                                "arguments": func_call.get("args", {}),
                            })
                        if "text" in part:
                            text_output += part["text"]
                    
                    if function_calls:
                        result["function_calls"] = function_calls
                    
                    if text_output:
                        # Parse text output as JSON if it looks like a final decision
                        try:
                            parsed = json.loads(text_output)
                            result.update(parsed)
                        except json.JSONDecodeError:
                            result["text"] = text_output
                    
                    return result
                
                # No candidates - return empty
                return {}
            
            except Exception as exc:
                if attempt > max_retries:
                    raise
                await self._sleep_for_retry(attempt)
        
        return {}

    async def _analyze_with_langgraph(self, payload: AnalyzeRequest, api_key: str) -> AnalyzeResponse:
        """
        Autonomous analysis using LangGraph + Gemini native function calling.
        No workflow restrictions - agent autonomously decides which tools to invoke.
        """
        model = self._settings.google_ai_studio_model
        url = self._build_model_url(model, api_key)
        
        max_iterations = max(1, int(self._settings.langgraph_max_iterations))
        timeout_total = max(5.0, float(self._settings.langgraph_timeout_seconds))
        backoff = max(0.1, float(self._settings.autonomous_retry_backoff_seconds))
        
        tool_definitions = get_gemini_tool_definitions()
        tool_history: list[dict[str, Any]] = []
        observations: dict[str, Any] = {}
        iteration = 0
        last_error: str | None = None
        
        request_timeout = max(5.0, float(self._settings.request_timeout_seconds))
        timeout = httpx.Timeout(
            connect=min(10.0, request_timeout),
            read=request_timeout,
            write=min(30.0, request_timeout),
            pool=min(30.0, request_timeout),
        )
        
        system_prompt = (
            "You are a security analysis expert analyzing email scan data.\n"
            "\n"
            "The payload structure contains:\n"
            "- auth: SPF/DKIM/DMARC results (if auth_summary is needed)\n"
            "- email_agent: Email content analysis results (if email_signal is needed)\n"
            "- file_module: Attachment analysis results (if file_signal is needed)\n"
            "- web_module: URL analysis results (if web_signal is needed)\n"
            "- urls: List of detected URLs (if url_domains is needed)\n"
            "- issue_count: Count of security signals detected\n"
            "- provisional_final_status: Current risk level before AI analysis\n"
            "\n"
            "Available tools: auth_summary, email_signal, file_signal, web_signal, url_domains, risk_rollup\n"
            "\n"
            "Autonomously decide which tools to call based on the data present:\n"
            "- If auth data exists → call auth_summary\n"
            "- If email_agent results exist → call email_signal\n"
            "- If file_module data exists → call file_signal\n"
            "- If web_module or URLs exist → call web_signal and url_domains\n"
            "- After analyzing relevant signals → call risk_rollup for final assessment\n"
            "\n"
            "Then respond with JSON: {classify, reason, summary, risk_factors, danger_reasons, safe_reasons, confidence_percent, should_escalate}\n"
            "classify must be: safe, suspicious, or dangerous"
        )
        
        user_message = f"Analyze this security scan:\n{json.dumps(payload.model_dump(), ensure_ascii=False)}"
        
        async with httpx.AsyncClient(timeout=timeout) as client:
            for iteration in range(max_iterations):
                try:
                    await self._respect_rpm_limit()
                    
                    # Build messages with tool history
                    messages = [{"role": "user", "parts": [{"text": user_message}]}]
                    
                    # Append tool results to conversation if we have history
                    if tool_history:
                        history_text = "Tool execution results:\n"
                        for tool_call in tool_history:
                            tool_name = tool_call.get("tool_name", "unknown")
                            result = tool_call.get("result", {})
                            history_text += f"- {tool_name}: {json.dumps(result, ensure_ascii=False)[:200]}...\n"
                        messages.append({"role": "user", "parts": [{"text": history_text}]})
                    
                    # Call Gemini with native function calling
                    response_json = await self._request_json_with_tools(
                        client=client,
                        url=url,
                        api_key=api_key,
                        model=model,
                        system_prompt=system_prompt,
                        messages=messages,
                        tools=tool_definitions,
                    )
                    
                    # Check if LLM decided to finish
                    if "final_decision" in response_json or response_json.get("classify"):
                        # LLM provided final decision
                        final_obj = response_json
                        result = self._normalize(final_obj)
                        result.tool_trace = tool_history
                        result.schema_review = {
                            "reviewer_model": self._settings.google_ai_studio_reviewer_model,
                            "valid": True,
                            "repaired": False,
                            "issues": ["langgraph: autonomous decision"],
                        }
                        if tool_history:
                            tools_used = {item.get("tool_name") for item in tool_history}
                            result.risk_factors = result.risk_factors + [
                                f"LangGraph autonomous steps: {len(tool_history)}",
                                f"Tools used: {', '.join(sorted(tools_used))}"
                            ]
                        return result
                    
                    # Check if LLM requested tool calls
                    function_calls = response_json.get("function_calls", [])
                    if not function_calls:
                        # No function calls and no final decision - odd state
                        # Try once more with error feedback
                        if iteration < max_iterations - 1:
                            user_message += "\n\nPlease provide either function calls or a final decision (classify, reason, etc.)."
                            await asyncio.sleep(backoff)
                            continue
                        else:
                            # Give up after max iterations
                            break
                    
                    # Execute requested tools
                    for func_call in function_calls:
                        tool_name = func_call.get("name", "").replace("call_", "")
                        tool_args = func_call.get("arguments", {})
                        
                        if tool_name not in TOOLS:
                            continue
                        
                        try:
                            tool_func = TOOLS[tool_name]
                            result = tool_func(payload, tool_args)
                            tool_history.append({
                                "step": len(tool_history) + 1,
                                "tool_name": tool_name,
                                "tool_args": tool_args,
                                "result": result,
                            })
                            observations[tool_name] = result
                        except Exception as e:
                            tool_history.append({
                                "step": len(tool_history) + 1,
                                "tool_name": tool_name,
                                "tool_args": tool_args,
                                "error": str(e),
                            })
                    
                    # Continue loop for next iteration
                    
                except Exception as exc:
                    last_error = self._sanitize_error(str(exc))
                    if iteration < max_iterations - 1:
                        await asyncio.sleep(backoff * (iteration + 1))
                    continue
        
        # Fallback if LangGraph loop completed without final decision
        if not tool_history:
            bootstrap = TOOLS["risk_rollup"](payload, {})
            tool_history.append({
                "step": 1,
                "tool_name": "risk_rollup",
                "tool_args": {},
                "tool_result": bootstrap,
            })
        
        return self._heuristic_fallback(
            payload=payload,
            tool_history=tool_history,
            reason=f"LangGraph autonomous analysis incomplete after {max_iterations} iterations: {last_error}",
        )

    async def analyze(self, payload: AnalyzeRequest) -> AnalyzeResponse:
        """
        Autonomous LLM-based security analysis using LangGraph + Gemini native function calling.
        No workflow restrictions - the agent autonomously decides which tools to invoke.
        """
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
        
        # LangGraph autonomous agent with native function calling
        return await self._analyze_with_langgraph(payload, api_key)
