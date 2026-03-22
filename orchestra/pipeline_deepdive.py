from __future__ import annotations

import hashlib
import json
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx
from sqlalchemy.ext.asyncio import AsyncSession

from email_agent.protocol_verifier import ProtocolVerifier
from orchestra.clients import AgentClient
from orchestra.config import Settings
from orchestra.early_termination import should_terminate
from orchestra.models import AuditLog, Email, EmailFile, EmailStatus, EmailUrl, EntityStatus, File, Url, VerdictType
from orchestra.risk_scorer import final_status_from_issue_count
from orchestra.schemas import ScanResponse
from orchestra.threat_intel import ThreatIntelScanner
from utils.parse_eml import parse_eml


@dataclass
class DeepDiveDependencies:
	settings: Settings
	email_client: AgentClient
	file_client: AgentClient
	web_client: AgentClient
	threat_scanner: ThreatIntelScanner
	protocol_verifier: ProtocolVerifier


def _hash_file(path: Path) -> str:
	hasher = hashlib.sha256()
	with path.open("rb") as handle:
		for chunk in iter(lambda: handle.read(8192), b""):
			hasher.update(chunk)
	return hasher.hexdigest()


def _hash_url(url: str) -> str:
	return hashlib.sha256(url.encode("utf-8", errors="ignore")).hexdigest()


def _verdict_type_from_status(status: str) -> VerdictType:
	if status == "DANGER":
		return VerdictType.malicious
	if status == "WARNING":
		return VerdictType.suspicious
	return VerdictType.safe


async def _upsert_url(session: AsyncSession, raw_url: str, status: EntityStatus) -> str:
	url_hash = _hash_url(raw_url)
	db_obj = await session.get(Url, url_hash)
	if db_obj is None:
		db_obj = Url(url_hash=url_hash, raw_url=raw_url, status=status)
		session.add(db_obj)
	else:
		db_obj.status = status
	return url_hash


async def _upsert_file(session: AsyncSession, file_hash: str, file_path: str, status: EntityStatus) -> str:
	db_obj = await session.get(File, file_hash)
	if db_obj is None:
		db_obj = File(file_hash=file_hash, file_path=file_path, status=status)
		session.add(db_obj)
	else:
		db_obj.status = status
		db_obj.file_path = file_path
	return file_hash


class DeepDiveAnalyzer:
	"""Google AI Studio deep-dive analysis for suspicious scans."""

	def __init__(self, settings: Settings) -> None:
		self._settings = settings

	async def analyze(self, payload: dict[str, Any]) -> dict[str, Any]:
		api_key = self._settings.google_ai_studio_api_key
		if not api_key:
			return {
				"available": False,
				"summary": "LLM deep-dive skipped: API key is not configured.",
				"risk_factors": [],
				"confidence_percent": 0,
				"should_escalate": False,
			}

		model = self._settings.google_ai_studio_model
		base_url = self._settings.google_ai_studio_base_url.rstrip("/")
		url = f"{base_url}/models/{model}:generateContent?key={api_key}"

		prompt = (
			"You are an email security analyst.\n"
			"Given the scan context below, produce strict JSON only.\n"
			"If the email is clearly malicious and dangerous, set should_escalate=true.\n\n"
			f"Context:\n{json.dumps(payload, ensure_ascii=False)}\n\n"
			"Output JSON schema:\n"
			"{\n"
			'  "summary": "short explanation",\n'
			'  "risk_factors": ["factor1", "factor2"],\n'
			'  "confidence_percent": 0,\n'
			'  "should_escalate": false\n'
			"}\n"
		)

		req_payload = {
			"contents": [{"role": "user", "parts": [{"text": prompt}]}],
			"generationConfig": {
				"temperature": 0.2,
				"responseMimeType": "application/json",
			},
		}

		try:
			async with httpx.AsyncClient(timeout=self._settings.request_timeout_seconds) as client:
				response = await client.post(url, json=req_payload)
				response.raise_for_status()
				body = response.json()

			text = str(body["candidates"][0]["content"]["parts"][0]["text"])
			parsed = json.loads(text)
			confidence = int(parsed.get("confidence_percent", 0))
			return {
				"available": True,
				"summary": str(parsed.get("summary", "")),
				"risk_factors": [str(x) for x in parsed.get("risk_factors", [])],
				"confidence_percent": max(0, min(100, confidence)),
				"should_escalate": bool(parsed.get("should_escalate", False)),
			}
		except Exception as exc:
			return {
				"available": False,
				"summary": f"LLM deep-dive failed: {exc}",
				"risk_factors": [],
				"confidence_percent": 0,
				"should_escalate": False,
			}


async def execute_pipeline_deepdive(
	email_path: str,
	session: AsyncSession,
	settings: Settings,
	user_accepts_danger: bool = False,
) -> ScanResponse:
	issue_count = 0
	termination_reason: str | None = None
	logs: list[str] = []

	threat_hashes = {item.strip() for item in settings.threat_intel_malicious_hashes.split(",") if item.strip()}
	deps = DeepDiveDependencies(
		settings=settings,
		email_client=AgentClient(settings.email_agent_url, settings.request_timeout_seconds),
		file_client=AgentClient(settings.file_agent_url, settings.request_timeout_seconds),
		web_client=AgentClient(settings.web_agent_url, settings.request_timeout_seconds),
		threat_scanner=ThreatIntelScanner(threat_hashes),
		protocol_verifier=ProtocolVerifier(),
	)

	email_path_obj = Path(email_path)
	with tempfile.TemporaryDirectory(prefix="securemail-orch-llm-") as temp_dir:
		attachment_dir = Path(temp_dir) / "attachments"
		attachment_dir.mkdir(parents=True, exist_ok=True)

		parsed = parse_eml(email_path_obj, attachment_dir)
		logs.append("[INFO] Step 1: utils.parse_eml() - SUCCESS")

		auth_result = deps.protocol_verifier.verify_from_eml_file(email_path_obj)
		spf_ok = bool(auth_result.get("spf", {}).get("pass", False))
		dkim_ok = bool(auth_result.get("dkim", {}).get("pass", False))
		dmarc_ok = bool(auth_result.get("dmarc", {}).get("pass", False))
		auth_failed = not (spf_ok and dkim_ok and dmarc_ok)
		logs.append(f"[INFO] Step 2: protocol verification - SPF={spf_ok} DKIM={dkim_ok} DMARC={dmarc_ok}")

		decision = should_terminate(
			issue_count=issue_count,
			auth_failed=auth_failed,
			malicious_detected=False,
			reason="Auth Failure: SPF/DKIM/DMARC failed",
		)
		attachment_hashes: list[tuple[str, str]] = []
		if decision.halt:
			termination_reason = decision.reason
			logs.append(f"[HALT] Step 2: {termination_reason}")
		else:
			malicious_hash_detected = False
			for attachment in attachment_dir.iterdir():
				if not attachment.is_file():
					continue
				attachment_hash = _hash_file(attachment)
				attachment_hashes.append((attachment_hash, str(attachment)))
				scan_result = deps.threat_scanner.scan_hash(attachment_hash)
				if scan_result.verdict == "MALICIOUS":
					malicious_hash_detected = True
					termination_reason = f"Malicious file hash detected: {attachment_hash}"
					logs.append(f"[HALT] Step 3: {termination_reason}")
					break
			if not malicious_hash_detected:
				logs.append("[INFO] Step 3: attachment hash triage - SAFE")

			decision = should_terminate(
				issue_count=issue_count,
				auth_failed=False,
				malicious_detected=malicious_hash_detected,
				reason=termination_reason,
			)

			email_resp: dict[str, Any] = {}
			file_signals: list[dict[str, Any]] = []
			web_resp: dict[str, Any] = {}

			if not decision.halt:
				body_text = "\n\n".join(parsed.plain_parts)
				email_payload = {
					"email_id": parsed.subject,
					"headers": parsed.auth_headers,
					"body_text": body_text,
					"timestamp": parsed.sent_at,
				}
				try:
					email_resp = await deps.email_client.analyze(email_payload)
					email_risk = float(email_resp.get("risk_score", 0.0))
					if email_risk >= deps.settings.email_suspicious_threshold:
						issue_count += 1
						logs.append(f"[WARNING] Step 4: EmailAgent suspicious - issue_count={issue_count}")
					else:
						logs.append("[INFO] Step 4: EmailAgent - PASS")
				except Exception as exc:
					issue_count += 1
					logs.append(f"[WARNING] Step 4: EmailAgent unavailable ({exc}) - issue_count={issue_count}")

				decision = should_terminate(issue_count=issue_count, auth_failed=False, malicious_detected=False)
				if decision.halt:
					termination_reason = decision.reason
					logs.append(f"[HALT] Step 4: {termination_reason}")

			if not decision.halt:
				if attachment_hashes:
					try:
						for file_hash, path in attachment_hashes:
							file_resp = await deps.file_client.analyze_file(path)
							file_signals.append(file_resp)

							file_label = str(file_resp.get("label", "safe")).lower()
							file_risk_level = str(file_resp.get("risk_level", "")).lower()
							file_risk_score = float(file_resp.get("risk_score", 0.0))

							if file_label in {"malicious", "phishing"} or file_risk_level in {"high", "critical"} or file_risk_score >= 0.7:
								termination_reason = f"FileAgent detected malicious attachment: {Path(path).name}"
								logs.append(f"[HALT] Step 5: {termination_reason}")
								decision = should_terminate(
									issue_count=issue_count,
									auth_failed=False,
									malicious_detected=True,
									reason=termination_reason,
								)
								break

							if file_risk_level == "medium" or file_risk_score >= 0.4:
								issue_count += 1
								logs.append(
									f"[WARNING] Step 5: FileAgent suspicious ({Path(path).name}) - issue_count={issue_count}"
								)
							else:
								logs.append(f"[INFO] Step 5: FileAgent - PASS ({Path(path).name})")
					except Exception as exc:
						if deps.settings.count_file_agent_unavailable_as_issue:
							issue_count += 1
							logs.append(f"[WARNING] Step 5: FileAgent unavailable ({exc}) - issue_count={issue_count}")
						else:
							logs.append(f"[INFO] Step 5: FileAgent unavailable ({exc}) - degraded mode, no issue increment")
				else:
					logs.append("[INFO] Step 5: FileAgent skipped - no attachments")

				if not decision.halt:
					decision = should_terminate(issue_count=issue_count, auth_failed=False, malicious_detected=False)
				if decision.halt and termination_reason is None:
					termination_reason = decision.reason
					logs.append(f"[HALT] Step 5: {termination_reason}")

			if not decision.halt:
				urls = sorted(parsed.urls)
				if urls:
					try:
						web_resp = await deps.web_client.analyze({"email_id": parsed.subject, "urls": urls})
						web_label = str(web_resp.get("label", "safe")).lower()
						if web_label in {"malicious", "phishing"}:
							termination_reason = "WebAgent detected phishing URL"
							logs.append(f"[HALT] Step 6: {termination_reason}")
							decision = should_terminate(issue_count=issue_count, auth_failed=False, malicious_detected=True, reason=termination_reason)
						elif web_resp.get("risk_score", 0.0) >= 0.5:
							issue_count += 1
							logs.append(f"[WARNING] Step 6: WebAgent suspicious - issue_count={issue_count}")
						else:
							logs.append("[INFO] Step 6: WebAgent - PASS")
					except Exception as exc:
						issue_count += 1
						logs.append(f"[WARNING] Step 6: WebAgent unavailable ({exc}) - issue_count={issue_count}")
				else:
					logs.append("[INFO] Step 6: WebAgent skipped - no URLs")

				if not decision.halt:
					decision = should_terminate(issue_count=issue_count, auth_failed=False, malicious_detected=False)
				if decision.halt and termination_reason is None:
					termination_reason = decision.reason
					logs.append(f"[HALT] Step 6: {termination_reason}")

			final_status = "DANGER" if decision.halt else final_status_from_issue_count(issue_count)

			deepdive = DeepDiveAnalyzer(settings)
			llm_payload = {
				"subject": parsed.subject,
				"sender": parsed.auth_headers.get("from", [None])[0] if parsed.auth_headers.get("from") else None,
				"auth": {
					"spf": auth_result.get("spf", {}),
					"dkim": auth_result.get("dkim", {}),
					"dmarc": auth_result.get("dmarc", {}),
				},
				"email_agent": email_resp,
				"file_agent": file_signals,
				"web_agent": web_resp,
				"issue_count": issue_count,
				"provisional_final_status": final_status,
				"termination_reason": termination_reason,
				"urls": sorted(parsed.urls),
			}
			llm_result = await deepdive.analyze(llm_payload)

			logs.append(f"[INFO] Step 7: LLM summary - {llm_result.get('summary', '')}")
			if llm_result.get("risk_factors"):
				logs.append(f"[INFO] Step 7: LLM risk factors - {', '.join(llm_result['risk_factors'])}")
			logs.append(f"[INFO] Step 7: LLM confidence={llm_result.get('confidence_percent', 0)}")

			if (
				final_status != "DANGER"
				and llm_result.get("should_escalate")
				and int(llm_result.get("confidence_percent", 0)) >= 70
			):
				final_status = "DANGER"
				termination_reason = llm_result.get("summary") or "LLM deep-dive escalated the verdict"
				logs.append(f"[HALT] Step 7: {termination_reason}")

			logs.append(f"[INFO] Step 8: Final verdict = {final_status}")

			email_row = Email(
				message_id=parsed.subject,
				sender=parsed.auth_headers.get("from", [None])[0] if parsed.auth_headers.get("from") else None,
				receiver=parsed.auth_headers.get("to", [None])[0] if parsed.auth_headers.get("to") else None,
				status=EmailStatus.quarantined if final_status == "DANGER" else EmailStatus.completed,
				total_risk_score=float(issue_count),
				final_verdict=_verdict_type_from_status(final_status),
			)
			session.add(email_row)
			await session.flush()

			session.add(
				AuditLog(
					email_id=email_row.id,
					agent_name="Orchestrator-LLM",
					reasoning_trace={
						"issue_count": issue_count,
						"termination_reason": termination_reason,
						"llm_result": llm_result,
						"logs": logs,
					},
					cryptographic_hash=None,
				)
			)

			for url in sorted(parsed.urls):
				default_status = EntityStatus.malicious if final_status == "DANGER" and user_accepts_danger else EntityStatus.unknown
				url_hash = await _upsert_url(session, url, default_status)
				session.add(EmailUrl(email_id=email_row.id, url_hash=url_hash))

			for file_hash, file_path in attachment_hashes:
				default_status = EntityStatus.malicious if final_status == "DANGER" and user_accepts_danger else EntityStatus.unknown
				row_hash = await _upsert_file(session, file_hash, file_path, default_status)
				session.add(EmailFile(email_id=email_row.id, file_hash=row_hash))

			await session.commit()

	return ScanResponse(
		final_status=final_status,
		issue_count=issue_count,
		termination_reason=termination_reason,
		execution_logs=logs,
	)
