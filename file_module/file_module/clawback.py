"""
clawback.py — Task 2.5
Cơ chế thu hồi sau giao nhận (Post-Delivery Clawback)

Mô phỏng luồng:
  Email vượt qua đường nhanh → giao nhận → sandbox hoàn thành
  → phát hiện mối đe dọa → cách ly hồi tố

Hành động hỗ trợ:
  - quarantine_email:  đánh dấu cách ly email trong mail server (giả lập)
  - delete_attachment: xóa tệp đính kèm độc hại
  - alert_user:        gửi cảnh báo đến người nhận
  - block_sender:      chặn địa chỉ người gửi

Trong môi trường thực:
  - Gọi Exchange/O365 API để di chuyển email vào Quarantine folder
  - Gọi Gmail API (REST) để xóa attachment
"""
from __future__ import annotations

import logging
from datetime import datetime
from typing import Optional

from .models import AnalysisResult, RiskLevel

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────
# Clawback Result
# ─────────────────────────────────────────────

class ClawbackResult:
    def __init__(self):
        self.triggered:     bool           = False
        self.reason:        str            = ""
        self.actions_taken: list[str]      = []
        self.timestamp:     str            = datetime.utcnow().isoformat()
        self.success:       bool           = False
        self.error:         Optional[str]  = None

    def to_dict(self) -> dict:
        return {
            "triggered":     self.triggered,
            "reason":        self.reason,
            "actions_taken": self.actions_taken,
            "timestamp":     self.timestamp,
            "success":       self.success,
            "error":         self.error,
        }


# ─────────────────────────────────────────────
# Mail server adapter (stub — thay bằng API thực)
# ─────────────────────────────────────────────

class MailServerAdapter:
    """
    Adapter giả lập mail server API.
    Trong production: thay bằng Exchange EWS, O365 Graph API, hoặc Gmail API.
    """

    def __init__(self, server: str = "localhost", api_key: str = ""):
        self.server  = server
        self.api_key = api_key
        self._simulated_quarantine: list[dict] = []

    def quarantine_email(self, message_id: str, reason: str) -> bool:
        """Chuyển email vào thư mục Quarantine."""
        logger.info(f"[Clawback] QUARANTINE email: {message_id} | reason: {reason}")
        self._simulated_quarantine.append({
            "message_id": message_id,
            "action":     "quarantine",
            "reason":     reason,
            "time":       datetime.utcnow().isoformat(),
        })
        # Simulate success (trong production: gọi API)
        return True

    def delete_attachment(self, message_id: str, attachment_name: str) -> bool:
        """Xóa tệp đính kèm khỏi email đã giao."""
        logger.info(f"[Clawback] DELETE attachment: {attachment_name} from {message_id}")
        self._simulated_quarantine.append({
            "message_id":      message_id,
            "action":          "delete_attachment",
            "attachment_name": attachment_name,
            "time":            datetime.utcnow().isoformat(),
        })
        return True

    def alert_user(self, recipient_email: str, threat_info: dict) -> bool:
        """Gửi cảnh báo đến người nhận email."""
        logger.info(
            f"[Clawback] ALERT user: {recipient_email} | "
            f"threat={threat_info.get('risk_level')} file={threat_info.get('filename')}"
        )
        return True

    def block_sender(self, sender_email: str, reason: str) -> bool:
        """Thêm sender vào blocklist."""
        logger.info(f"[Clawback] BLOCK sender: {sender_email} | reason: {reason}")
        return True

    def get_quarantine_log(self) -> list[dict]:
        return list(self._simulated_quarantine)


# ─────────────────────────────────────────────
# Clawback engine
# ─────────────────────────────────────────────

# Singleton adapter cho demo
_mail_adapter = MailServerAdapter()


def _should_clawback(result: AnalysisResult) -> tuple[bool, str]:
    """
    Xác định có cần thực hiện clawback không.
    Returns: (should_clawback, reason)
    """
    if result.risk_level == RiskLevel.CRITICAL:
        return True, f"Mức độ rủi ro CRITICAL (score={result.risk_score:.2f})"

    if result.risk_level == RiskLevel.HIGH:
        return True, f"Mức độ rủi ro HIGH (score={result.risk_score:.2f})"

    if result.ioc_matched:
        return True, "Hash khớp IOC database"

    if result.sandbox and result.sandbox.c2_indicators:
        return True, f"Phát hiện C2 indicators: {result.sandbox.c2_indicators[:3]}"

    return False, ""


def execute_clawback(
    result: AnalysisResult,
    message_id: Optional[str] = None,
    recipient_email: Optional[str] = None,
    sender_email: Optional[str] = None,
) -> ClawbackResult:
    """
    Thực hiện post-delivery clawback nếu cần thiết.

    Args:
        result:          AnalysisResult đã hoàn thành
        message_id:      ID email gốc (None = mô phỏng)
        recipient_email: Địa chỉ người nhận
        sender_email:    Địa chỉ người gửi

    Returns:
        ClawbackResult
    """
    clawback = ClawbackResult()

    # Kiểm tra có cần clawback không
    should, reason = _should_clawback(result)
    clawback.triggered = should

    if not should:
        clawback.reason  = f"Không cần clawback: {result.risk_level.value}"
        clawback.success = True
        logger.info(f"[Clawback] Không cần thiết: {result.risk_level.value}")
        return clawback

    clawback.reason = reason
    logger.warning(f"[Clawback] Khởi động clawback: {reason}")

    # Dùng simulated message_id nếu không có
    msg_id = message_id or f"<simulated-{result.analysis_id[:8]}@fileagent.local>"
    all_ok = True

    # ── Hành động 1: Cách ly email ────────────────────────────
    ok1 = _mail_adapter.quarantine_email(msg_id, reason)
    if ok1:
        clawback.actions_taken.append(f"quarantine_email:{msg_id}")
    else:
        all_ok = False
        clawback.error = "Quarantine thất bại"

    # ── Hành động 2: Xóa tệp đính kèm ────────────────────────
    ok2 = _mail_adapter.delete_attachment(msg_id, result.filename)
    if ok2:
        clawback.actions_taken.append(f"delete_attachment:{result.filename}")
    else:
        all_ok = False

    # ── Hành động 3: Cảnh báo người nhận ─────────────────────
    if recipient_email:
        threat_info = {
            "filename":   result.filename,
            "risk_level": result.risk_level.value,
            "sha256":     result.hash_triage.sha256[:16] + "...",
            "reason":     reason,
        }
        ok3 = _mail_adapter.alert_user(recipient_email, threat_info)
        if ok3:
            clawback.actions_taken.append(f"alert_user:{recipient_email}")

    # ── Hành động 4: Chặn sender (chỉ khi CRITICAL) ──────────
    if result.risk_level == RiskLevel.CRITICAL and sender_email:
        ok4 = _mail_adapter.block_sender(sender_email, reason)
        if ok4:
            clawback.actions_taken.append(f"block_sender:{sender_email}")

    clawback.success = all_ok

    logger.info(
        f"[Clawback] Hoàn thành: success={all_ok} "
        f"actions={clawback.actions_taken}"
    )

    return clawback


def get_quarantine_log() -> list[dict]:
    """Lấy log tất cả các lần clawback đã thực hiện."""
    return _mail_adapter.get_quarantine_log()
