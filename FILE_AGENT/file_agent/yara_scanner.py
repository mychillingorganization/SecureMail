"""
yara_scanner.py — Task 2.3
Quét IOC bằng YARA rules (tĩnh + memory dump)

Tải rules từ thư mục yara_rules/:
  - malware_index.yar      (community rules)
  - office_malware.yar     (Office-specific)
  - pe_packed.yar          (packer detection)

Severity mapping: critical=+0.5, high=+0.3, medium=+0.15, low=+0.05
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Optional

from models import YaraMatch, YaraScanResult

logger = logging.getLogger(__name__)

# Cache compiled rules để không compile lại mỗi lần
_compiled_rules: Optional[object] = None
_rules_mtime: float = 0.0


def _load_rules(rules_dir: Path) -> Optional[object]:
    """
    Load và compile tất cả .yar/.yara trong rules_dir.
    Dùng lazy compile + mtime check để không reload không cần thiết.
    """
    global _compiled_rules, _rules_mtime

    try:
        import yara
    except ImportError:
        logger.error("yara-python chưa được cài: pip install yara-python")
        return None

    yar_files = list(rules_dir.glob("**/*.yar")) + list(rules_dir.glob("**/*.yara"))
    if not yar_files:
        logger.warning(f"[YARA] Không tìm thấy rule file trong {rules_dir}")
        return None

    # Check if reload needed
    latest_mtime = max(f.stat().st_mtime for f in yar_files)
    if _compiled_rules is not None and latest_mtime <= _rules_mtime:
        return _compiled_rules

    try:
        filepaths = {str(i): str(f) for i, f in enumerate(yar_files)}
        _compiled_rules = yara.compile(filepaths=filepaths)
        _rules_mtime = latest_mtime
        logger.info(f"[YARA] Compiled {len(yar_files)} rule files")
        return _compiled_rules
    except yara.SyntaxError as e:
        logger.error(f"[YARA] Syntax error trong rule: {e}")
        return None
    except Exception as e:
        logger.error(f"[YARA] Lỗi compile rules: {e}")
        return None


def _severity_from_meta(meta: dict) -> str:
    """Suy ra severity từ YARA meta section (ưu tiên hơn tags)."""
    if isinstance(meta, dict):
        severity = meta.get("severity", "").lower()
        if severity in ("critical", "high", "medium", "low"):
            return severity
    return "low"


def _severity_from_tags(tags: list[str]) -> str:
    """Fallback: Suy ra severity từ YARA tags."""
    tags_lower = {t.lower() for t in tags}
    if "critical" in tags_lower:
        return "critical"
    if "high" in tags_lower or "malware" in tags_lower:
        return "high"
    if "medium" in tags_lower or "suspicious" in tags_lower:
        return "medium"
    return "low"


SEVERITY_DELTA = {
    "critical": 0.50,
    "high":     0.30,
    "medium":   0.15,
    "low":      0.05,
}


def scan_bytes(data: bytes, rules_dir: Path) -> YaraScanResult:
    """
    Quét bytes (file tĩnh hoặc memory dump) với YARA.

    Args:
        data:      bytes cần quét
        rules_dir: thư mục chứa .yar files

    Returns:
        YaraScanResult
    """
    result = YaraScanResult(scanned_size_bytes=len(data))

    rules = _load_rules(rules_dir)
    if rules is None:
        return result

    try:
        matches = rules.match(data=data)
    except Exception as e:
        logger.error(f"[YARA] Lỗi khi quét: {e}")
        return result

    yara_matches: list[YaraMatch] = []
    total_delta = 0.0

    for match in matches:
        tags = list(match.tags) if match.tags else []
        meta = match.meta if hasattr(match, "meta") else {}
        # Prioritize meta severity over tags
        severity = _severity_from_meta(meta) if meta else _severity_from_tags(tags)
        delta = SEVERITY_DELTA.get(severity, 0.15)

        # Trích strings matched (giới hạn 5 strings/rule để tránh noise)
        matched_strings = []
        for s in list(match.strings)[:5]:
            # match.strings là list tuple: (offset, identifier, data)
            try:
                matched_strings.append(f"{s.identifier}={s.instances[0].matched_data[:64].hex()}")
            except Exception:
                pass

        meta = match.meta if hasattr(match, "meta") else {}
        description = meta.get("description", meta.get("desc", None))

        yara_matches.append(YaraMatch(
            rule_name=match.rule,
            tags=tags,
            severity=severity,
            description=description,
            matched_strings=matched_strings,
        ))
        total_delta += delta

    result.matches = yara_matches
    result.risk_score_delta = min(total_delta, 0.80)  # cap tại 0.8

    if yara_matches:
        logger.info(
            f"[YARA] {len(yara_matches)} matches, "
            f"severities={[m.severity for m in yara_matches]}, "
            f"delta={result.risk_score_delta:.2f}"
        )

    return result