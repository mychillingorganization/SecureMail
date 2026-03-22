"""
pe_analyzer.py — Task 2.3
Phân tích PE header cho .exe/.dll/.msi dùng pefile

Phát hiện:
  - Imports đáng ngờ (injection, persistence, download)
  - Entropy cao theo section → payload đóng gói/mã hóa
  - Packer signatures: UPX, ASPack, Themida
  - TLS callbacks (anti-debug technique)
  - Compile timestamp bất thường
"""
from __future__ import annotations

import logging
import math
import struct
from datetime import datetime, timezone
from typing import Optional

from models import PeAnalysisResult, PeSection

logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────
# Suspicious imports theo nhóm
# ─────────────────────────────────────────────
SUSPICIOUS_IMPORTS: dict[str, list[str]] = {
    "process_injection": [
        "CreateRemoteThread",
        "VirtualAllocEx",
        "WriteProcessMemory",
        "NtCreateThreadEx",
        "RtlCreateUserThread",
        "QueueUserAPC",
    ],
    "persistence": [
        "RegSetValueExA",
        "RegSetValueExW",
        "RegCreateKeyExA",
        "RegCreateKeyExW",
        "SHSetValue",
    ],
    "download_execute": [
        "URLDownloadToFileA",
        "URLDownloadToFileW",
        "InternetOpenA",
        "InternetOpenW",
        "WinExec",
        "ShellExecuteA",
        "ShellExecuteExA",
        "CreateProcessA",
    ],
    "anti_analysis": [
        "IsDebuggerPresent",
        "CheckRemoteDebuggerPresent",
        "NtQueryInformationProcess",
        "GetTickCount",
        "QueryPerformanceCounter",
        "OutputDebugStringA",
    ],
    "crypto": [
        "CryptEncrypt",
        "CryptDecrypt",
        "CryptImportKey",
        "BCryptEncrypt",
    ],
}

FLAT_SUSPICIOUS = {fn for fns in SUSPICIOUS_IMPORTS.values() for fn in fns}


# ─────────────────────────────────────────────
# Packer signatures (section names / entry point)
# ─────────────────────────────────────────────
PACKER_SIGNATURES: dict[str, list[str]] = {
    "UPX":     ["UPX0", "UPX1", "UPX2"],
    "ASPack":  [".aspack", ".adata"],
    "Themida": [".themida", ".winlicen"],
    "PECompact": [".pec", "pec2"],
    "FSG":     [".nsp0", ".nsp1"],
    "Petite":  [".petite"],
    "MPRESS":  [".MPRESS1", ".MPRESS2"],
}


# ─────────────────────────────────────────────
# Entropy calculation
# ─────────────────────────────────────────────

def _entropy(data: bytes) -> float:
    """Shannon entropy của một chuỗi bytes."""
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    length = len(data)
    return -sum(
        (f / length) * math.log2(f / length)
        for f in freq if f > 0
    )


# ─────────────────────────────────────────────
# Main analyzer
# ─────────────────────────────────────────────

def analyze_pe(data: bytes) -> PeAnalysisResult:
    """
    Phân tích PE binary.

    Args:
        data: bytes của file PE (.exe/.dll/.msi)

    Returns:
        PeAnalysisResult với đầy đủ thông tin
    """
    try:
        import pefile
    except ImportError:
        logger.error("pefile chưa được cài: pip install pefile")
        return PeAnalysisResult(risk_score_delta=0.0)

    result = PeAnalysisResult()

    try:
        pe = pefile.PE(data=data, fast_load=False)
    except pefile.PEFormatError as e:
        logger.warning(f"[PE] Không phải PE hợp lệ: {e}")
        return result

    # ── DLL flag ───────────────────────────────────────────────
    result.is_dll = bool(pe.FILE_HEADER.Characteristics & 0x2000)

    # ── Compile timestamp ──────────────────────────────────────
    ts = pe.FILE_HEADER.TimeDateStamp
    try:
        dt = datetime.fromtimestamp(ts, tz=timezone.utc)
        result.compile_timestamp = dt.isoformat()
        # Timestamp trong tương lai hoặc trước 2000 = đáng ngờ
        now = datetime.now(tz=timezone.utc)
        if dt > now or dt.year < 2000:
            result.risk_score_delta += 0.10
    except Exception:
        pass

    # ── Sections: entropy ─────────────────────────────────────
    high_entropy = []
    sections: list[PeSection] = []

    for section in pe.sections:
        name = section.Name.rstrip(b"\x00").decode("utf-8", errors="replace")
        raw_data = section.get_data()
        ent = _entropy(raw_data)

        sections.append(PeSection(
            name=name,
            virtual_size=section.Misc_VirtualSize,
            raw_size=section.SizeOfRawData,
            entropy=round(ent, 3),
            characteristics=hex(section.Characteristics),
        ))

        if ent > 7.0:
            high_entropy.append(name)

    result.sections = sections
    result.high_entropy_sections = high_entropy

    if high_entropy:
        # Mỗi section entropy cao += 0.15 (tối đa 0.45)
        result.risk_score_delta += min(len(high_entropy) * 0.15, 0.45)

    # ── Packer detection ─────────────────────────────────────
    section_names = {s.name for s in sections}
    for packer, sigs in PACKER_SIGNATURES.items():
        if any(sig in section_names for sig in sigs):
            result.is_packed = True
            result.packer_name = packer
            result.risk_score_delta += 0.20
            break

    # ── Imports ──────────────────────────────────────────────
    found_suspicious: list[str] = []
    all_imports: dict[str, list[str]] = {}

    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll_name = entry.dll.decode("utf-8", errors="replace")
            funcs = []
            for imp in entry.imports:
                if imp.name:
                    fn_name = imp.name.decode("utf-8", errors="replace")
                    funcs.append(fn_name)
                    if fn_name in FLAT_SUSPICIOUS:
                        found_suspicious.append(fn_name)
            all_imports[dll_name] = funcs

    result.suspicious_imports = list(set(found_suspicious))
    result.all_imports = all_imports

    # Scoring: mỗi nhóm suspicious import phát hiện += 0.15
    groups_hit = set()
    for group, fns in SUSPICIOUS_IMPORTS.items():
        if any(fn in found_suspicious for fn in fns):
            groups_hit.add(group)
    result.risk_score_delta += min(len(groups_hit) * 0.15, 0.45)

    # ── TLS Callbacks (anti-debug) ────────────────────────────
    if hasattr(pe, "DIRECTORY_ENTRY_TLS"):
        result.has_tls_callbacks = True
        result.risk_score_delta += 0.10

    pe.close()

    logger.info(
        f"[PE] packed={result.is_packed}({result.packer_name}) "
        f"suspicious_imports={len(result.suspicious_imports)} "
        f"high_entropy_sections={result.high_entropy_sections} "
        f"delta={result.risk_score_delta:.2f}"
    )

    return result