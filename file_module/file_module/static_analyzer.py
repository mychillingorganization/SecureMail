"""
static_analyzer.py — Task 2.3
Phân tích tĩnh tổng hợp:
  - Office (.doc/.docx/.docm/.xls/.xlsm/.ppt/.pptx) → oletools
  - PDF → pdf-parser
  - PE (.exe/.dll/.msi) → pe_analyzer
  - Archive (.zip/.rar/.7z/.tar) → zip bomb detection
  - YARA → toàn bộ loại file

Tất cả kết quả được chuẩn hoá thành StaticAnalysisResult (JSON-serializable)
"""
from __future__ import annotations

import io
import logging
import zipfile
from pathlib import Path
from typing import Optional

import magic  # python-magic

from .config import settings
from .models import (
    ArchiveAnalysisResult,
    FileType,
    OleAnalysisResult,
    PdfAnalysisResult,
    StaticAnalysisResult,
)
from .pe_analyzer import analyze_pe
from .yara_scanner import scan_bytes

logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────
# File type detection
# ─────────────────────────────────────────────

OFFICE_EXTENSIONS = {
    ".doc", ".docx", ".docm", ".dot", ".dotm",
    ".xls", ".xlsx", ".xlsm", ".xlsb",
    ".ppt", ".pptx", ".pptm",
    ".rtf",
}
PE_EXTENSIONS = {".exe", ".dll", ".msi", ".scr", ".cpl", ".sys"}
SCRIPT_EXTENSIONS = {".js", ".vbs", ".vbe", ".ps1", ".psm1", ".sh", ".py", ".bat", ".cmd"}
ARCHIVE_EXTENSIONS = {".zip", ".rar", ".7z", ".tar", ".gz", ".bz2", ".xz"}
IMAGE_EXTENSIONS = {".png", ".jpg", ".jpeg", ".gif", ".bmp", ".tiff", ".webp", ".svg"}

PDF_MAGIC    = b"%PDF"
MZ_MAGIC     = b"MZ"
PNG_MAGIC    = b"\x89PNG"
JPEG_MAGIC   = b"\xff\xd8\xff"
GIF_MAGIC    = b"GIF89a"


def _detect_qr_code(data: bytes) -> bool:
    """
    Attempt to detect if image data contains a QR code.
    Uses pyzbar library if available, otherwise returns False.
    """
    try:
        from PIL import Image
        from io import BytesIO
        try:
            from pyzbar import pyzbar
        except ImportError:
            return False
        
        img = Image.open(BytesIO(data))
        img = img.convert("RGB")
        barcodes = pyzbar.decode(img)
        return len(barcodes) > 0
    except Exception:
        return False


def detect_file_type(data: bytes, filename: str) -> FileType:
    """Xác định file type dựa trên magic bytes, extension, và QR detection."""
    ext = Path(filename).suffix.lower()

    # Magic bytes check trước
    if data[:4] == PDF_MAGIC:
        return FileType.PDF
    if data[:2] == MZ_MAGIC:
        return FileType.PE
    
    # Image detection with QR code check
    is_image = False
    if data[:4] == PNG_MAGIC:
        is_image = True
    elif data[:3] == JPEG_MAGIC:
        is_image = True
    elif data[:6] == GIF_MAGIC:
        is_image = True
    elif ext in IMAGE_EXTENSIONS:
        is_image = True
    
    if is_image:
        # Check if image contains QR code
        if _detect_qr_code(data):
            return FileType.QR_CODE
        else:
            return FileType.IMAGE
    
    if ext in OFFICE_EXTENSIONS:
        return FileType.OFFICE
    if ext in PE_EXTENSIONS:
        return FileType.PE
    if ext in SCRIPT_EXTENSIONS:
        return FileType.SCRIPT
    if ext in ARCHIVE_EXTENSIONS:
        return FileType.ARCHIVE

    # Dùng libmagic fallback
    try:
        mime = magic.from_buffer(data[:4096], mime=True)
        if "pdf" in mime:
            return FileType.PDF
        if mime in ("application/x-dosexec", "application/x-msdownload"):
            return FileType.PE
        if mime in ("application/zip", "application/x-rar-compressed",
                    "application/x-7z-compressed"):
            return FileType.ARCHIVE
        if "image" in mime:
            # Check for QR code in detected image
            if _detect_qr_code(data):
                return FileType.QR_CODE
            else:
                return FileType.IMAGE
        if "officedocument" in mime or "msword" in mime or "ms-excel" in mime:
            return FileType.OFFICE
    except Exception:
        pass

    return FileType.UNKNOWN


# ─────────────────────────────────────────────
# Office analysis — oletools
# ─────────────────────────────────────────────

AUTO_EXEC_KEYWORDS = [
    "AutoOpen", "AutoClose", "AutoExec", "AutoNew",
    "Document_Open", "DocumentOpen", "Document_Close",
    "Workbook_Open", "Workbook_Close",
    "App_NewWorkbook", "Sheet_Calculate",
]

SUSPICIOUS_KEYWORDS = [
    "Shell", "CreateObject", "WScript.Shell", "Environ",
    "PowerShell", "cmd.exe", "mshta", "regsvr32",
    "Base64", "Chr(", "Asc(", "StrReverse",
    "DownloadFile", "URLDownloadToFile",
    "CreateProcessA", "OpenProcess",
    "VirtualAlloc", "WriteProcessMemory",
]


def analyze_office(data: bytes) -> OleAnalysisResult:
    """Phân tích file Office tìm VBA macros độc hại."""
    result = OleAnalysisResult()

    try:
        from oletools.olevba import VBA_Parser, TYPE_OLE, TYPE_OpenXML
        import oletools.mraptor as mraptor
    except ImportError:
        logger.error("oletools chưa được cài: pip install oletools")
        return result

    try:
        vba = VBA_Parser("file", data=data)

        # Check for ANY macros (including XL4, Excel 4.0)
        has_macros = vba.detect_vba_macros()
        
        # Additional check for Excel 4.0 macros (XLM) via XL4Macro_Parser
        if not has_macros:
            try:
                from oletools.xl4macro import XL4Macro_Parser
                xl4 = XL4Macro_Parser("file", data=data)
                xl4_result = xl4.analyze()
                if xl4_result and len(xl4_result) > 0:
                    has_macros = True
                    logger.info(f"[OLE] Found XL4 macros: {len(xl4_result)}")
                xl4.close()
            except Exception:
                pass

        # Fallback: Check file structure for macrosheets (Excel 4.0 macros)
        if not has_macros:
            try:
                import zipfile
                import io
                zf = zipfile.ZipFile(io.BytesIO(data))
                names = zf.namelist()
                
                # Check for macrosheet folder
                if any('xl/macrosheets/' in n for n in names):
                    has_macros = True
                    logger.info("[OLE] Found macrosheets folder (Excel 4.0 macros)")
                    
                    # Check for suspicious formulas in macrosheet
                    for name in names:
                        if 'macrosheet' in name and name.endswith('.bin'):
                            macro_data = zf.read(name)
                            # Check for suspicious strings in binary
                            suspicious_patterns = [b'EXEC', b'RUN', b'OPEN', b'CALL', b'http', b'cmd', b'powershell']
                            for pattern in suspicious_patterns:
                                if pattern in macro_data or pattern.lower() in macro_data:
                                    result.extracted_strings.append(f"suspicious_macro_pattern:{pattern.decode()}")
                                    result.risk_score_delta = 0.50
                                    logger.info(f"[OLE] Found suspicious pattern in macrosheet: {pattern}")
                                    break
                zf.close()
            except Exception as e:
                logger.debug(f"[OLE] Structure check error: {e}")

        if not has_macros:
            # Check for external connections, embedded objects
            text = data.decode('latin-1', errors='replace')
            if any(x in text.lower() for x in ['http://', 'https://', 'cmd', 'powershell', 'wscript']):
                result.extracted_strings = ['suspicious_external_refs']
                result.risk_score_delta = 0.20
                logger.info("[OLE] Found suspicious external references")
            return result

        result.has_macros = True
        risk_delta = 0.30  # Có macro = cơ bản đã đáng ngờ

        # Extract VBA code
        vba_code_parts = []
        for (filename, stream_path, vba_filename, vba_code) in vba.extract_macros():
            if vba_code:
                vba_code_parts.append(vba_code)

        full_code = "\n".join(vba_code_parts)
        result.raw_vba_code = full_code[:10000]  # limit to 10KB

        # Keyword detection
        code_upper = full_code.upper()
        found_auto = [kw for kw in AUTO_EXEC_KEYWORDS if kw.upper() in code_upper]
        found_susp = [kw for kw in SUSPICIOUS_KEYWORDS if kw.upper() in code_upper]

        result.auto_exec_keywords = found_auto
        result.suspicious_keywords = found_susp

        # Strings đáng ngờ (URLs, registry paths, encoded strings)
        import re
        urls = re.findall(r'https?://[^\s"\'<>]+', full_code, re.IGNORECASE)
        result.extracted_strings = list(set(urls))[:20]

        # ── OBFUSCATION DETECTION ──
        code_lower = full_code.lower()
        
        # Check for DoEvents (hiding loop)
        result.has_doevents = 'doevents' in code_lower
        
        # Check for string obfuscation (ChrW/Chr used for character encoding)
        has_chrw = 'chrw(' in code_lower
        has_chr = 'chr(' in code_lower
        result.has_string_obfuscation = has_chrw or has_chr
        
        # Count loops (For/While statements)
        import re as regex
        loop_matches = regex.findall(r'\b(for|while)\s+', code_lower, regex.IGNORECASE)
        result.loop_count = len(loop_matches)
        
        # Count string concatenation ops (&)
        concat_matches = regex.findall(r'\s&\s', full_code)
        result.string_concat_count = len(concat_matches)
        
        # Obfuscation score: higher = more obfuscated
        obf_score = 0.0
        if result.has_doevents:
            obf_score += 0.30
        if result.has_string_obfuscation:
            obf_score += 0.25
        if result.loop_count > 3:
            obf_score += 0.20  # Many loops = suspicious
        if result.string_concat_count > 10:
            obf_score += 0.25  # Heavy string ops = hiding
        result.obfuscation_score = min(obf_score, 1.0)
        
        logger.debug(
            f"[OLE] Obfuscation: doevents={result.has_doevents} "
            f"stringobf={result.has_string_obfuscation} loops={result.loop_count} "
            f"concat={result.string_concat_count} score={result.obfuscation_score:.2f}"
        )

        # Risk scoring
        if found_auto:
            risk_delta += 0.25   # Auto-exec = mức độ cao hơn
        if found_susp:
            risk_delta += min(len(found_susp) * 0.05, 0.25)
        
        # Obfuscation adds extra risk
        if result.obfuscation_score > 0.5:
            risk_delta += 0.20  # Moderate obfuscation
        if result.obfuscation_score > 0.75:
            risk_delta += 0.15  # Heavy obfuscation (additional)

        result.risk_score_delta = min(risk_delta, 0.80)

        logger.info(
            f"[OLE] macros=True auto_exec={found_auto} "
            f"suspicious={len(found_susp)} delta={result.risk_score_delta:.2f}"
        )

    except Exception as e:
        logger.warning(f"[OLE] Lỗi phân tích: {e}")

    return result


# ─────────────────────────────────────────────
# PDF analysis — pdf-parser
# ─────────────────────────────────────────────

PDF_SUSPICIOUS_ELEMENTS = [
    "/JS", "/JavaScript",
    "/Launch",
    "/OpenAction", "/AA",
    "/EmbeddedFile",
    "/RichMedia",
    "/XFA",
    "/AcroForm",
    "/URI",
]


def analyze_pdf(data: bytes) -> PdfAnalysisResult:
    """Phân tích PDF tìm JavaScript, Launch actions, embedded files."""
    result = PdfAnalysisResult()

    try:
        # Dùng pdfid để quick scan (thay vì pdf-parser phức tạp hơn)
        from oletools import pdfid
        data_str = data.decode("latin-1", errors="replace")
    except Exception:
        pass

    # Fallback: manual keyword scan trên raw bytes
    try:
        text = data.decode("latin-1", errors="replace")
        found_elements = []

        for element in PDF_SUSPICIOUS_ELEMENTS:
            if element in text:
                found_elements.append(element)

        result.suspicious_elements = found_elements

        if "/JS" in found_elements or "/JavaScript" in found_elements:
            result.has_javascript = True
            result.risk_score_delta += 0.40

        if "/Launch" in found_elements:
            result.has_launch_action = True
            result.risk_score_delta += 0.50

        if "/OpenAction" in found_elements or "/AA" in found_elements:
            result.has_open_action = True
            result.risk_score_delta += 0.25

        if "/EmbeddedFile" in found_elements:
            result.has_embedded_files = True
            result.risk_score_delta += 0.20

        # Count streams
        import re
        result.stream_count = len(re.findall(r"\bstream\b", text))

        result.risk_score_delta = min(result.risk_score_delta, 0.80)

        logger.info(
            f"[PDF] js={result.has_javascript} launch={result.has_launch_action} "
            f"elements={found_elements} delta={result.risk_score_delta:.2f}"
        )

    except Exception as e:
        logger.warning(f"[PDF] Lỗi phân tích: {e}")

    return result


# ─────────────────────────────────────────────
# Archive analysis — zip bomb detection
# ─────────────────────────────────────────────

def analyze_archive(data: bytes, filename: str) -> ArchiveAnalysisResult:
    """
    Phát hiện zip bomb và file độc hại trong archive.
    Tiêu chí zip bomb: tỷ lệ nén > 100:1 HOẶC độ sâu lồng nhau > 3
    """
    result = ArchiveAnalysisResult()
    ext = Path(filename).suffix.lower()

    try:
        if ext == ".zip" or data[:2] == b"PK":
            _analyze_zip(data, result, depth=0, max_depth=5)
        elif ext == ".7z":
            _analyze_7z(data, result)
        elif ext in (".rar",):
            _analyze_rar(data, result)
    except Exception as e:
        logger.warning(f"[Archive] Lỗi phân tích: {e}")

    return result


def _analyze_zip(data: bytes, result: ArchiveAnalysisResult,
                 depth: int, max_depth: int) -> int:
    """Đệ quy phân tích ZIP. Returns tổng uncompressed size."""
    if depth > max_depth:
        return 0

    result.depth = max(result.depth, depth)

    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile:
        return 0

    total_compressed   = len(data)
    total_uncompressed = 0

    for info in zf.infolist():
        name = info.filename
        result.file_list.append(f"[depth={depth}] {name}")
        total_uncompressed += info.file_size

        ext = Path(name).suffix.lower()

        # Check for nested archive by extension OR magic bytes (detect renamed ZIPs)
        if depth < max_depth:
            try:
                nested_data = zf.read(name)
                if nested_data[:2] == b"PK":   # ZIP magic — recurse regardless of extension
                    nested_size = _analyze_zip(nested_data, result, depth + 1, max_depth)
                    total_uncompressed += nested_size
            except Exception:
                pass

        # Flag suspicious nested files
        if ext in PE_EXTENSIONS | SCRIPT_EXTENSIONS | OFFICE_EXTENSIONS:
            result.nested_suspicious_files.append(name)

    zf.close()

    # Tính compression ratio ở level này
    if total_compressed > 0:
        ratio = total_uncompressed / total_compressed
        result.compression_ratio = max(result.compression_ratio, ratio)

    # Zip bomb criteria
    if result.compression_ratio > 100 or result.depth > 3:
        result.is_zip_bomb = True
        result.risk_score_delta = 0.90

        logger.warning(
            f"[Archive] ZIP BOMB detected! "
            f"ratio={result.compression_ratio:.1f}x depth={result.depth}"
        )
    elif result.nested_suspicious_files:
        result.risk_score_delta = 0.30
        logger.info(f"[Archive] Suspicious nested files: {result.nested_suspicious_files[:5]}")

    return total_uncompressed


def _analyze_7z(data: bytes, result: ArchiveAnalysisResult) -> None:
    try:
        import py7zr
        with py7zr.SevenZipFile(io.BytesIO(data)) as archive:
            entries = archive.list()
            for entry in entries:
                result.file_list.append(entry.filename)
                if Path(entry.filename).suffix.lower() in PE_EXTENSIONS | SCRIPT_EXTENSIONS:
                    result.nested_suspicious_files.append(entry.filename)
    except ImportError:
        logger.debug("py7zr chưa được cài")
    except Exception as e:
        logger.warning(f"[7z] Lỗi: {e}")


def _analyze_rar(data: bytes, result: ArchiveAnalysisResult) -> None:
    try:
        import rarfile
        with rarfile.RarFile(io.BytesIO(data)) as rf:
            for info in rf.infolist():
                result.file_list.append(info.filename)
                if Path(info.filename).suffix.lower() in PE_EXTENSIONS | SCRIPT_EXTENSIONS:
                    result.nested_suspicious_files.append(info.filename)
    except ImportError:
        logger.debug("rarfile chưa được cài")
    except Exception as e:
        logger.warning(f"[RAR] Lỗi: {e}")


# ─────────────────────────────────────────────
# Main entry point
# ─────────────────────────────────────────────

def run_static_analysis(data: bytes, filename: str) -> StaticAnalysisResult:
    """
    Chạy toàn bộ static analysis pipeline.
    Luôn chạy YARA sau khi phân tích loại file.

    Args:
        data:     bytes của file
        filename: tên file gốc (để xác định extension)

    Returns:
        StaticAnalysisResult — JSON-serializable analysis results
    """
    file_type = detect_file_type(data, filename)
    logger.info(f"[Static] {filename} → type={file_type.value} size={len(data)}")

    result = StaticAnalysisResult(file_type=file_type)

    # ── File-type specific analysis ───────────────────────────
    if file_type == FileType.OFFICE:
        result.ole = analyze_office(data)

    elif file_type == FileType.PDF:
        result.pdf = analyze_pdf(data)

    elif file_type == FileType.PE:
        result.pe = analyze_pe(data)

    elif file_type == FileType.ARCHIVE:
        result.archive = analyze_archive(data, filename)

    # ── YARA (tất cả loại file) ───────────────────────────────
    yara_rules_dir = settings.yara_rules_dir
    if yara_rules_dir.exists():
        result.yara = scan_bytes(data, yara_rules_dir)
    else:
        logger.warning(f"[YARA] Thư mục rules không tồn tại: {yara_rules_dir}")

    return result