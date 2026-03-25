"""
models.py — Pydantic schemas dùng chung toàn bộ pipeline
Mỗi stage trả về một typed object → tổng hợp thành AnalysisResult
"""
from __future__ import annotations
from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from enum import Enum
from datetime import datetime


# ─────────────────────────────────────────────
# Enums
# ─────────────────────────────────────────────

class RiskLevel(str, Enum):
    CLEAN    = "clean"
    LOW      = "low"
    MEDIUM   = "medium"
    HIGH     = "high"
    CRITICAL = "critical"


class FileType(str, Enum):
    PE      = "pe"        # .exe .dll .msi
    OFFICE  = "office"    # .doc .docx .docm .xls .xlsm .ppt .pptx
    PDF     = "pdf"
    IMAGE   = "image"     # .png .jpg .jpeg .gif .bmp (regular photos, screenshots, etc.)
    QR_CODE = "qr_code"   # .png .jpg .jpeg (detected as QR code)
    SCRIPT  = "script"    # .js .vbs .ps1 .sh .py .bat
    ARCHIVE = "archive"   # .zip .rar .7z .tar .gz
    UNKNOWN = "unknown"


# ─────────────────────────────────────────────
# Task 2.2 — Hash Triage
# ─────────────────────────────────────────────

class HashTriageResult(BaseModel):
    sha256: str
    md5: str
    sha1: str
    file_size: int
    cache_hit: bool = False

    # Local IOC DB
    ioc_db_hit:    bool           = False
    ioc_db_threat: Optional[str]  = None

    # ClamAV
    clamd_result: Optional[str] = None
    clamd_error:  Optional[str] = None

    risk_score_delta: float = 0.0


# ─────────────────────────────────────────────
# Task 2.3 — Static Analysis
# ─────────────────────────────────────────────

class OleAnalysisResult(BaseModel):
    """oletools — Office macros"""
    has_macros:          bool       = False
    auto_exec_keywords:  List[str]  = []
    suspicious_keywords: List[str]  = []
    extracted_strings:   List[str]  = []
    raw_vba_code:        Optional[str] = None
    risk_score_delta:    float      = 0.0
    
    # Obfuscation detection
    has_doevents:        bool       = False  # DoEvents loop indicates hiding
    has_string_obfuscation: bool    = False  # ChrW/Chr + string concat
    loop_count:          int        = 0      # Number of loops (for/while)
    string_concat_count: int        = 0      # Number of string concatenation ops
    obfuscation_score:   float      = 0.0    # 0-1 obfuscation confidence


class PdfAnalysisResult(BaseModel):
    """pdf-parser — PDF elements"""
    has_javascript:    bool      = False
    has_launch_action: bool      = False
    has_open_action:   bool      = False
    has_embedded_files: bool     = False
    suspicious_elements: List[str] = []
    stream_count:      int       = 0
    risk_score_delta:  float     = 0.0


class PeSection(BaseModel):
    name:            str
    virtual_size:    int
    raw_size:        int
    entropy:         float
    characteristics: str


class PeAnalysisResult(BaseModel):
    """pefile — PE header"""
    is_packed:             bool                  = False
    packer_name:           Optional[str]         = None
    suspicious_imports:    List[str]             = []
    all_imports:           Dict[str, List[str]]  = {}
    sections:              List[PeSection]       = []
    high_entropy_sections: List[str]             = []
    compile_timestamp:     Optional[str]         = None
    is_dll:                bool                  = False
    has_tls_callbacks:     bool                  = False
    risk_score_delta:      float                 = 0.0


class YaraMatch(BaseModel):
    rule_name:       str
    tags:            List[str]      = []
    severity:        str            = "medium"
    description:     Optional[str]  = None
    matched_strings: List[str]      = []


class YaraScanResult(BaseModel):
    matches:            List[YaraMatch] = []
    scanned_size_bytes: int             = 0
    risk_score_delta:   float           = 0.0


class ArchiveAnalysisResult(BaseModel):
    compression_ratio:       float     = 0.0
    depth:                   int       = 0
    is_zip_bomb:             bool      = False
    file_list:               List[str] = []
    nested_suspicious_files: List[str] = []
    risk_score_delta:        float     = 0.0


class StaticAnalysisResult(BaseModel):
    file_type: FileType
    ole:       Optional[OleAnalysisResult]     = None
    pdf:       Optional[PdfAnalysisResult]     = None
    pe:        Optional[PeAnalysisResult]      = None
    yara:      Optional[YaraScanResult]        = None
    archive:   Optional[ArchiveAnalysisResult] = None


# ─────────────────────────────────────────────
# Task 2.4 — Dynamic Sandbox
# ─────────────────────────────────────────────

class SandboxResult(BaseModel):
    executed:          bool                   = False
    sandbox_type:      Optional[str]          = None   # "wine" | "linux"
    registry_changes:  List[str]              = []
    dns_queries:       List[str]              = []
    http_requests:     List[Dict[str, str]]   = []
    syscalls:          List[str]              = []
    dropped_files:     List[str]              = []
    c2_indicators:     List[str]              = []
    error:             Optional[str]          = None
    risk_score_delta:  float                  = 0.0


# ─────────────────────────────────────────────
# Final aggregated result
# ─────────────────────────────────────────────

class XGBoostResult(BaseModel):
    """XGBoost prediction result"""
    available:     bool              = False
    risk_level:    str               = "unknown"
    confidence:    float             = 0.0
    probabilities: dict              = {}
    top_features:  list              = []


class AnalysisResult(BaseModel):
    """Aggregated malware analysis result from all stages"""
    analysis_id: str
    filename:    str
    file_type:   FileType
    timestamp:   datetime = Field(default_factory=datetime.utcnow)

    # Stages
    hash_triage:     HashTriageResult
    static_analysis: StaticAnalysisResult
    sandbox:         Optional[SandboxResult]     = None
    xgboost:         Optional[XGBoostResult]     = None

    # Aggregate
    risk_score:         float     = 0.0
    risk_level:         RiskLevel = RiskLevel.CLEAN
    ioc_matched:        bool      = False
    needs_sandbox:      bool      = False
    recommended_action: str       = "allow"

    def compute_risk(self) -> None:
        """
        Aggregate risk score from:
        - Primary: XGBoost prediction (highest confidence)
        - Secondary: Static analysis (hash triage, PE analysis, Office macros, PDF JS, etc.)
        - Dynamic: Sandbox execution behavior
        
        Override logic: Use static indicators for obvious red flags:
        - PDF with JavaScript + OpenAction → high risk (suspicious JS execution)
        - Office with macros + suspicious keywords → high risk (likely C&C)
        - PE with packed + high entropy → high risk (encoded payload)
        - YARA high/critical match → follow YARA detection
        """
        # ── Phase 0: Check for obvious red flags (override XGBoost) ──────────────────
        sa = self.static_analysis
        
        # PDF: JS + OpenAction = high risk
        pdf_js_open = (sa.pdf and sa.pdf.has_javascript and sa.pdf.has_open_action)
        
        # Office: macros + suspicious keywords
        ole_risky = (sa.ole and sa.ole.has_macros and 
                    len(sa.ole.suspicious_keywords) > 0)
        
        # Office: macros mà VBA code rỗng → có thể obfuscated hoặc embedded differently
        ole_macro_unextractable = (sa.ole and sa.ole.has_macros and 
                                  (not sa.ole.raw_vba_code or len(sa.ole.raw_vba_code.strip()) == 0))
        
        # Office: obfuscation indicators (DoEvents + ChrW + loop = malware)
        ole_obfuscated = (sa.ole and sa.ole.has_doevents and 
                         sa.ole.has_string_obfuscation and 
                         len(sa.ole.suspicious_keywords) > 0)
        
        # PE: packed + suspicious = high risk
        pe_risky = (sa.pe and sa.pe.is_packed and 
                   (len(sa.pe.suspicious_imports) > 0 or 
                    any(e > 0.6 for e in [s.entropy for s in sa.pe.high_entropy_sections] if hasattr(s, 'entropy'))))
        
        # YARA: high/critical matches
        yara_dangerous = (sa.yara and any(m.severity in ("high", "critical") for m in sa.yara.matches))
        
        # Archive: zip bomb
        is_zip_bomb = (sa.archive and sa.archive.is_zip_bomb)
        
        # If obvious malicious indicators → force sandbox and elevated risk
        if pdf_js_open and self.file_type == FileType.PDF:
            # PDF with JS execution = medium+
            self.risk_score = 0.50
            self.risk_level = RiskLevel.MEDIUM
            self.recommended_action = "sandbox_and_review"
            return
        
        if ole_obfuscated and self.file_type == FileType.OFFICE:
            # Office with obfuscation (DoEvents + ChrW + concat) = HIGH risk
            self.risk_score = 0.70
            self.risk_level = RiskLevel.HIGH
            self.recommended_action = "quarantine_and_review"
            return
        
        if ole_macro_unextractable and self.file_type == FileType.OFFICE:
            # Office with unextractable macros = suspicious (obfuscation, encoding)
            self.risk_score = 0.60
            self.risk_level = RiskLevel.HIGH
            self.recommended_action = "quarantine_and_review"
            return
        
        if ole_risky and self.file_type == FileType.OFFICE:
            # Office macro+keywords = medium+
            self.risk_score = 0.55
            self.risk_level = RiskLevel.MEDIUM
            self.recommended_action = "sandbox_and_review"
            return
        
        if pe_risky and self.file_type == FileType.PE:
            # Packed PE with suspicious = high
            self.risk_score = 0.75
            self.risk_level = RiskLevel.HIGH
            self.recommended_action = "quarantine_and_review"
            return
        
        if yara_dangerous:
            # YARA high/critical = override XGBoost
            self.risk_score = 0.72
            self.risk_level = RiskLevel.HIGH
            self.recommended_action = "quarantine_and_review"
            return
        
        if is_zip_bomb:
            # Zip bomb = quarantine
            self.risk_score = 0.88
            self.risk_level = RiskLevel.CRITICAL
            self.recommended_action = "quarantine_immediately"
            return
        
        # ── Phase 1: XGBoost is PRIMARY scorer (nếu không có red flags) ──────────────────
        xgb_result = getattr(self, '_xgboost_result', None)
        if xgb_result and xgb_result.get('available'):
            xgb_risk = xgb_result['risk_level']
            xgb_conf = xgb_result['confidence']
            
            # Map XGBoost risk level → score
            xgb_risk_map = {
                "critical": 0.90,
                "high": 0.75,
                "medium": 0.50,
                "low": 0.25,
                "clean": 0.0
            }
            self.risk_score = xgb_risk_map.get(xgb_risk, 0.0)
            
            # Set risk level dựa trên XGBoost
            if self.risk_score >= 0.85:
                self.risk_level = RiskLevel.CRITICAL
                self.recommended_action = "quarantine_immediately"
            elif self.risk_score >= 0.65:
                self.risk_level = RiskLevel.HIGH
                self.recommended_action = "quarantine_and_review"
            elif self.risk_score >= 0.40:
                self.risk_level = RiskLevel.MEDIUM
                self.recommended_action = "sandbox_and_review"
            elif self.risk_score >= 0.20:
                self.risk_level = RiskLevel.LOW
                self.recommended_action = "flag_for_review"
            else:
                self.risk_level = RiskLevel.CLEAN
                self.recommended_action = "allow"
            
            return  # ✅ Stop here, VT positive overrides everything
        
        # ── Phase 2: Fallback to static analysis (nếu XGBoost không available) ──
        score = self.hash_triage.risk_score_delta

        sa = self.static_analysis
        for part in (sa.ole, sa.pdf, sa.pe, sa.yara, sa.archive):
            if part:
                score += part.risk_score_delta

        if self.sandbox:
            score += self.sandbox.risk_score_delta

        self.risk_score = min(round(score, 3), 1.0)



        # Tính lại risk level từ static score
        score = self.risk_score
        if score >= 0.85:
            self.risk_level         = RiskLevel.CRITICAL
            self.recommended_action = "quarantine_immediately"
        elif score >= 0.65:
            self.risk_level         = RiskLevel.HIGH
            self.recommended_action = "quarantine_and_review"
        elif score >= 0.40:
            self.risk_level         = RiskLevel.MEDIUM
            self.recommended_action = "sandbox_and_review"
        elif score >= 0.20:
            self.risk_level         = RiskLevel.LOW
            self.recommended_action = "flag_for_review"
        else:
            self.risk_level         = RiskLevel.CLEAN
            self.recommended_action = "allow"

        self.ioc_matched = self.hash_triage.ioc_db_hit