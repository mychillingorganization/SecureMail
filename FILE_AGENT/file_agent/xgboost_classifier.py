"""
file_agent/xgboost_classifier.py
Inference module — trích xuất features từ AnalysisResult và dự đoán risk level.

Sử dụng:
    from xgboost_classifier import predict_risk
    result_dict = predict_risk(analysis_result)
"""
from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Optional

import numpy as np

from models import AnalysisResult, FileType

logger = logging.getLogger(__name__)

# Label mapping (phải trùng với dataset/train_xgboost.py)
LABEL_NAMES = ["clean", "low", "medium", "high", "critical"]

FILE_TYPE_MAP = {
    FileType.PE:       1,
    FileType.OFFICE:   2,
    FileType.PDF:      3,
    FileType.SCRIPT:   4,
    FileType.ARCHIVE:  5,
    FileType.QR_CODE:  5,
    FileType.IMAGE:    7,
    FileType.UNKNOWN:  0,
}


# ─────────────────────────────────────────────
# Model loading (cached per file type)
# ─────────────────────────────────────────────

_model_cache: dict[str, Optional[object]] = {}


def _get_model_path_for_filetype(file_type: FileType, filename: Optional[str] = None) -> Path:
    """Return the best available model path for a specific file type."""
    configured_dir = os.getenv("FILE_AGENT_MODEL_DIR")
    if configured_dir:
        model_root = Path(configured_dir).resolve()
    else:
        # New default: keep inference artifacts inside FILE_AGENT/file_agent/models.
        model_root = Path(__file__).parent / "models"
        # Backward compatibility for older layouts.
        if not model_root.exists():
            model_root = Path(__file__).parent.parent / "dataset"

    # Candidate order per file type.
    # We avoid hard-failing on model.pkl because many deployments only ship per-type models.
    office_is_excel = False
    if filename:
        ext = Path(filename).suffix.lower()
        office_is_excel = ext in {".xls", ".xlsx", ".xlsm", ".xlsb", ".csv"}

    if file_type == FileType.PDF:
        candidates = ["model_pdf.pkl", "model_word.pkl", "model_excel.pkl"]
    elif file_type == FileType.OFFICE:
        if office_is_excel:
            candidates = ["model_excel.pkl", "model_word.pkl"]
        else:
            candidates = ["model_word.pkl", "model_excel.pkl"]
    elif file_type == FileType.QR_CODE:
        candidates = ["model_qr.pkl", "model_image.pkl"]
    elif file_type == FileType.IMAGE:
        candidates = ["model_image.pkl", "model_qr.pkl"]
    else:
        # PE/SCRIPT/ARCHIVE/UNKNOWN fallback order uses available trained models first.
        candidates = [
            "model_word.pkl",
            "model_excel.pkl",
            "model_pdf.pkl",
            "model_image.pkl",
            "model_qr.pkl",
            "model.pkl",
        ]

    for name in candidates:
        path = model_root / name
        if path.exists():
            return path

    # Keep deterministic behavior if no model exists at all.
    return model_root / candidates[-1]


def _load_model(model_path: Path) -> object:
    """Load XGBoost model from pickle file (cached)"""
    model_str = str(model_path)
    
    if model_str in _model_cache:
        return _model_cache[model_str]

    if not model_path.exists():
        logger.warning(f"[XGB] Model chưa được train: {model_path}")
        return None

    try:
        import joblib
        model = joblib.load(model_path)
        _model_cache[model_str] = model
        logger.info(f"[XGB] Model đã tải: {model_path}")
        return model
    except Exception as e:
        logger.error(f"[XGB] Không tải được model: {e}")
        return None


# ─────────────────────────────────────────────
# Feature extraction
# ─────────────────────────────────────────────

def extract_features(result: AnalysisResult) -> np.ndarray:
    """
    Trích 25 features từ AnalysisResult, trả về numpy array shape (1, 25).
    Thứ tự PHẢI khớp với FEATURE_COLS trong dataset/train_xgboost.py.
    """
    ht = result.hash_triage
    sa = result.static_analysis

    # Hash Triage
    clamd_detected    = 0 if (not ht.clamd_result or ht.clamd_result == "OK") else 1
    ioc_db_hit        = int(ht.ioc_db_hit)

    # PE Analysis
    pe = sa.pe
    pe_suspicious_imports = len(pe.suspicious_imports) if pe else 0
    pe_high_entropy       = len(pe.high_entropy_sections) if pe else 0
    pe_is_packed          = int(pe.is_packed) if pe else 0
    pe_has_tls            = int(pe.has_tls_callbacks) if pe else 0

    # Office / OLE
    ole = sa.ole
    has_macros         = int(ole.has_macros) if ole else 0
    auto_exec_count    = len(ole.auto_exec_keywords) if ole else 0
    suspicious_kw_count = len(ole.suspicious_keywords) if ole else 0
    # Obfuscation features
    has_doevents       = int(ole.has_doevents) if ole else 0
    has_string_obfuscation = int(ole.has_string_obfuscation) if ole else 0
    loop_count         = int(ole.loop_count) if ole else 0
    string_concat_count = int(ole.string_concat_count) if ole else 0
    obfuscation_score  = float(ole.obfuscation_score) if ole else 0.0

    # PDF
    pdf = sa.pdf
    has_js_pdf        = int(pdf.has_javascript) if pdf else 0
    has_launch_action = int(pdf.has_launch_action) if pdf else 0
    has_open_action   = int(pdf.has_open_action) if pdf else 0

    # YARA
    yara = sa.yara
    yara_total    = len(yara.matches) if yara else 0
    yara_critical = sum(1 for m in yara.matches if m.severity == "critical") if yara else 0
    yara_high     = sum(1 for m in yara.matches if m.severity == "high") if yara else 0
    yara_medium   = sum(1 for m in yara.matches if m.severity == "medium") if yara else 0

    # Archive
    archive = sa.archive
    is_zip_bomb      = int(archive.is_zip_bomb) if archive else 0
    compression_ratio = float(archive.compression_ratio) if archive else 0.0

    # Meta
    file_size_kb = round(ht.file_size / 1024, 2)
    file_type    = FILE_TYPE_MAP.get(result.file_type, 0)

    features = [
        clamd_detected, ioc_db_hit,
        pe_suspicious_imports, pe_high_entropy, pe_is_packed, pe_has_tls,
        has_macros, auto_exec_count, suspicious_kw_count,
        has_doevents, has_string_obfuscation, loop_count, string_concat_count, obfuscation_score,
        has_js_pdf, has_launch_action, has_open_action,
        yara_total, yara_critical, yara_high, yara_medium,
        is_zip_bomb, compression_ratio,
        file_size_kb, file_type,
        0, 0,  # ← placeholder for removed VT features (vt_positives, vt_detection_ratio)
    ]
    return np.array(features, dtype=np.float32).reshape(1, -1)


# ─────────────────────────────────────────────
# Prediction
# ─────────────────────────────────────────────

def predict_risk(result: AnalysisResult, model_path: Optional[Path] = None) -> dict:
    """
    Dự đoán risk level bằng XGBoost (file-type specific models).

    Returns dict:
      {
        "available":        bool,      # False nếu model chưa train
        "risk_level":       str,       # "clean"|"low"|"medium"|"high"|"critical"
        "confidence":       float,     # xác suất class dự đoán
        "probabilities":    dict,      # xác suất từng class
        "top_features":     list[str], # top 5 features đóng góp nhiều nhất
      }
    """
    # Nếu không chỉ định model_path, tự động chọn model theo file_type
    if model_path is None:
        model_path = _get_model_path_for_filetype(result.file_type, result.filename)
        logger.info(f"[XGB] Auto-selected model for {result.file_type.value}: {model_path.name}")

    model = _load_model(model_path)
    if model is None:
        logger.warning(f"[XGB] Model not available, returning empty result")
        return {
            "available":     False,
            "risk_level":    result.risk_level.value,
            "confidence":    0.0,
            "probabilities": {},
            "top_features":  [],
        }

    X = extract_features(result)

    try:
        label_idx   = int(model.predict(X)[0])
        proba       = model.predict_proba(X)[0]
        confidence  = float(proba[label_idx])
        risk_level  = LABEL_NAMES[label_idx] if label_idx < len(LABEL_NAMES) else "unknown"

        # ⚠️ Obfuscation detection: reduce confidence if malicious indicators present
        # This prevents 99.99% confidence on clear malware with obfuscation
        ole = result.static_analysis.ole if result.static_analysis else None
        if ole and ole.has_macros:
            # If obfuscation detected + suspicious keywords → model likely unreliable
            is_obfuscated = ole.has_doevents and ole.has_string_obfuscation
            has_dangerous_keywords = any(kw in ole.suspicious_keywords for kw in 
                                        ['CreateObject', 'Shell', 'WScript', 'Win32', 'WMI'])
            
            if is_obfuscated and has_dangerous_keywords:
                # Heavy obfuscation + code execution indicators = unreliable prediction
                # Cap confidence at 0.75 to prevent false negatives
                confidence = min(confidence, 0.75)
                logger.info(f"[XGB] Obfuscation detected (DoEvents+ChrW+{len(ole.suspicious_keywords)} kw) "
                           f"→ capping confidence to {confidence:.2f}")
                
                # If model is very confident on "low/clean" despite obfuscation → flag as suspicious
                if risk_level in ("clean", "low") and confidence > 0.5:
                    confidence = 0.5  # Force neutral prediction
                    logger.warning(f"[XGB] Obfuscated code detected but model predicts '{risk_level}' "
                                 f"→ reducing confidence to 0.50 (unreliable)")

        # Top-5 features by importance
        top_features: list[str] = []
        try:
            importances = model.feature_importances_
            # Simple feature names if not stored in model
            feature_cols = [
                "clamd_detected", "ioc_db_hit",
                "pe_suspicious_imports", "pe_high_entropy", "pe_is_packed", "pe_has_tls",
                "has_macros", "auto_exec_count", "suspicious_kw_count",
                "has_doevents", "has_string_obfuscation", "loop_count", "string_concat_count", "obfuscation_score",
                "has_js_pdf", "has_launch_action", "has_open_action",
                "yara_total", "yara_critical", "yara_high", "yara_medium",
                "is_zip_bomb", "compression_ratio", "file_size_kb", "file_type",
            ]
            ranked = sorted(
                zip(feature_cols, importances),
                key=lambda x: x[1],
                reverse=True,
            )
            top_features = [name for name, _ in ranked[:5]]
        except Exception as e:
            logger.debug(f"[XGB] Could not extract feature importances: {e}")

        return {
            "available":     True,
            "risk_level":    risk_level,
            "confidence":    round(confidence, 4),
            "probabilities": {
                LABEL_NAMES[i]: round(float(p), 4) for i, p in enumerate(proba)
            },
            "top_features":  top_features,
        }

    except Exception as e:
        logger.error(f"[XGB] Lỗi dự đoán: {e}")
        return {
            "available":     False,
            "risk_level":    result.risk_level.value,
            "confidence":    0.0,
            "probabilities": {},
            "top_features":  [],
        }
