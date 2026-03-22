"""Train XGBoost models from extracted CSV data"""
import pandas as pd
import numpy as np
import joblib
import logging
import warnings
from pathlib import Path
from xgboost import XGBClassifier
from sklearn.model_selection import cross_val_score
from sklearn.metrics import accuracy_score, f1_score, confusion_matrix, precision_recall_fscore_support

warnings.filterwarnings("ignore")
logging.basicConfig(level=logging.INFO, format='%(message)s')
logger = logging.getLogger("TRAIN")

DATASET_ROOT = Path(__file__).parent / "Dataset"

UNIFIED_COLS = [
    "clamd_detected", "ioc_db_hit",
    "pe_suspicious_imports", "pe_high_entropy", "pe_is_packed", "pe_has_tls",
    "has_macros", "auto_exec_count", "suspicious_kw_count",
    "has_doevents", "has_string_obfuscation", "loop_count", "string_concat_count", "obfuscation_score",
    "has_js_pdf", "has_launch_action", "has_open_action",
    "yara_total", "yara_critical", "yara_high", "yara_medium",
    "is_zip_bomb", "compression_ratio",
    "file_size_kb", "file_type",
    "label"
]

def load_and_map_pdf():
    csv_path = DATASET_ROOT / "PDF" / "PDF_Extract.csv"
    if not csv_path.exists():
        return pd.DataFrame()
    
    df = pd.read_csv(csv_path)
    out = pd.DataFrame(0, index=df.index, columns=UNIFIED_COLS)
    
    if "file_size" in df.columns:
        out["file_size_kb"] = pd.to_numeric(df["file_size"], errors='coerce').fillna(0) / 1024
    if "javascript_count" in df.columns:
        out["has_js_pdf"] = (pd.to_numeric(df["javascript_count"], errors='coerce').fillna(0) > 0).astype(int)
    if "openaction_count" in df.columns:
        out["has_open_action"] = (pd.to_numeric(df["openaction_count"], errors='coerce').fillna(0) > 0).astype(int)
    if "launch_count" in df.columns:
        out["has_launch_action"] = (pd.to_numeric(df["launch_count"], errors='coerce').fillna(0) > 0).astype(int)
    if "label" in df.columns:
        out["label"] = pd.to_numeric(df["label"], errors='coerce').fillna(0).astype(int)
    
    out["file_type"] = 3
    for col in out.columns:
        if col != "label":
            out[col] = pd.to_numeric(out[col], errors='coerce').fillna(0)
    
    logger.info(f"Loaded {len(out)} PDF samples")
    return out

def load_and_map_word():
    csv_path = DATASET_ROOT / "Word Document" / "WORD_Extract.csv"
    if not csv_path.exists():
        return pd.DataFrame()
    
    df = pd.read_csv(csv_path)
    out = pd.DataFrame(0, index=df.index, columns=UNIFIED_COLS)
    
    if "file_size" in df.columns:
        out["file_size_kb"] = pd.to_numeric(df["file_size"], errors='coerce').fillna(0) / 1024
    if "macro_present" in df.columns:
        out["has_macros"] = pd.to_numeric(df["macro_present"], errors='coerce').fillna(0).astype(int)
    if "vba_keywords_count" in df.columns:
        out["suspicious_kw_count"] = pd.to_numeric(df["vba_keywords_count"], errors='coerce').fillna(0)
    if "has_doevents" in df.columns:
        out["has_doevents"] = pd.to_numeric(df["has_doevents"], errors='coerce').fillna(0).astype(int)
    if "has_string_obfuscation" in df.columns:
        out["has_string_obfuscation"] = pd.to_numeric(df["has_string_obfuscation"], errors='coerce').fillna(0).astype(int)
    if "loop_count" in df.columns:
        out["loop_count"] = pd.to_numeric(df["loop_count"], errors='coerce').fillna(0)
    if "string_concat_count" in df.columns:
        out["string_concat_count"] = pd.to_numeric(df["string_concat_count"], errors='coerce').fillna(0)
    if "obfuscation_score" in df.columns:
        out["obfuscation_score"] = pd.to_numeric(df["obfuscation_score"], errors='coerce').fillna(0)
    if "label" in df.columns:
        out["label"] = pd.to_numeric(df["label"], errors='coerce').fillna(0).astype(int)
    
    out["file_type"] = 2
    for col in out.columns:
        if col != "label":
            out[col] = pd.to_numeric(out[col], errors='coerce').fillna(0)
    
    logger.info(f"Loaded {len(out)} Word samples")
    return out

def load_and_map_excel():
    csv_path = DATASET_ROOT / "Excel" / "EXCEL_Extract.csv"
    if not csv_path.exists():
        return pd.DataFrame()
    
    df = pd.read_csv(csv_path, low_memory=False)
    out = pd.DataFrame(0, index=df.index, columns=UNIFIED_COLS)
    
    if "file_size" in df.columns:
        out["file_size_kb"] = pd.to_numeric(df["file_size"], errors='coerce').fillna(0) / 1024
    if "has_macro" in df.columns:
        out["has_macros"] = pd.to_numeric(df["has_macro"], errors='coerce').fillna(0)
    
    susp_cols = ["uses_file_api", "uses_network_api", "uses_process_api"]
    for col in susp_cols:
        if col in df.columns:
            out["suspicious_kw_count"] += pd.to_numeric(df[col], errors='coerce').fillna(0)
    
    if "label" in df.columns:
        out["label"] = pd.to_numeric(df["label"], errors='coerce').fillna(0).astype(int)
    
    out["file_type"] = 2
    for col in out.columns:
        if col != "label":
            out[col] = pd.to_numeric(out[col], errors='coerce').fillna(0)
    
    logger.info(f"Loaded {len(out)} Excel samples")
    return out

def load_and_map_qr():
    """Load and map QR code features (comprehensive URL+QR analysis)"""
    csv_path = DATASET_ROOT / "QR Codes" / "QR_Extract.csv"
    if not csv_path.exists():
        return pd.DataFrame()
    
    df = pd.read_csv(csv_path)
    out = pd.DataFrame(0, index=df.index, columns=UNIFIED_COLS)
    
    # File & image size
    if "file_size" in df.columns:
        out["file_size_kb"] = pd.to_numeric(df["file_size"], errors='coerce').fillna(0) / 1024
    
    # URL presence (phishing indicator)
    if "url_present" in df.columns:
        out["has_macros"] = pd.to_numeric(df["url_present"], errors='coerce').fillna(0)
    
    # C2/suspicious port usage
    if "uses_nonstandard_port" in df.columns:
        out["auto_exec_count"] = pd.to_numeric(df["uses_nonstandard_port"], errors='coerce').fillna(0)
    
    # URL obfuscation indicators (special chars, hyphens, etc.)
    special_chars = pd.to_numeric(df.get("special_char_count", 0), errors='coerce').fillna(0)
    hyphens = pd.to_numeric(df.get("hyphen_count", 0), errors='coerce').fillna(0)
    at_symbols = pd.to_numeric(df.get("at_symbol_present", 0), errors='coerce').fillna(0)
    out["suspicious_kw_count"] = (special_chars + hyphens + at_symbols).clip(0, 10)
    
    # Domain risk (subdomains, IP addresses)
    subdomains = pd.to_numeric(df.get("subdomain_count", 0), errors='coerce').fillna(0)
    uses_ip = pd.to_numeric(df.get("uses_ip_address", 0), errors='coerce').fillna(0)
    out["has_doevents"] = ((subdomains > 2) | (uses_ip == 1)).astype(int)
    
    # URL entropy (malformed URL detection)
    if "url_entropy" in df.columns:
        out["has_string_obfuscation"] = (pd.to_numeric(df["url_entropy"], errors='coerce').fillna(0) > 4.0).astype(int)
    
    # Path depth (redirect/multi-level exploit)
    if "path_depth" in df.columns:
        out["loop_count"] = pd.to_numeric(df["path_depth"], errors='coerce').fillna(0)
    
    # Query parameters (form submission/data exfiltration)
    if "query_param_count" in df.columns:
        out["string_concat_count"] = pd.to_numeric(df["query_param_count"], errors='coerce').fillna(0)
    
    # QR metrics
    if "qr_count" in df.columns:
        out["pe_suspicious_imports"] = (pd.to_numeric(df["qr_count"], errors='coerce').fillna(0) > 1).astype(int)
    
    # Protocol indicators (HTTP vs HTTPS mismatch)
    has_http = pd.to_numeric(df.get("has_http", 0), errors='coerce').fillna(0)
    has_https = pd.to_numeric(df.get("has_https", 0), errors='coerce').fillna(0)
    out["has_launch_action"] = ((has_http == 1) & (has_https == 0)).astype(int)
    
    # Fragment/obfuscation in URL
    if "has_fragment" in df.columns:
        out["has_open_action"] = pd.to_numeric(df["has_fragment"], errors='coerce').fillna(0).astype(int)
    
    # Decoded text characteristics
    if "decoded_text_entropy" in df.columns:
        out["obfuscation_score"] = (pd.to_numeric(df["decoded_text_entropy"], errors='coerce').fillna(0) / 8.0).clip(0, 1)
    
    # Text length (unusually long = command injection)
    if "decoded_text_length" in df.columns:
        out["yara_critical"] = (pd.to_numeric(df["decoded_text_length"], errors='coerce').fillna(0) > 500).astype(int)
    
    # URL length metric
    if "url_length" in df.columns:
        out["yara_medium"] = (pd.to_numeric(df["url_length"], errors='coerce').fillna(0) > 100).astype(int)
    
    # Digit ratio (encoded payload)
    if "digit_ratio" in df.columns:
        out["pe_high_entropy"] = (pd.to_numeric(df["digit_ratio"], errors='coerce').fillna(0) > 0.3).astype(int)
    
    if "label" in df.columns:
        out["label"] = pd.to_numeric(df["label"], errors='coerce').fillna(0).astype(int)
    
    out["file_type"] = 5
    for col in out.columns:
        if col != "label":
            out[col] = pd.to_numeric(out[col], errors='coerce').fillna(0)
    
    logger.info(f"Loaded {len(out)} QR Code")
    return out

def load_and_map_image():
    """Load and map regular image features"""
    csv_path = DATASET_ROOT / "Images" / "IMAGE_Extract.csv"
    if not csv_path.exists():
        logger.warning(f" Image dataset not found")
        return pd.DataFrame()
    
    df = pd.read_csv(csv_path)
    out = pd.DataFrame(0, index=df.index, columns=UNIFIED_COLS)
    
    if "file_size" in df.columns:
        out["file_size_kb"] = pd.to_numeric(df["file_size"], errors='coerce').fillna(0) / 1024
    if "image_entropy" in df.columns:
        out["obfuscation_score"] = pd.to_numeric(df["image_entropy"], errors='coerce').fillna(0) / 8.0
    if "brightness_mean" in df.columns:
        out["suspicious_kw_count"] = pd.to_numeric(df["brightness_mean"], errors='coerce').fillna(0) / 255.0
    if "contrast_std" in df.columns:
        out["auto_exec_count"] = pd.to_numeric(df["contrast_std"], errors='coerce').fillna(0) / 255.0
    if "image_width" in df.columns:
        out["pe_high_entropy"] = (pd.to_numeric(df["image_width"], errors='coerce').fillna(0) > 10000).astype(int)
    if "image_height" in df.columns:
        out["pe_is_packed"] = (pd.to_numeric(df["image_height"], errors='coerce').fillna(0) > 10000).astype(int)
    if "image_mode_id" in df.columns:
        out["pe_suspicious_imports"] = pd.to_numeric(df["image_mode_id"], errors='coerce').fillna(0)
    if "aspect_ratio" in df.columns:
        out["has_macros"] = (pd.to_numeric(df["aspect_ratio"], errors='coerce').fillna(0) > 5.0).astype(int)
    if "label" in df.columns:
        out["label"] = pd.to_numeric(df["label"], errors='coerce').fillna(0).astype(int)
    
    out["file_type"] = 7
    for col in out.columns:
        if col != "label":
            out[col] = pd.to_numeric(out[col], errors='coerce').fillna(0)
    
    logger.info(f"Loaded {len(out)} Image samples")
    return out

def train_model(name, df, model_file):
    if len(df) == 0:
        logger.warning(f"{name}: No data")
        return
    
    X = df.drop(columns=["label"])
    y = df["label"]
    
    sample_weights = None
    if name == "Word" and len(y) > 0:
        sample_weights = np.array([5.0 if label == 1 else 1.0 for label in y])
        logger.info(f"   Applying 5x weight to malicious Word samples")
    
    model = XGBClassifier(n_estimators=100, max_depth=6, learning_rate=0.1, 
                         use_label_encoder=False, eval_metric="logloss", random_state=42)
    model.fit(X, y, sample_weight=sample_weights)
    
    cv_scores = cross_val_score(model, X, y, cv=10, scoring='f1_weighted')
    train_pred = model.predict(X)
    acc = accuracy_score(y, train_pred)
    train_f1 = f1_score(y, train_pred, average='weighted', zero_division=0)
    cv_f1 = cv_scores.mean()
    
    # Confusion Matrix
    cm = confusion_matrix(y, train_pred)
    tn, fp, fn, tp = cm.ravel() if cm.size == 4 else (0, 0, 0, 0)
    
    # Precision & Recall
    precision, recall, f1_macro, _ = precision_recall_fscore_support(
        y, train_pred, average='weighted', zero_division=0
    )
    
    importance = model.feature_importances_
    top_idx = np.argsort(importance)[-3:][::-1]
    top_feat = ", ".join([f"{X.columns[i]}={importance[i]:.2f}" for i in top_idx])
    
    logger.info(f" {name:8}  TP={tp:>6d} | FP={fp:>6d}")
    logger.info(f"           FN={fn:>6d} | TN={tn:>6d}")
    
    joblib.dump(model, DATASET_ROOT.parent / model_file)

def main():
    logger.info("XGBOOST TRAINING")
    
    df_pdf = load_and_map_pdf()
    df_word = load_and_map_word()
    df_excel = load_and_map_excel()
    df_qr = load_and_map_qr()
    df_image = load_and_map_image()
    
    logger.info("")
    train_model("PDF", df_pdf, "model_pdf.pkl")
    train_model("Word", df_word, "model_word.pkl")
    train_model("Excel", df_excel, "model_excel.pkl")
    train_model("QR Code", df_qr, "model_qr.pkl")
    if len(df_image) > 0:
        train_model("Image", df_image, "model_image.pkl")
    
    dfs_to_combine = [df_pdf, df_word, df_excel, df_qr] + ([df_image] if len(df_image) > 0 else [])
    full_df = pd.concat(dfs_to_combine, ignore_index=True)
    if len(full_df) > 0:
        full_df.to_csv(DATASET_ROOT.parent / "training_data_collected.csv", index=False)
    
    logger.info("")
    logger.info("TRAINING COMPLETE")
    image_text = f" Image = {len(df_image)}" if len(df_image) > 0 else ""
    logger.info(f" Samples: PDF = {len(df_pdf)} Word = {len(df_word)} Excel = {len(df_excel)} QR = {len(df_qr)}{image_text} | Total = {len(full_df)}")
    malicious_count = len(full_df[full_df['label'] == 1]) if len(full_df) > 0 else 0
    clean_count = len(full_df[full_df['label'] == 0]) if len(full_df) > 0 else 0
    logger.info(f" Distribution: Clean = {clean_count} Malicious = {malicious_count}")
    model_text = "pdf, word, excel, qr" + (", image" if len(df_image) > 0 else "")
    logger.info(f" Models: {model_text}")

if __name__ == "__main__":
    main()
