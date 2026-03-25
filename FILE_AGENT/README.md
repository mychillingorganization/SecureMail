# 📋 File Agent — Malware Analysis System

Fast, accurate file analysis for email attachments using hash lookup, static analysis, ML prediction, and dynamic sandbox.

**Pipeline:** `hash triage → static analysis → XGBoost → [optional] sandbox → quarantine`

---

## 🎯 File Types Supported

| Type | Extensions | Detection |
|------|-----------|-----------|
| PE | .exe, .dll, .msi | Packer, imports, entropy |
| OFFICE | .doc, .docx, .xls, .xlsx, .ppt | Macro, auto-exec keywords |
| PDF | .pdf | /JS, /Launch action |
| SCRIPT | .js, .vbs, .ps1 | Obfuscation, syscalls |
| ARCHIVE | .zip, .rar, .7z | Zip bomb, recursive scanning |
| OTHER | any | YARA rules, magic bytes |

---

## ⚡ How It Works (5 Stages)

1. **Hash Triage** (~1s): SHA-256 → Redis → IOC Database
2. **Static Analysis** (~3-5s): macros, imports, entropy, YARA rules
3. **ML Prediction** (~1s): XGBoost classifier (86% accuracy)
4. **Sandbox** (70-120s, optional): Wine/Linux containers + network monitor
5. **Decision**: Aggregate all signals → risk level + action

---

## 📦 Installation

### Requirements
- Python 3.8+, Redis, Docker (optional)

### Setup

```bash
# Linux/Ubuntu
cd "/home/tkayyy/Project Hackathon"
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Windows
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

### Redis (Required)

```bash
# System package
sudo apt-get install redis-server && sudo systemctl start redis-server

# Or Docker
docker run -d --name redis -p 6379:6379 redis:latest
```

---

## 🚀 Quick Start

### Start API Server

```bash
# Linux
cd file_module && source ../venv/bin/activate
python -m uvicorn main:app --reload

# Windows
cd file_module && ..\venv\Scripts\python.exe -m uvicorn main:app --reload
```

Access Swagger UI: **http://localhost:8000/docs**

### API Endpoints

| Endpoint | Time | Purpose |
|----------|------|---------|
| `POST /analyze` | 5-10s | Hash + static |
| `POST /analyze/full` | 70-120s | Full + sandbox |
| `POST /clawback/{id}` | <1s | Quarantine email |
| `GET /result/{id}` | <1s | Get results |

### Train Models

```bash
python dataset/extract_all.py --input "dataset/Dataset"
python dataset/Training_Model.py
```

---

## 📊 System Architecture

```
file_module/           API & analysis
  ├── main.py        FastAPI server
  ├── hash_triage.py IOC Database + ClamAV
  ├── static_analyzer.py File analysis
  ├── xgboost_classifier.py Risk prediction
  └── dynamic_sandbox.py Sandbox orchestration

dataset/             ML & training
  ├── extract_all.py Feature extraction
  └── Training_Model.py XGBoost model

yara_rules/          Malware signatures
  ├── malware_index.yar
  ├── office_malware.yar
  └── pe_packed.yar

Sandbox/             Docker containers
  ├── Dockerfile.wine
  └── Dockerfile.linux
```

---

## 📈 Risk Levels

| Level | Action | Time |
|-------|--------|------|
| CLEAN (0.0) | Allow | 5-10s |
| LOW (0.25) | Review | 5-10s |
| MEDIUM (0.5) | Sandbox | 70-120s |
| HIGH (0.75) | Quarantine | 70-120s |
| CRITICAL (0.9) | Immediate isolation | <1s |

---

## ✅ Features

- ✅ 4 ML models (PDF, Word, Excel, QR) with 86% accuracy
- ✅ Hash-based IOC detection + ClamAV scanning
- ✅ Dynamic sandbox + network monitoring
- ✅ Post-delivery clawback
- ✅ Async API + Redis cache
- ✅ Docker orchestration

---

## 🔧 Configuration

Edit `file_module/config.py`:
- Redis connection
- PostgreSQL for IOC database
- Sandbox timeout (default: 90s)
- Max file size (default: 50MB)

---

