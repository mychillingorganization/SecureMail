from fastapi import FastAPI
from pydantic import BaseModel
import joblib
import numpy as np
import re
import math
from scipy.sparse import hstack

# ================== LOAD MODEL ==================
model = joblib.load('svm_model.pkl')
tfidf = joblib.load('tfidf.pkl')
scaler = joblib.load('scaler.pkl')

# ================== INIT APP ==================
app = FastAPI()

# ================== REQUEST SCHEMA ==================
class EmailRequest(BaseModel):
    subject: str
    email: str

# ================== FEATURE FUNCTION ==================
def extract_features(text):
    text = str(text)
    return [
        len(text),
        len(re.findall(r'http[s]?://', text)),
        int(bool(re.search(r'urgent|money|bank|transfer|account|verify|login', text.lower()))),
        sum(c.isdigit() for c in text),
        text.count('!'),
        int(bool(re.search(r'[A-Z]{5,}', text)))
    ]

# ================== ROOT ==================
@app.get("/")
def home():
    return {"message": "Phishing Detection API is running"}

# ================== PREDICT ==================
@app.post("/predict")
def predict(req: EmailRequest):
    # Gộp subject + body
    full_text = req.subject + " " + req.email

    # TF-IDF
    text_vec = tfidf.transform([full_text])
    
    # Feature engineering
    extra = np.array([extract_features(full_text)])
    extra_scaled = scaler.transform(extra)
    
    # Combine
    final = hstack([text_vec, extra_scaled])
    
    # Predict
    pred = model.predict(final)[0]

    # Raw score (SVM)
    score = float(model.decision_function(final)[0])

    # Convert → confidence (0 → 1)
    confidence = 1 / (1 + math.exp(-score))

    return {
        "prediction": "phishing" if pred == 1 else "safe",
        "confidence": round(confidence, 4),
        "raw_score": round(score, 4)
    }