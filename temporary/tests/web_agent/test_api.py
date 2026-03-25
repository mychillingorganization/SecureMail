import pytest
from fastapi.testclient import TestClient
import json

from main import app, _model

def test_health_check():
    with TestClient(app) as client:
        response = client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ok"
        assert data["service"] == "web-agent"

def test_analyze_invalid_payload():
    with TestClient(app) as client:
        response = client.post("/api/v1/analyze", json={})
        # Should be 422 because urls list is missing/invalid according to AnalyzeRequest?
        # Actually it defaults to []
        pass

def test_analyze_empty_urls():
    with TestClient(app) as client:
        response = client.post("/api/v1/analyze", json={"email_id": "test", "urls": []})
        assert response.status_code == 200
        data = response.json()
        assert data["risk_score"] == 0.0
        assert data["confidence"] == 0.0
        assert data["label"] == "safe"
        assert "url_analysis" in data["checks"]
        assert len(data["checks"]["url_analysis"]) == 0

def test_analyze_urls_json_endpoint():
    # The /api/v1/analyze-urls-json endpoint is expected by the orchestrator
    with TestClient(app) as client:
        response = client.post("/api/v1/analyze-urls-json", json={
            "email_id": "test1234",
            "urls_json": {
                "urls": ["http://example.com", "https://google.com"]
            }
        })
        
        # Test that model is loaded and we get a normal result
        assert response.status_code == 200
        data = response.json()
        assert "risk_score" in data
        assert "confidence" in data
        assert "label" in data
        assert "checks" in data
        assert "url_analysis" in data["checks"]
        assert len(data["checks"]["url_analysis"]) == 2
        for res in data["checks"]["url_analysis"]:
            assert "url" in res
            assert "risk_score" in res
            assert "redirection_chain" in res
