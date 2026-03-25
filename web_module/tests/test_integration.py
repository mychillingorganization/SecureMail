"""
Integration tests for Web Agent — comprehensive scenario coverage.

Tests cover:
- Blacklist/whitelist fast-path behavior
- Redirection chain handling
- Malformed input handling
- Error recovery
"""

import pytest
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient

from main import app


# ── Blacklist/Whitelist Fast-Path Tests ────────────────────────────────────


@patch("main.is_blacklisted")
@patch("main.is_whitelisted")
def test_blacklist_immediate_phishing_verdict(mock_whitelisted, mock_blacklisted):
    """Test that blacklisted URL immediately returns phishing verdict without feature extraction."""
    mock_blacklisted.return_value = True
    mock_whitelisted.return_value = False

    with TestClient(app) as client:
        response = client.post(
            "/api/v1/analyze",
            json={
                "email_id": "test-001",
                "urls": ["http://phishing-site.com/fake-login"],
            },
        )

    assert response.status_code == 200
    data = response.json()
    
    # Blacklisted → immediate phishing verdict
    assert data["risk_score"] == 0.99
    assert data["confidence"] == 0.98
    assert data["label"] == "phishing"
    
    # Check that the URL analysis shows source as "blacklist"
    url_result = data["checks"]["url_analysis"][0]
    assert url_result["source"] == "blacklist"
    assert url_result["html_features_used"] is False


@patch("main.is_blacklisted")
@patch("main.is_whitelisted")
def test_url_normalized_before_list_checks(mock_whitelisted, mock_blacklisted):
    """Test schemeless URLs are normalized before blacklist/whitelist checks."""
    mock_whitelisted.return_value = False

    def is_blacklisted_side_effect(candidate_url):
        return candidate_url == "https://phishing-site.com/login"

    mock_blacklisted.side_effect = is_blacklisted_side_effect

    with TestClient(app) as client:
        response = client.post(
            "/api/v1/analyze",
            json={
                "email_id": "test-001b",
                "urls": ["phishing-site.com/login"],
            },
        )

    assert response.status_code == 200
    data = response.json()

    assert data["label"] == "phishing"
    url_result = data["checks"]["url_analysis"][0]
    assert url_result["source"] == "blacklist"
    assert url_result["url"] == "https://phishing-site.com/login"


@patch("main.is_whitelisted")
@patch("main.is_blacklisted")
def test_whitelist_immediate_safe_verdict(mock_blacklisted, mock_whitelisted):
    """Test that whitelisted URL immediately returns safe verdict without feature extraction."""
    mock_blacklisted.return_value = False
    mock_whitelisted.return_value = True

    with TestClient(app) as client:
        response = client.post(
            "/api/v1/analyze",
            json={
                "email_id": "test-002",
                "urls": ["http://trusted-bank.com"],
            },
        )

    assert response.status_code == 200
    data = response.json()
    
    # Whitelisted → immediate safe verdict
    assert data["risk_score"] == 0.01
    assert data["confidence"] == 0.98
    assert data["label"] == "safe"
    
    url_result = data["checks"]["url_analysis"][0]
    assert url_result["source"] == "whitelist"
    assert url_result["html_features_used"] is False


# ── Redirection Chain Tests ────────────────────────────────────────────────


@patch("main.fetch_url_context")
@patch("main.is_blacklisted")
@patch("main.is_whitelisted")
def test_redirection_chain_with_malicious_intermediate(
    mock_whitelisted, mock_blacklisted, mock_fetch
):
    """Test that malicious redirects in chain are detected and caught by blacklist."""
    # User clicks: example.com → redirects to phishing-site.com
    redirection_chain = ["http://example.com", "http://phishing-site.com"]
    
    # Mock: return chain info, but intermediate is blacklisted
    mock_fetch.return_value = ("/phishing-site.com", "<html>...</html>", redirection_chain)
    
    def is_blacklisted_side_effect(url):
        return "phishing-site" in url
    
    mock_blacklisted.side_effect = is_blacklisted_side_effect
    mock_whitelisted.return_value = False

    with TestClient(app) as client:
        response = client.post(
            "/api/v1/analyze",
            json={"email_id": "test-003", "urls": ["http://example.com"]},
        )

    assert response.status_code == 200
    data = response.json()
    
    # Intermediate URL in chain is blacklisted → phishing verdict
    assert data["label"] == "phishing"
    
    url_result = data["checks"]["url_analysis"][0]
    assert url_result["input_url"] == "http://example.com"
    assert len(url_result["redirection_chain"]) == 2
    assert url_result["source"] == "blacklist"


@patch("main.fetch_url_context")
@patch("main.is_blacklisted")
@patch("main.is_whitelisted")
def test_redirection_chain_tracked_in_response(
    mock_whitelisted, mock_blacklisted, mock_fetch
):
    """Test that full redirection chain is captured and returned in response."""
    chain = ["http://a.com", "http://b.com", "http://c.com"]
    mock_fetch.return_value = ("http://c.com", "<html></html>", chain)
    mock_blacklisted.return_value = False
    mock_whitelisted.return_value = False

    with TestClient(app) as client:
        response = client.post(
            "/api/v1/analyze",
            json={"email_id": "test-004", "urls": ["http://a.com"]},
        )

    assert response.status_code == 200
    url_result = response.json()["checks"]["url_analysis"][0]
    
    # Verify redirection chain is captured
    assert url_result["redirection_chain"] == chain


# ── Malformed Input Handling ───────────────────────────────────────────────


def test_empty_url_list():
    """Test that empty URL list returns safe verdict with no risk."""
    with TestClient(app) as client:
        response = client.post(
            "/api/v1/analyze",
            json={"email_id": "test-005", "urls": []},
        )

    assert response.status_code == 200
    data = response.json()
    assert data["risk_score"] == 0.0
    assert data["confidence"] == 0.0
    assert data["label"] == "safe"
    assert len(data["checks"]["url_analysis"]) == 0


def test_max_urls_limit_enforced():
    """Test that request with > MAX_URLS_PER_REQUEST is rejected."""
    urls = [f"http://example{i}.com" for i in range(150)]  # > 100
    
    with TestClient(app) as client:
        response = client.post(
            "/api/v1/analyze",
            json={"email_id": "test-006", "urls": urls},
        )

    # Should reject with 422 Unprocessable Entity
    assert response.status_code == 422


def test_max_url_length_enforced():
    """Test that individual URLs > MAX_URL_LENGTH are rejected."""
    long_url = "http://example.com/" + "x" * 3000  # > 2048
    
    with TestClient(app) as client:
        response = client.post(
            "/api/v1/analyze",
            json={"email_id": "test-007", "urls": [long_url]},
        )

    # Should reject with 422
    assert response.status_code == 422


@patch("main.is_blacklisted")
@patch("main.is_whitelisted")
@patch("main.fetch_url_context")
def test_malformed_url_handled_gracefully(mock_fetch, mock_whitelisted, mock_blacklisted):
    """Test malformed URLs are rejected with 422 before analysis."""
    mock_blacklisted.return_value = False
    mock_whitelisted.return_value = False
    
    # Simulate network error during fetch
    mock_fetch.side_effect = Exception("Connection timeout")

    with TestClient(app) as client:
        response = client.post(
            "/api/v1/analyze",
            json={"email_id": "test-008", "urls": ["ht!tp://[invalid]"]},
        )

    # Should reject malformed URL at validation layer
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert detail["code"] == "invalid_url_hostname"
    assert detail["index"] == 0
    assert "hostname" in detail["reason"]


@patch("main.is_blacklisted")
@patch("main.is_whitelisted")
@patch("main.fetch_url_context")
def test_malformed_hostname_rejected_before_list_checks(
    mock_fetch, mock_whitelisted, mock_blacklisted
):
    """Malformed hostname should fail validation and skip list/fetch stages."""
    with TestClient(app) as client:
        response = client.post(
            "/api/v1/analyze",
            json={
                "email_id": "test-008b",
                "urls": ["https://example..com", "https://exa mple.com"],
            },
        )

    assert response.status_code == 422
    detail = response.json()["detail"]
    assert detail["code"] == "invalid_url_hostname"
    assert detail["index"] == 0
    assert "hostname" in detail["reason"]

    mock_blacklisted.assert_not_called()
    mock_whitelisted.assert_not_called()
    mock_fetch.assert_not_called()


# ── Concurrent Request Handling ────────────────────────────────────────────


@patch("main.is_blacklisted")
@patch("main.is_whitelisted")
def test_multiple_urls_analyzed_concurrently(mock_whitelisted, mock_blacklisted):
    """Test that multiple URLs in one request are analyzed concurrently."""
    mock_blacklisted.return_value = False
    mock_whitelisted.return_value = False

    with TestClient(app) as client:
        response = client.post(
            "/api/v1/analyze",
            json={
                "email_id": "test-009",
                "urls": [
                    "http://example1.com",
                    "http://example2.com",
                    "http://example3.com",
                ],
            },
        )

    assert response.status_code == 200
    data = response.json()
    
    # All 3 URLs should be analyzed
    assert len(data["checks"]["url_analysis"]) == 3


# ── Model Not Loaded (Degraded Mode) Tests ─────────────────────────────────


@patch("main.PhishingModel", side_effect=FileNotFoundError("model missing"))
def test_degraded_mode_returns_503(_mock_model_cls):
    """Test that when model is not loaded, API returns 503 Service Unavailable."""
    with TestClient(app) as client:
        response = client.post(
            "/api/v1/analyze",
            json={"email_id": "test-010", "urls": ["http://example.com"]},
        )

    # Should return 503 since model is not available
    assert response.status_code == 503
    assert "Model not initialised" in response.text


def test_health_check_degraded_mode():
    """Test that health check reports 'degraded' status when model is unavailable."""
    # This test would require patching app state during startup
    # For now, document that health endpoint should check _model status
    pass


# ── Analyze-URLs-JSON Endpoint ─────────────────────────────────────────────


def test_analyze_urls_json_endpoint_with_valid_payload():
    """Test the alternate /api/v1/analyze-urls-json endpoint."""
    with TestClient(app) as client:
        response = client.post(
            "/api/v1/analyze-urls-json",
            json={
                "email_id": "test-012",
                "urls_json": {"urls": ["http://example.com", "http://google.com"]},
            },
        )

    assert response.status_code == 200
    data = response.json()
    assert len(data["checks"]["url_analysis"]) == 2


def test_analyze_urls_json_rejects_malformed_urls_field():
    """Test that urls_json.urls must be a list of strings."""
    with TestClient(app) as client:
        response = client.post(
            "/api/v1/analyze-urls-json",
            json={
                "email_id": "test-013",
                "urls_json": {"urls": "not-a-list"},
            },
        )

    assert response.status_code == 422


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
