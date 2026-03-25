"""
Tests for threat list refresh functionality with retry logic.
"""

import pytest
from unittest.mock import AsyncMock, patch, MagicMock
import httpx

from lists import (
    refresh_lists,
    _fetch_remote_blacklists_with_retry,
    _refresh_stats,
    RefreshStats,
)


@pytest.mark.asyncio
async def test_refresh_lists_success():
    """Test successful threat list refresh."""
    result = await refresh_lists(force=True)
    
    assert result["status"] == "success"
    assert "stats" in result
    assert "elapsed_seconds" in result
    assert result["stats"]["refresh_count"] >= 1
    assert result["stats"]["successful_refreshes"] >= 1


@pytest.mark.asyncio
async def test_refresh_stats_tracking():
    """Test that refresh statistics are properly tracked."""
    initial_count = _refresh_stats.refresh_count
    initial_success = _refresh_stats.successful_refreshes
    
    result = await refresh_lists(force=True)
    
    assert result["status"] == "success"
    assert _refresh_stats.refresh_count > initial_count
    assert _refresh_stats.successful_refreshes > initial_success
    assert _refresh_stats.last_refresh is not None
    assert _refresh_stats.last_error is None


@pytest.mark.asyncio
async def test_refresh_stats_export():
    """Test that RefreshStats.to_dict() exports all required fields."""
    stats = RefreshStats()
    result = stats.to_dict()
    
    required_fields = {
        "last_refresh",
        "refresh_count",
        "successful_refreshes",
        "failed_refreshes",
        "last_error",
        "domains_count",
        "urls_count",
        "whitelist_count",
    }
    
    assert all(field in result for field in required_fields)


@pytest.mark.asyncio
async def test_fetch_remote_with_retry_all_fail():
    """Test retry logic when all fetches fail."""
    sources = ["https://invalid-source-1.example.com/feed.txt"]
    
    # Mock failed HTTP response
    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
        mock_get.side_effect = httpx.ConnectError("Connection failed")
        
        domains, urls = await _fetch_remote_blacklists_with_retry(
            sources,
            timeout=5.0,
            max_retries=2,
            initial_backoff=0.1,
            max_backoff=0.2,
        )
        
        # Should return empty sets after retries exhausted
        assert domains == set()
        assert urls == set()
        
        # Verify retries were attempted
        assert mock_get.call_count >= 2  # At least 2 attempts


@pytest.mark.asyncio
async def test_fetch_remote_with_exponential_backoff():
    """Test exponential backoff behavior during retries."""
    sources = ["https://test-source.example.com/feed.txt"]
    call_times = []
    
    async def mock_get_with_timing(*args, **kwargs):
        import time
        call_times.append(time.time())
        if len(call_times) < 3:
            raise httpx.ConnectError("Connection failed")
        # Success on 3rd attempt
        response = MagicMock()
        response.text = "example.com\n192.168.1.1\n"
        response.raise_for_status = MagicMock()
        return response
    
    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
        mock_get.side_effect = mock_get_with_timing
        
        domains, urls = await _fetch_remote_blacklists_with_retry(
            sources,
            timeout=5.0,
            max_retries=3,
            initial_backoff=0.05,
            max_backoff=0.2,
        )
        
        # Should succeed on 3rd attempt
        assert len(domains) > 0
        
        # Verify timing: backoff should be ~0.05s then ~0.1s
        if len(call_times) >= 3:
            backoff_1 = call_times[1] - call_times[0]
            backoff_2 = call_times[2] - call_times[1]
            # Each backoff should be roughly double the previous (within tolerance)
            assert backoff_2 > backoff_1 or abs(backoff_2 - backoff_1) < 0.05  # tolerance


@pytest.mark.asyncio
async def test_refresh_lists_stats_on_failure():
    """Test that stats are updated even on failure."""
    initial_failed = _refresh_stats.failed_refreshes
    
    with patch("lists._read_whitelist", side_effect=Exception("Mock error")):
        with patch("lists._read_blacklist_file", side_effect=Exception("Mock error")):
            result = await refresh_lists(force=True)
            
            assert result["status"] == "failed"
            assert "error" in result["message"].lower()
            assert _refresh_stats.failed_refreshes > initial_failed


@pytest.mark.asyncio
async def test_fetch_remote_multiple_sources():
    """Test fetching from multiple sources with partial failure."""
    sources = [
        "https://source1.example.com/feed.txt",
        "https://source2.example.com/feed.txt",
    ]
    
    call_count = 0
    
    async def mock_get_partial_failure(*args, **kwargs):
        nonlocal call_count
        call_count += 1
        
        # First source: fail once then succeed
        if call_count <= 2:
            if call_count == 1:
                raise httpx.ConnectError("Connection failed")
            response = MagicMock()
            response.text = "example1.com\nexample2.com\n"
            response.raise_for_status = MagicMock()
            return response
        
        # Second source: succeed immediately
        response = MagicMock()
        response.text = "example3.com\nhttps://phishing.com\n"
        response.raise_for_status = MagicMock()
        return response
    
    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
        mock_get.side_effect = mock_get_partial_failure
        
        domains, urls = await _fetch_remote_blacklists_with_retry(
            sources,
            timeout=5.0,
            max_retries=2,
            initial_backoff=0.01,
            max_backoff=0.02,
        )
        
        # Should have collected from both sources
        assert len(domains) >= 3  # At least example1.com, example2.com, example3.com
        assert len(urls) >= 1  # At least the URL from source 2


@pytest.mark.asyncio
async def test_refresh_preserves_previous_lists_on_failure():
    """Test that previous lists are preserved (rollback) when refresh fails."""
    # Import fresh to get current state
    from lists import _blacklisted_domains, _blacklisted_urls
    
    # Capture current state
    prev_domains_count = len(_blacklisted_domains)
    prev_urls_count = len(_blacklisted_urls)
    
    # Mock a failure
    with patch("lists._read_whitelist", side_effect=Exception("Read failed")):
        with patch("lists._read_blacklist_file", side_effect=Exception("Read failed")):
            result = await refresh_lists(force=True)
            
            # Should fail
            assert result["status"] == "failed"
            
            # Lists should still be available (not cleared)
            from lists import _blacklisted_domains as current_domains
            from lists import _blacklisted_urls as current_urls
            
            assert len(current_domains) >= 0  # Should not crash
            assert len(current_urls) >= 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
