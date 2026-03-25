"""
Whitelist and Blacklist management for the Web Agent.

Loading is deferred to the FastAPI lifespan (`load_lists()`) so that
remote HTTP fetches never block at import time or during server startup.
"""

import asyncio
import logging
import os
from pathlib import Path
from urllib.parse import urlparse

import httpx

logger = logging.getLogger(__name__)

# ── Configuration ─────────────────────────────────────────────────────────────

_MODULE_DIR = Path(__file__).resolve().parent
_LIST_DIR_CANDIDATES: list[Path] = [
    # Preferred shared DB list location in this repository.
    _MODULE_DIR.parent / "src" / "db" / "data" / "lists",
    # Common when running from repository root (including many container setups).
    Path.cwd() / "src" / "db" / "data" / "lists",
    # Backward-compatible fallback location near this module.
    _MODULE_DIR / "data" / "lists",
]


def _resolve_default_list_file(filename: str) -> str:
    for directory in _LIST_DIR_CANDIDATES:
        candidate = directory / filename
        if candidate.exists():
            return str(candidate)
    return str(_LIST_DIR_CANDIDATES[0] / filename)


WHITELIST_FILE = os.getenv("WHITELIST_FILE", _resolve_default_list_file("whitelist.txt"))
BLACKLIST_FILE = os.getenv("BLACKLIST_FILE", _resolve_default_list_file("blacklist.txt"))
BLACKLIST_FETCH_TIMEOUT = float(os.getenv("BLACKLIST_FETCH_TIMEOUT", "8"))
BLACKLIST_SOURCE_URLS: list[str] = [
    "https://openphish.com/feed.txt",
]

# ── Runtime stores (populated on startup) ─────────────────────────────────────

_whitelisted_domains: set[str] = set()
_blacklisted_domains: set[str] = set()
_blacklisted_urls: set[str] = set()

# ── Internal helpers ──────────────────────────────────────────────────────────


def _bare_domain(raw: str) -> str | None:
    """Parse *raw* (URL or bare domain) into a lowercase domain without www. or port."""
    try:
        target = raw if "://" in raw else f"http://{raw}"
        parsed = urlparse(target)
        domain = (parsed.netloc or parsed.path).strip().lower()
        if domain.startswith("www."):
            domain = domain[4:]
        if ":" in domain:
            domain = domain.split(":")[0]
        return domain or None
    except ValueError:
        return None


def _normalize_entry(raw: str) -> tuple[str, str] | None:
    """Return ``(kind, value)`` for a non-blank, non-comment blacklist line.

    *kind* is ``"url"`` or ``"domain"``.  Returns ``None`` for empty/comment lines.
    """
    entry = raw.strip().lower()
    if not entry or entry.startswith("#"):
        return None
    if entry.startswith(("http://", "https://")):
        return ("url", entry)
    domain = _bare_domain(entry)
    return ("domain", domain) if domain else None


# ── File loaders ──────────────────────────────────────────────────────────────


def _read_whitelist(filepath: str) -> set[str]:
    domains: set[str] = set()
    try:
        with open(filepath, encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                stripped = line.strip().lower()
                if stripped and not stripped.startswith("#"):
                    domains.add(stripped)
    except FileNotFoundError:
        logger.warning("Whitelist file '%s' not found — using empty set.", filepath)
    return domains


def _read_blacklist_file(filepath: str) -> tuple[set[str], set[str]]:
    domains: set[str] = set()
    urls: set[str] = set()
    if not os.path.exists(filepath):
        return domains, urls
    try:
        with open(filepath, encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                result = _normalize_entry(line)
                if result:
                    kind, value = result
                    (urls if kind == "url" else domains).add(value)
    except OSError as exc:
        logger.warning("Could not read blacklist file '%s': %s", filepath, exc)
    return domains, urls


async def _fetch_remote_blacklists(
    source_urls: list[str], timeout: float
) -> tuple[set[str], set[str]]:
    domains: set[str] = set()
    urls: set[str] = set()
    async with httpx.AsyncClient(timeout=timeout) as client:
        for source_url in source_urls:
            try:
                response = await client.get(source_url)
                response.raise_for_status()
                for line in response.text.splitlines():
                    result = _normalize_entry(line)
                    if result:
                        kind, value = result
                        (urls if kind == "url" else domains).add(value)
                logger.info(
                    "Fetched blacklist from %s (%d domains, %d URLs so far)",
                    source_url,
                    len(domains),
                    len(urls),
                )
            except Exception as exc:  # network errors are non-fatal
                logger.warning("Could not fetch blacklist from '%s': %s", source_url, exc)
    return domains, urls


# ── Public API ────────────────────────────────────────────────────────────────


async def load_lists() -> None:
    """Populate whitelist and blacklist stores.  Must be called once at startup."""
    global _whitelisted_domains, _blacklisted_domains, _blacklisted_urls

    _whitelisted_domains = _read_whitelist(WHITELIST_FILE)
    file_domains, file_urls = _read_blacklist_file(BLACKLIST_FILE)
    remote_domains, remote_urls = await _fetch_remote_blacklists(
        BLACKLIST_SOURCE_URLS, BLACKLIST_FETCH_TIMEOUT
    )

    _blacklisted_domains = file_domains | remote_domains
    _blacklisted_urls = file_urls | remote_urls

    logger.info(
        "Lists ready — %d whitelisted domains | %d blacklisted domains | %d blacklisted URLs",
        len(_whitelisted_domains),
        len(_blacklisted_domains),
        len(_blacklisted_urls),
    )


# ── Refresh Statistics ────────────────────────────────────────────────────────

class RefreshStats:
    """Track statistics for threat list refresh operations."""
    
    def __init__(self):
        self.last_refresh: float | None = None
        self.refresh_count: int = 0
        self.successful_refreshes: int = 0
        self.failed_refreshes: int = 0
        self.last_error: str | None = None
        self.domains_count: int = len(_blacklisted_domains)
        self.urls_count: int = len(_blacklisted_urls)
        self.whitelist_count: int = len(_whitelisted_domains)
    
    def to_dict(self) -> dict:
        """Export stats as a dictionary."""
        return {
            "last_refresh": self.last_refresh,
            "refresh_count": self.refresh_count,
            "successful_refreshes": self.successful_refreshes,
            "failed_refreshes": self.failed_refreshes,
            "last_error": self.last_error,
            "domains_count": self.domains_count,
            "urls_count": self.urls_count,
            "whitelist_count": self.whitelist_count,
        }


_refresh_stats = RefreshStats()


async def refresh_lists(force: bool = False) -> dict:
    """
    Refresh threat lists from all sources with exponential backoff retry logic.
    
    Args:
        force: If True, refresh immediately even if one was attempted recently.
    
    Returns:
        Dictionary with status, stats, and any error messages.
    """
    from config import (
        THREAT_LIST_FETCH_TIMEOUT,
        THREAT_LIST_RETRY_MAX,
        THREAT_LIST_RETRY_BACKOFF_INITIAL,
        THREAT_LIST_RETRY_BACKOFF_MAX,
        THREAT_LIST_REFRESH_VERBOSE_LOGGING,
    )
    
    global _whitelisted_domains, _blacklisted_domains, _blacklisted_urls, _refresh_stats
    
    import time
    
    _refresh_stats.refresh_count += 1
    start_time = time.time()
    
    # Store previous state in case refresh fails (rollback capability)
    prev_blacklist_domains = _blacklisted_domains.copy()
    prev_blacklist_urls = _blacklisted_urls.copy()
    prev_whitelist_domains = _whitelisted_domains.copy()
    
    try:
        # Try to load fresh lists with retry backoff
        file_domains, file_urls = _read_blacklist_file(BLACKLIST_FILE)
        
        # Fetch remote with retries
        remote_domains, remote_urls = await _fetch_remote_blacklists_with_retry(
            BLACKLIST_SOURCE_URLS,
            BLACKLIST_FETCH_TIMEOUT,
            max_retries=THREAT_LIST_RETRY_MAX,
            initial_backoff=THREAT_LIST_RETRY_BACKOFF_INITIAL,
            max_backoff=THREAT_LIST_RETRY_BACKOFF_MAX,
        )
        
        # Merge all sources
        _blacklisted_domains = file_domains | remote_domains
        _blacklisted_urls = file_urls | remote_urls
        _whitelisted_domains = _read_whitelist(WHITELIST_FILE)
        
        # Update stats
        elapsed = time.time() - start_time
        _refresh_stats.last_refresh = start_time
        _refresh_stats.successful_refreshes += 1
        _refresh_stats.last_error = None
        _refresh_stats.domains_count = len(_blacklisted_domains)
        _refresh_stats.urls_count = len(_blacklisted_urls)
        _refresh_stats.whitelist_count = len(_whitelisted_domains)
        
        # Calculate deltas
        added_domains = len(_blacklisted_domains) - len(prev_blacklist_domains)
        added_urls = len(_blacklisted_urls) - len(prev_blacklist_urls)
        removed_domains = len(prev_blacklist_domains) - len(_blacklisted_domains)
        removed_urls = len(prev_blacklist_urls) - len(_blacklisted_urls)
        
        log_fn = logger.info if THREAT_LIST_REFRESH_VERBOSE_LOGGING else logger.debug
        log_fn(
            "Threat lists refreshed successfully in %.2fs — "
            "blacklist: %d domains, %d URLs | whitelist: %d domains | "
            "delta: +%d domains/%d URLs, -%d domains/%d URLs",
            elapsed,
            len(_blacklisted_domains),
            len(_blacklisted_urls),
            len(_whitelisted_domains),
            added_domains, added_urls,
            removed_domains, removed_urls,
        )
        
        return {
            "status": "success",
            "message": f"Refreshed {len(_blacklisted_domains)} blacklist domains, {len(_blacklisted_urls)} URLs",
            "stats": _refresh_stats.to_dict(),
            "elapsed_seconds": round(elapsed, 2),
        }
        
    except Exception as exc:
        # Rollback to previous state on failure
        _blacklisted_domains = prev_blacklist_domains
        _blacklisted_urls = prev_blacklist_urls
        _whitelisted_domains = prev_whitelist_domains
        
        _refresh_stats.failed_refreshes += 1
        _refresh_stats.last_error = str(exc)
        
        elapsed = time.time() - start_time
        logger.error(
            "Threat list refresh failed after %.2fs: %s — rolled back to previous state",
            elapsed,
            exc,
        )
        
        return {
            "status": "failed",
            "message": f"Refresh failed: {exc}",
            "stats": _refresh_stats.to_dict(),
            "elapsed_seconds": round(elapsed, 2),
        }


async def _fetch_remote_blacklists_with_retry(
    source_urls: list[str],
    timeout: float,
    max_retries: int = 3,
    initial_backoff: float = 1.0,
    max_backoff: float = 16.0,
) -> tuple[set[str], set[str]]:
    """
    Fetch remote blacklists with exponential backoff retry logic.
    
    On each retry, the backoff delay doubles: initial_backoff → 2x → 4x → ...
    up to max_backoff. Continues fetching all sources even if some fail.
    """
    domains: set[str] = set()
    urls: set[str] = set()
    
    for source_url in source_urls:
        backoff = initial_backoff
        last_error = None
        
        for attempt in range(max_retries):
            try:
                async with httpx.AsyncClient(timeout=timeout) as client:
                    response = await client.get(source_url)
                    response.raise_for_status()
                    for line in response.text.splitlines():
                        result = _normalize_entry(line)
                        if result:
                            kind, value = result
                            (urls if kind == "url" else domains).add(value)
                    
                    logger.debug(
                        "Fetched blacklist from %s (%d domains, %d URLs so far)",
                        source_url,
                        len(domains),
                        len(urls),
                    )
                    break  # Success, move to next source
                    
            except Exception as exc:
                last_error = exc
                if attempt < max_retries - 1:
                    logger.warning(
                        "Fetch attempt %d/%d failed for '%s': %s — retrying in %.1fs",
                        attempt + 1,
                        max_retries,
                        source_url,
                        exc,
                        backoff,
                    )
                    await asyncio.sleep(backoff)
                    backoff = min(backoff * 2, max_backoff)  # Exponential backoff
                else:
                    logger.warning(
                        "All %d retry attempts exhausted for '%s': %s",
                        max_retries,
                        source_url,
                        exc,
                    )
        
        if last_error and attempt == max_retries - 1:
            # Log final failure but continue with next source
            logger.warning("Skipping source '%s' after %d failed attempts", source_url, max_retries)
    
    return domains, urls


def is_whitelisted(url: str) -> bool:
    """Return ``True`` if *url*'s domain (or any parent) is whitelisted."""
    domain = _bare_domain(url)
    if not domain:
        return False
    if domain in _whitelisted_domains:
        return True
    return any(domain.endswith("." + trusted) for trusted in _whitelisted_domains)


def is_blacklisted(url: str) -> bool:
    """Return ``True`` if *url* or its domain (or any parent) is blacklisted."""
    normalized = url.strip().lower()
    if not normalized.startswith(("http://", "https://")):
        normalized = f"http://{normalized}"
    if normalized in _blacklisted_urls:
        return True
    domain = _bare_domain(normalized)
    if not domain:
        return False
    if domain in _blacklisted_domains:
        return True
    return any(domain.endswith("." + blocked) for blocked in _blacklisted_domains)
