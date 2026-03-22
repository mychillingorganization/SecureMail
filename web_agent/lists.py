"""
Whitelist and Blacklist management for the Web Agent.

Loading is deferred to the FastAPI lifespan (`load_lists()`) so that
remote HTTP fetches never block at import time or during server startup.
"""

import logging
import os
from urllib.parse import urlparse

import httpx

logger = logging.getLogger(__name__)

# ── Configuration ─────────────────────────────────────────────────────────────

WHITELIST_FILE = os.getenv("WHITELIST_FILE", "whitelist.txt")
BLACKLIST_FILE = os.getenv("BLACKLIST_FILE", "blacklist.txt")
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
