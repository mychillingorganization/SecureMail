"""
Feature extraction for phishing URL detection.

Two stages:
  1. ``extract_url_features(url)``  — 30 static features, no network I/O.
  2. ``fetch_html(url)``            — async HTTP fetch.
     ``extract_html_features(html)`` — 40 DOM-based features from raw HTML.

Callers should always merge both dicts before passing to the model.
"""

import asyncio
import ipaddress
import logging
import re
import socket
from urllib.parse import urljoin, urlparse

import httpx

logger = logging.getLogger(__name__)

# ── Constants ─────────────────────────────────────────────────────────────────

_SHORTENING_RE = re.compile(
    r"bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|"
    r"tr\.im|is\.gd|cli\.gs|yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|"
    r"twit\.ac|su\.pr|twurl\.nl|snipurl\.com|short\.to|BudURL\.com|ping\.fm|"
    r"post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|doiop\.com|"
    r"short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|lnkd\.in|"
    r"db\.tt|qr\.ae|adf\.ly|bitly\.com|cur\.lv|ity\.im|q\.gs|po\.st|bc\.vc|"
    r"twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|"
    r"prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|"
    r"1url\.com|tweez\.me|v\.gd|link\.zip\.net",
    re.IGNORECASE,
)

_SUSPICIOUS_URL_KEYWORDS = frozenset(
    [
        "login", "signin", "account", "verify", "update", "secure", "banking",
        "paypal", "ebay", "amazon", "confirm", "suspend", "bonus", "free", "click",
    ]
)

_SUSPICIOUS_HTML_KEYWORDS = frozenset(
    [
        "verify", "account", "suspend", "login", "signin", "update", "confirm",
        "secure", "banking", "click here", "urgent", "expired",
        "verify your account", "update your information",
    ]
)

_SOCIAL_KEYWORDS = frozenset(["facebook", "twitter", "instagram", "linkedin", "youtube"])

_RE_DISPLAY_NONE = re.compile(
    r"display\s*:\s*none|visibility\s*:\s*hidden", re.IGNORECASE
)
_RE_EMAIL = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")
_RE_TAGS = re.compile(r"<[^>]+>")

MAX_REDIRECT_HOPS = 5

# Default HTML features returned when the page cannot be fetched / parsed.
HTML_DEFAULT_FEATURES: dict[str, int | float] = {
    "NoOfForms": 0,
    "NoOfInputs": 0,
    "NoOfPasswordFields": 0,
    "NoOfEmailFields": 0,
    "NoOfHiddenFields": 0,
    "NoOfLinks": 0,
    "NoOfExternalLinks": 0,
    "NoOfInternalLinks": 0,
    "NoOfNullLinks": 0,
    "ExternalLinkRatio": 0.0,
    "NoOfExternalFormActions": 0,
    "NoOfScripts": 0,
    "NoOfInlineScripts": 0,
    "NoOfIframes": 0,
    "NoOfImages": 0,
    "NoOfMetaTags": 0,
    "HasTitle": 0,
    "TitleLength": 0,
    "SuspiciousKeywordsCount": 0,
    "NoOfButtons": 0,
    "NoOfTextareas": 0,
    "NoOfStyleTags": 0,
    "NoOfExternalCSS": 0,
    "HasObfuscation": 0,
    "HasPopup": 0,
    "HTMLLength": 0,
    "TextLength": 0,
    "TextToHTMLRatio": 0.0,
    "HasFavicon": 0,
    "NoOfSocialLinks": 0,
    "NoOfEmailsInHTML": 0,
}

# ── URL Feature Extraction ────────────────────────────────────────────────────


def extract_url_features(url: str) -> dict[str, int | float]:
    """Extract 30 static URL features — no network I/O required.

    All values are numeric (int or float) and safe to feed directly to XGBoost.
    """
    url_str = str(url)
    url_lower = url_str.lower()

    try:
        parsed = urlparse(url_str)
    except ValueError:
        from urllib.parse import ParseResult
        parsed = ParseResult("", "", "", "", "", "")

    netloc = parsed.netloc or ""
    path = parsed.path or ""
    query = parsed.query or ""
    parts = [p for p in netloc.split(".") if p]

    n_letters = sum(c.isalpha() for c in url_str)
    n_digits = sum(c.isdigit() for c in url_str)
    url_len = len(url_str)

    # Have_IP: true when the hostname is a raw IP address
    have_ip = 0
    try:
        host = netloc.split(":")[0]
        if host:
            ipaddress.ip_address(host)
            have_ip = 1
    except ValueError:
        pass

    # Redirection: '//' appears after position 7 (past 'https://')
    try:
        redirection = 1 if url_str.rfind("//") > 7 else 0
    except Exception:
        redirection = 0

    # HasPort: netloc contains a numeric port
    has_port = 0
    if ":" in netloc:
        possible_port = netloc.split(":")[-1]
        if possible_port.isdigit():
            has_port = 1

    special_chars = r"""!@#$%^&*()[]{}|\:;"'<>,.?/~`"""

    return {
        "DomainPartCount": len(parts),
        "Have_IP": have_ip,
        "Have_At": 1 if "@" in url_str else 0,
        "URL_Length": url_len,
        "URL_Depth": len([x for x in path.split("/") if x]),
        "Redirection": redirection,
        "https_Domain": 1 if "http" in netloc.lower() else 0,
        "TinyURL": 1 if _SHORTENING_RE.search(url_str) else 0,
        "Prefix_Suffix": 1 if "-" in netloc else 0,
        "IsHTTPS": 1 if parsed.scheme == "https" else 0,
        "NoOfDots": url_str.count("."),
        "NoOfHyphen": url_str.count("-"),
        "NoOfUnderscore": url_str.count("_"),
        "NoOfSlash": url_str.count("/"),
        "NoOfQuestionMark": url_str.count("?"),
        "NoOfEquals": url_str.count("="),
        "NoOfAmpersand": url_str.count("&"),
        "NoOfPercent": url_str.count("%"),
        "NoOfDigits": n_digits,
        "NoOfLetters": n_letters,
        "LetterRatio": n_letters / max(url_len, 1),
        "DigitRatio": n_digits / max(url_len, 1),
        "HasSubdomain": 1 if len(parts) > 2 else 0,
        "SubdomainCount": max(len(parts) - 2, 0),
        "DomainLength": len(netloc),
        "PathLength": len(path),
        "QueryLength": len(query),
        "HasPort": has_port,
        "SuspiciousWords": (
            1 if any(kw in url_lower for kw in _SUSPICIOUS_URL_KEYWORDS) else 0
        ),
        "SpecialCharCount": sum(1 for c in url_str if c in special_chars),
    }


# ── HTML Feature Extraction ───────────────────────────────────────────────────


def extract_html_features(html_content: str) -> dict[str, int | float]:
    """Extract 40 DOM-based features from raw HTML.

    Returns ``HTML_DEFAULT_FEATURES`` (all zeros) on parse failure or empty input.
    """
    if not html_content:
        return dict(HTML_DEFAULT_FEATURES)

    try:
        from collections import Counter
        from bs4 import BeautifulSoup

        soup = BeautifulSoup(html_content, "html.parser")
        tag_counter: Counter[str] = Counter()
        forms, inputs, link_hrefs, scripts, link_tags = [], [], [], [], []
        title_text: str | None = None

        for tag in soup.find_all(True):
            name = tag.name
            tag_counter[name] += 1
            if name == "form":
                forms.append(tag)
            elif name == "input":
                inputs.append(tag)
            elif name == "a":
                href = tag.get("href")
                if href is not None:
                    link_hrefs.append(href)
            elif name == "script":
                scripts.append(tag)
            elif name == "link":
                link_tags.append(tag)
            elif name == "title" and title_text is None:
                title_text = tag.string

        external_links = sum(
            1 for h in link_hrefs if str(h).startswith(("http://", "https://"))
        )
        null_links = sum(
            1
            for h in link_hrefs
            if str(h).startswith("#") or str(h) in ("", "javascript:")
        )
        internal_links = len(link_hrefs) - external_links - null_links

        html_lower = html_content.lower()
        text_approx = _RE_TAGS.sub(" ", html_lower)

        def _rel_str(lt) -> str:
            rel = lt.get("rel", [])
            return (" ".join(rel) if isinstance(rel, list) else str(rel)).lower()

        has_favicon = any("icon" in _rel_str(lt) for lt in link_tags)

        return {
            "NoOfForms": len(forms),
            "NoOfInputs": len(inputs),
            "NoOfPasswordFields": sum(
                1 for i in inputs if i.get("type") == "password"
            ),
            "NoOfEmailFields": sum(
                1
                for i in inputs
                if i.get("type") == "email"
                or "email" in str(i.get("name", "")).lower()
            ),
            "NoOfHiddenFields": sum(
                1 for i in inputs if i.get("type") == "hidden"
            ),
            "NoOfLinks": len(link_hrefs),
            "NoOfExternalLinks": external_links,
            "NoOfInternalLinks": internal_links,
            "NoOfNullLinks": null_links,
            "ExternalLinkRatio": external_links / max(len(link_hrefs), 1),
            "NoOfExternalFormActions": sum(
                1
                for f in forms
                if str(f.get("action", "")).startswith(("http://", "https://"))
            ),
            "NoOfScripts": len(scripts),
            "NoOfInlineScripts": sum(
                1 for s in scripts if s.string and s.string.strip()
            ),
            "NoOfIframes": tag_counter["iframe"],
            "NoOfImages": tag_counter["img"],
            "NoOfMetaTags": tag_counter["meta"],
            "NoOfButtons": tag_counter["button"],
            "NoOfTextareas": tag_counter["textarea"],
            "HasTitle": 1 if title_text else 0,
            "TitleLength": len(title_text) if title_text else 0,
            "SuspiciousKeywordsCount": sum(
                1 for kw in _SUSPICIOUS_HTML_KEYWORDS if kw in html_lower
            ),
            "NoOfStyleTags": tag_counter["style"],
            "NoOfExternalCSS": sum(
                1 for lt in link_tags if "stylesheet" in _rel_str(lt)
            ),
            "HasObfuscation": 1 if _RE_DISPLAY_NONE.search(html_content) else 0,
            "HasPopup": (
                1
                if "window.open" in html_lower or "alert(" in html_lower
                else 0
            ),
            "HTMLLength": len(html_content),
            "TextLength": len(text_approx),
            "TextToHTMLRatio": len(text_approx) / max(len(html_content), 1),
            "HasFavicon": 1 if has_favicon else 0,
            "NoOfSocialLinks": sum(
                1
                for h in link_hrefs
                if any(s in str(h).lower() for s in _SOCIAL_KEYWORDS)
            ),
            "NoOfEmailsInHTML": len(_RE_EMAIL.findall(html_content)),
        }

    except Exception as exc:
        logger.debug("HTML feature extraction failed: %s", exc)
        return dict(HTML_DEFAULT_FEATURES)


# ── Async HTML Fetcher ────────────────────────────────────────────────────────


async def fetch_html(url: str, timeout: float = 8.0) -> str | None:
    """Async-fetch the HTML content of *url*.

    Returns the response text, or ``None`` when the fetch fails or the
    response is not HTML.
    """
    _, html_content, _ = await fetch_url_context(url, timeout=timeout)
    return html_content


async def fetch_url_context(url: str, timeout: float = 8.0) -> tuple[str, str | None, list[str]]:
    """Fetch URL and return (final_url, html_content, redirection_chain).

    - final_url reflects the post-redirect destination when available.
    - html_content is ``None`` when request fails or the response is non-HTML.
    - redirection_chain is a list of URLs visited during redirection (including the initial URL).
    """
    fetch_url = _normalize_fetch_url(url)
    headers = {"User-Agent": "Mozilla/5.0 (compatible; SecureMail-WebAgent/1.0)"}
    chain: list[str] = [fetch_url]
    if not await _is_safe_public_url(fetch_url):
        logger.info("Blocked URL fetch by SSRF guard: %s", fetch_url)
        return fetch_url, None, chain

    try:
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=False) as client:
            current_url = fetch_url

            for _ in range(MAX_REDIRECT_HOPS + 1):
                async with client.stream("GET", current_url, headers=headers) as response:
                    if response.status_code in {301, 302, 303, 307, 308}:
                        location = response.headers.get("location")
                        if not location:
                            return str(response.url), None, chain
                        next_url = urljoin(str(response.url), location)
                        chain.append(next_url)
                        if not await _is_safe_public_url(next_url):
                            logger.info(
                                "Blocked redirect by SSRF guard: %s -> %s",
                                current_url,
                                next_url,
                            )
                            return current_url, None, chain
                        current_url = next_url
                        continue
                    
                    response.raise_for_status()
                    final_url = str(response.url)
                    content_type = response.headers.get("content-type", "").lower()
                    if content_type and "text/html" not in content_type:
                        return final_url, None, chain

                    body = bytearray()
                    async for chunk in response.aiter_bytes():
                        body.extend(chunk)
                        if len(body) > 2 * 1024 * 1024:
                            logger.warning("HTML body exceeds 2MB limit for %s, truncating", final_url)
                            break
                            
                    return final_url, body.decode("utf-8", errors="ignore"), chain

            return fetch_url, None, chain
    except (httpx.HTTPError, httpx.TimeoutException) as exc:
        logger.debug("HTML fetch failed for '%s': %s", url, exc)
        return fetch_url, None, chain


def _normalize_fetch_url(url: str) -> str:
    stripped = str(url).strip()
    return stripped if stripped.startswith(("http://", "https://")) else f"http://{stripped}"


def _is_public_ip(ip_str: str) -> bool:
    try:
        ip_obj = ipaddress.ip_address(ip_str)
    except ValueError:
        return False

    return not (
        ip_obj.is_private
        or ip_obj.is_loopback
        or ip_obj.is_link_local
        or ip_obj.is_multicast
        or ip_obj.is_reserved
        or ip_obj.is_unspecified
    )


async def _is_safe_public_url(url: str) -> bool:
    try:
        parsed = urlparse(url)
    except ValueError:
        return False

    if parsed.scheme not in {"http", "https"}:
        return False

    hostname = parsed.hostname
    if not hostname:
        return False

    # Direct IP host
    try:
        ipaddress.ip_address(hostname)
        return _is_public_ip(hostname)
    except ValueError:
        pass

    # DNS host: all resolved addresses must be public
    try:
        addrinfos = await asyncio.to_thread(socket.getaddrinfo, hostname, None)
    except Exception:
        return False

    if not addrinfos:
        return False

    addresses = {info[4][0] for info in addrinfos if info and len(info) >= 5 and info[4]}
    return bool(addresses) and all(_is_public_ip(address) for address in addresses)
