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
    
    **Feature Groups** (see docs/FEATURES.md for full documentation):
    - **Identity/Trust Signals** (7 features): Have_IP, Have_At, IsHTTPS, https_Domain, Prefix_Suffix, TinyURL, SuspiciousWords
      * Phishing Signal: Legitimate domains rarely use raw IPs, multiple @ symbols, or URL shorteners.
    - **Structural Complexity** (13 features): DomainPartCount, SubdomainCount, URL_Depth, URL_Length, path/query/domain lengths
      * Phishing Signal: Obfuscated URLs with deep subdomains, long query strings used to hide true destination.
    - **Character Distribution** (10 features): special char counts, letter/digit ratios
      * Phishing Signal: Unusual character mixes indicate encoding obfuscation or random padding.
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

    # ─ TRUST SIGNALS ─
    # Have_IP: binary flag indicating raw IP address used instead of domain name.
    # Phishing detectors > 0: Legitimate sites rarely use raw IPs; typical range: 0-1
    have_ip = 0
    try:
        host = netloc.split(":")[0]
        if host:
            ipaddress.ip_address(host)
            have_ip = 1
    except ValueError:
        pass

    # Redirection: binary flag for embedded '//' after the scheme (e.g., 'https://').
    # Phishing signal: URI confusion attacks use extra '//' to obfuscate the actual destination.
    # Range: 0-1 (expected: 0 for legitimate URLs)
    try:
        redirection = 1 if url_str.rfind("//") > 7 else 0
    except Exception:
        redirection = 0

    # HasPort: binary flag indicating explicit port number in netloc (e.g., :8080, :443).
    # Phishing signal: Non-standard ports often used to bypass filtering; range: 0-1
    has_port = 0
    if ":" in netloc:
        possible_port = netloc.split(":")[-1]
        if possible_port.isdigit():
            has_port = 1

    special_chars = r"""!@#$%^&*()[]{}|\:;"'<>,.?/~`"""

    return {
        # ──────────────────────────────────────────────────────────────────────
        # DOMAIN STRUCTURE (5 features)
        # ──────────────────────────────────────────────────────────────────────
        # DomainPartCount: number of labels (parts separated by '.') in the domain.
        # Range: 1-5 typical; expected: 1-3 for legitimate. >4 indicates subdomain obfuscation.
        # Phishing signal: Deep subdomains hide true domain origin (e.g., a.b.c.d.example.phishing.com).
        "DomainPartCount": len(parts),
        
        # HasSubdomain: binary flag for presence of subdomains (parts.count > 2).
        # Range: 0-1; expected: 0 (no subdomains) or 1 (has subdomains)
        # Phishing signal: Legitimate orgs often use 1-2 levels; excessive nesting is suspicious.
        "HasSubdomain": 1 if len(parts) > 2 else 0,
        
        # SubdomainCount: number of subdomains (parts.count - 2, min 0).
        # Range: 0-10 typical; expected: 0-2 for legitimate. >4 is suspicious.
        # Phishing signal: Each additional subdomain increases obfuscation potential.
        "SubdomainCount": max(len(parts) - 2, 0),
        
        # DomainLength: character count of the netloc (domain + port).
        # Range: 5-255; expected: 10-50 for legitimate. >100 is unusual and suspicious.
        # Phishing signal: Extremely long domains used to hide true sender via visual truncation.
        "DomainLength": len(netloc),
        
        # Prefix_Suffix: binary flag for presence of hyphen '-' in the domain name.
        # Range: 0-1; expected: 0 (legitimate domains rarely use hyphens)
        # Phishing signal: Hyphens confuse visual parsing; e.g., 'amaz-on.com' mimics 'amazon.com'.
        "Prefix_Suffix": 1 if "-" in netloc else 0,

        # ──────────────────────────────────────────────────────────────────────
        # TRUST SIGNALS & PROTOCOLS (5 features)
        # ──────────────────────────────────────────────────────────────────────
        # Have_IP: binary flag indicating hostname is a raw IPv4/IPv6 address.
        # Range: 0-1; expected: 0 (legitimate sites use domain names)
        # Phishing signal: IP addresses bypass DNS reputation lookups and domain WHOIS verification.
        "Have_IP": have_ip,
        
        # IsHTTPS: binary flag for HTTPS scheme in the URL.
        # Range: 0-1; expected: 1 for modern legitimate sites. 0 = HTTP (less secure, suspicious).
        # Phishing signal: Phishers increasingly use HTTPS; not sufficient alone, but absence is flag.
        "IsHTTPS": 1 if parsed.scheme == "https" else 0,
        
        # Have_At: binary flag for '@' symbol in the URL (classic phishing trick).
        # Range: 0-1; expected: 0 (legitimate URLs rarely use @)
        # Phishing signal: 'http://attacker.com@legitimate.com' exploits user misreading; browser treats text before @ as username.
        "Have_At": 1 if "@" in url_str else 0,
        
        # https_Domain: binary flag for 'http' text appearing in the netloc (not scheme).
        # Range: 0-1; expected: 0 (unusual and suspicious if found in domain name)
        # Phishing signal: Rare edge case where 'http' appears as part of hostname to confuse visual parsing.
        "https_Domain": 1 if "http" in netloc.lower() else 0,
        
        # TinyURL: binary flag for presence of URL shortening service domains.
        # Range: 0-1; expected: 0 for direct links. 1 = shortened (increased phishing risk due to hidden destination).
        # Phishing signal: Shorteners hide true URL; attacker sends shortened link to phishing site without user visibility.
        "TinyURL": 1 if _SHORTENING_RE.search(url_str) else 0,

        # ──────────────────────────────────────────────────────────────────────
        # URL DEPTH & COMPLEXITY (4 features)
        # ──────────────────────────────────────────────────────────────────────
        # URL_Length: total character count of the entire URL.
        # Range: 10-2048 typical; expected: 30-150 for legitimate. >200 is suspicious (obfuscation).
        # Phishing signal: Excessively long URLs used to hide true destination in truncated display.
        "URL_Length": url_len,
        
        # URL_Depth: number of directory levels in the path (segments separated by '/').
        # Range: 0-10 typical; expected: 0-3 for legitimate. >5 is suspicious.
        # Phishing signal: Deep nesting obscures true path; attacker redirects from legitimate path to phishing.
        "URL_Depth": len([x for x in path.split("/") if x]),
        
        # PathLength: character count of the URL path component (after domain, before query).
        # Range: 0-500 typical; expected: 0-100 for legitimate. >200 is suspicious.
        # Phishing signal: Padding with fake path mimics legitimate URL structure to deceive visual inspection.
        "PathLength": len(path),
        
        # QueryLength: character count of the query string (after '?').
        # Range: 0-500 typical; expected: 0-100 for legitimate. >200 is suspicious.
        # Phishing signal: Long query strings hide malicious parameters or redirect tokens.
        "QueryLength": len(query),

        # ──────────────────────────────────────────────────────────────────────
        # CHARACTER & SPECIAL CHARACTER DISTRIBUTION (10 features)
        # ──────────────────────────────────────────────────────────────────────
        # NoOfDots: count of '.' characters in the URL.
        # Range: 2-50 typical; expected: 2-8 for legitimate. >15 is suspicious (deep domain/path obfuscation).
        # Phishing signal: Excessive dots in domain or path indicate subdomain/path injection attacks.
        "NoOfDots": url_str.count("."),
        
        # NoOfHyphen: count of '-' characters in the URL.
        # Range: 0-20 typical; expected: 0-3 for legitimate. >5 is suspicious.
        # Phishing signal: Multiple hyphens confuse visual domain parsing; e.g., 'amaz-on-secure-login.com'.
        "NoOfHyphen": url_str.count("-"),
        
        # NoOfUnderscore: count of '_' characters in the URL.
        # Range: 0-10 typical; expected: 0-2 for legitimate. >3 is suspicious.
        # Phishing signal: Underscores often used in obfuscated parameter names or subdomain encoding.
        "NoOfUnderscore": url_str.count("_"),
        
        # NoOfSlash: count of '/' characters in the URL.
        # Range: 2-20 typical; expected: 2-8 for legitimate. >12 is suspicious.
        # Phishing signal: Excessive slash nesting used to hide true destination path.
        "NoOfSlash": url_str.count("/"),
        
        # NoOfQuestionMark: count of '?' characters (query string markers).
        # Range: 0-5 typical; expected: 0-2 for legitimate. >3 is suspicious (multiple query params suggest parameter tampering).
        # Phishing signal: Multiple query strings indicate hidden redirect parameters or encoded payloads.
        "NoOfQuestionMark": url_str.count("?"),
        
        # NoOfEquals: count of '=' characters (parameter assignment in query string).
        # Range: 0-20 typical; expected: 0-5 for legitimate. >10 is suspicious.
        # Phishing signal: Many parameters increase likelihood of malicious payload embedding.
        "NoOfEquals": url_str.count("="),
        
        # NoOfAmpersand: count of '&' characters (parameter separator).
        # Range: 0-20 typical; expected: 0-5 for legitimate. >10 is suspicious.
        # Phishing signal: Multiple parameters suggest complex redirect or encoding scheme.
        "NoOfAmpersand": url_str.count("&"),
        
        # NoOfPercent: count of '%' characters (URL encoding markers).
        # Range: 0-50 typical; expected: 0-5 for legitimate. >20 is suspicious (heavy obfuscation).
        # Phishing signal: Excessive URL encoding hides true destination or embedded payloads.
        "NoOfPercent": url_str.count("%"),
        
        # NoOfDigits: count of digit characters (0-9) in the entire URL.
        # Range: 0-100 typical; expected: 5-30 for legitimate. >50 is suspicious (random padding).
        # Phishing signal: Excessive digits suggest IP-like obfuscation or random parameter padding.
        "NoOfDigits": n_digits,
        
        # NoOfLetters: count of alphabetic characters (a-zA-Z) in the entire URL.
        # Range: 5-200 typical; expected: 20-100 for legitimate. >150 is unusual.
        # Phishing signal: Unusually high letter counts indicate mimicry or encoding schemes.
        "NoOfLetters": n_letters,

        # ──────────────────────────────────────────────────────────────────────
        # RATIOS & CHARACTER COMPOSITIONS (2 features)
        # ──────────────────────────────────────────────────────────────────────
        # LetterRatio: (count of letters) / (total URL length).
        # Range: 0.0-1.0; expected: 0.3-0.7 for legitimate. <0.2 or >0.8 is suspicious.
        # Phishing signal: Very low ratio indicates heavy encoding/encoding; very high suggests mimicry.
        "LetterRatio": n_letters / max(url_len, 1),
        
        # DigitRatio: (count of digits) / (total URL length).
        # Range: 0.0-1.0; expected: 0.05-0.3 for legitimate. >0.5 is suspicious (IP-like or random padding).
        # Phishing signal: High digit ratio indicates IP addresses or random parameter encoding.
        "DigitRatio": n_digits / max(url_len, 1),

        # ──────────────────────────────────────────────────────────────────────
        # PORT & KEYWORD INDICATORS (2 features)
        # ──────────────────────────────────────────────────────────────────────
        # HasPort: binary flag for explicit port number in netloc (e.g., :8080, :3128).
        # Range: 0-1; expected: 0 for standard HTTPS (443) or HTTP (80). 1 = non-standard port (suspicious).
        # Phishing signal: Non-standard ports bypass firewalls; attacker uses internal port to avoid detection.
        "HasPort": has_port,
        
        # SuspiciousWords: binary flag for presence of phishing-related keywords in URL.
        # Range: 0-1; keywords: login, signin, verify, update, secure, banking, paypal, confirm, etc.
        # Phishing signal: Presence of these keywords strongly indicates phishing (social engineering attempt).
        "SuspiciousWords": (
            1 if any(kw in url_lower for kw in _SUSPICIOUS_URL_KEYWORDS) else 0
        ),
        
        # Redirection: binary flag for embedded '//' after the scheme (URI confusion attack).
        # Range: 0-1; expected: 0 (legitimate URLs rarely have nested '//'). 1 = unusual and suspicious.
        # Phishing signal: 'https://attacker.com//legitimate.com' exploits parser confusion; early parsers see 'attacker', later ones see 'legitimate'.
        "Redirection": redirection,
        
        # SpecialCharCount: count of special characters (!@#$%^&*()[]{}|\:;"'<>,.?/~`)
        # Range: 0-50 typical; expected: 5-20 for legitimate. >30 is suspicious (encoding obfuscation).
        # Phishing signal: Excessive special chars indicate encoding, script injection, or obfuscation.
        "SpecialCharCount": sum(1 for c in url_str if c in special_chars),
    }


# ── HTML Feature Extraction ───────────────────────────────────────────────────


def extract_html_features(html_content: str) -> dict[str, int | float]:
    """Extract 40 DOM-based features from raw HTML.

    Returns ``HTML_DEFAULT_FEATURES`` (all zeros) on parse failure or empty input.
    
    **Feature Groups** (see docs/FEATURES.md for full documentation):
    - **Form Structure** (6 features): NoOfForms, NoOfInputs, NoOfPasswordFields, NoOfEmailFields, NoOfHiddenFields, NoOfExternalFormActions
      * Phishing Signal: Multiple forms, password fields, or hidden fields indicate credential theft attempts.
    - **Link Structure** (5 features): NoOfLinks, NoOfExternalLinks, NoOfInternalLinks, NoOfNullLinks, ExternalLinkRatio
      * Phishing Signal: High external link ratio and null links ('javascript:', '#') indicate redirect attacks.
    - **Script & Payload** (5 features): NoOfScripts, NoOfInlineScripts, NoOfIframes, HasPopup, HasObfuscation
      * Phishing Signal: Inline scripts and iframes allow malicious code injection; obfuscation hides attacks.
    - **Content Structure** (5 features): NoOfImages, NoOfMetaTags, HasTitle, NoOfStyleTags, NoOfExternalCSS
      * Phishing Signal: Minimal legitimate content + heavy external resources indicate low-effort phishing.
    - **Text & Metadata** (6 features): TitleLength, HTMLLength, TextLength, TextToHTMLRatio, HasFavicon, SuspiciousKeywordsCount
      * Phishing Signal: Low text ratio, missing favicon, or phishing keywords confirm phishing.
    - **Engagement Signals** (3 features): NoOfButtons, NoOfTextareas, NoOfEmailsInHTML, NoOfSocialLinks
      * Phishing Signal: Many buttons/textareas = credential harvest; social links = trust exploitation.
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

        # Link classification for external/internal/null ratio
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
            # ──────────────────────────────────────────────────────────────────────
            # FORM STRUCTURE INDICATORS (6 features) — Credential Harvesting Signals
            # ──────────────────────────────────────────────────────────────────────
            # NoOfForms: count of <form> elements in the HTML.
            # Range: 0-20 typical; expected: 0-2 for legitimate. >5 is suspicious (multiple credential harvest forms).
            # Phishing signal: Phishing pages often contain multiple forms to capture credentials under different labels.
            "NoOfForms": len(forms),
            
            # NoOfInputs: total count of <input> elements.
            # Range: 0-100 typical; expected: 5-30 for legitimate. >50 is suspicious (excessive input fields).
            # Phishing signal: More input fields increase chances of capturing user information.
            "NoOfInputs": len(inputs),
            
            # NoOfPasswordFields: count of <input type="password"> elements.
            # Range: 0-10 typical; expected: 0-2 for legitimate. >2 is suspicious (password field multiplicity).
            # Phishing signal: Multiple password fields suggest credential harvesting (fake login forms).
            "NoOfPasswordFields": sum(
                1 for i in inputs if i.get("type") == "password"
            ),
            
            # NoOfEmailFields: count of <input type="email"> or name containing 'email'.
            # Range: 0-10 typical; expected: 0-2 for legitimate. >3 is suspicious.
            # Phishing signal: Email field multiplicity indicates multi-stage credential harvesting.
            "NoOfEmailFields": sum(
                1
                for i in inputs
                if i.get("type") == "email"
                or "email" in str(i.get("name", "")).lower()
            ),
            
            # NoOfHiddenFields: count of <input type="hidden"> elements.
            # Range: 0-50 typical; expected: 0-5 for legitimate. >10 is suspicious (hidden tracking/redirect params).
            # Phishing signal: Hidden fields often carry redirect URLs, CSRF tokens for phishing infrastructure.
            "NoOfHiddenFields": sum(
                1 for i in inputs if i.get("type") == "hidden"
            ),
            
            # NoOfExternalFormActions: count of <form> with action URLs pointing to external domains.
            # Range: 0-5 typical; expected: 0-1 for legitimate. >1 is suspicious (credentials sent offsite).
            # Phishing signal: External form actions send stolen credentials to attacker's server.
            "NoOfExternalFormActions": sum(
                1
                for f in forms
                if str(f.get("action", "")).startswith(("http://", "https://"))
            ),

            # ──────────────────────────────────────────────────────────────────────
            # LINK STRUCTURE INDICATORS (5 features) — Redirect & Click-Jacking Signals
            # ──────────────────────────────────────────────────────────────────────
            # NoOfLinks: total count of <a> (hyperlink) elements.
            # Range: 0-100 typical; expected: 5-30 for legitimate. >50 is suspicious.
            # Phishing signal: High link count used to redirect, track, or distribute malware.
            "NoOfLinks": len(link_hrefs),
            
            # NoOfExternalLinks: count of <a> with href pointing to external domains (http:// or https://).
            # Range: 0-50 typical; expected: 1-10 for legitimate. >30 is suspicious (link farm/redirect attack).
            # Phishing signal: External links used to redirect victims to malware, additional phishing stages.
            "NoOfExternalLinks": external_links,
            
            # NoOfInternalLinks: count of <a> with href pointing to same-origin relative URLs.
            # Range: 0-30 typical; expected: 5-20 for legitimate. 0 for external-only phishing.
            # Phishing signal: Legitimate pages have internal links; phishing pages often have none.
            "NoOfInternalLinks": internal_links,
            
            # NoOfNullLinks: count of <a> with href='#', '', or 'javascript:' (clickable but non-navigating).
            # Range: 0-20 typical; expected: 0-2 for legitimate. >5 is suspicious (JavaScript execution traps).
            # Phishing signal: Null links often trigger malicious JavaScript (credential steal, drive-by download).
            "NoOfNullLinks": null_links,
            
            # ExternalLinkRatio: (NoOfExternalLinks) / max(NoOfLinks, 1).
            # Range: 0.0-1.0; expected: 0.1-0.4 for legitimate. >0.7 is suspicious (link farm).
            # Phishing signal: High ratio indicates redirection attacks; legitimate pages mix internal + external.
            "ExternalLinkRatio": external_links / max(len(link_hrefs), 1),

            # ──────────────────────────────────────────────────────────────────────
            # SCRIPT & DYNAMIC BEHAVIOR INDICATORS (5 features) — Malware Injection Signals
            # ──────────────────────────────────────────────────────────────────────
            # NoOfScripts: total count of <script> elements.
            # Range: 0-50 typical; expected: 2-10 for legitimate. >20 is suspicious (code injection).
            # Phishing signal: Multiple scripts allow credential theft, tracking, drive-by download injection.
            "NoOfScripts": len(scripts),
            
            # NoOfInlineScripts: count of <script> elements with inline code (text content, not src attribute).
            # Range: 0-20 typical; expected: 1-5 for legitimate. >10 is suspicious (obfuscated malware).
            # Phishing signal: Inline scripts are harder to detect; used to hide credential theft logic.
            "NoOfInlineScripts": sum(
                1 for s in scripts if s.string and s.string.strip()
            ),
            
            # NoOfIframes: count of <iframe> elements.
            # Range: 0-10 typical; expected: 0-2 for legitimate. >3 is suspicious (hidden iframe injection).
            # Phishing signal: Iframes embed malicious content, tracking pixels, or phishing forms in separate origin.
            "NoOfIframes": tag_counter["iframe"],
            
            # HasPopup: binary flag for presence of 'window.open' or 'alert(' JavaScript calls.
            # Range: 0-1; expected: 0 (alerts are dev-time but shouldn't appear in production). 1 = suspicious.
            # Phishing signal: Popups used to display fake security warnings or redirect to malware.
            "HasPopup": (
                1
                if "window.open" in html_lower or "alert(" in html_lower
                else 0
            ),
            
            # HasObfuscation: binary flag for presence of CSS display:none or visibility:hidden.
            # Range: 0-1; expected: 0 (legitimate pages rarely hide large content sections). 1 = suspicious.
            # Phishing signal: Hidden content used to hide malicious elements, SEO spam, or cloaking attacks.
            "HasObfuscation": 1 if _RE_DISPLAY_NONE.search(html_content) else 0,

            # ──────────────────────────────────────────────────────────────────────
            # CONTENT & STRUCTURE INDICATORS (5 features) — Low-Effort Phishing Signals
            # ──────────────────────────────────────────────────────────────────────
            # NoOfImages: count of <img> elements.
            # Range: 0-50 typical; expected: 5-20 for legitimate. <2 is suspicious (low-effort phishing).
            # Phishing signal: Legitimate pages have images for branding/content; phishing often skips images.
            "NoOfImages": tag_counter["img"],
            
            # NoOfMetaTags: count of <meta> elements.
            # Range: 5-20 typical; expected: 10-15 for legitimate. <5 is suspicious (missing SEO/metadata).
            # Phishing signal: Minimal metadata indicates hastily assembled or cloned page.
            "NoOfMetaTags": tag_counter["meta"],
            
            # NoOfStyleTags: count of <style> elements (inline CSS).
            # Range: 0-10 typical; expected: 1-3 for legitimate. >5 is suspicious (code obfuscation via CSS).
            # Phishing signal: Multiple inline styles indicate inline malicious CSS or heavy obfuscation.
            "NoOfStyleTags": tag_counter["style"],
            
            # NoOfExternalCSS: count of <link rel="stylesheet"> elements (external stylesheets).
            # Range: 0-10 typical; expected: 1-3 for legitimate. >5 is suspicious.
            # Phishing signal: Excessive external CSS downloads increase attack surface; loaded from attacker's server.
            "NoOfExternalCSS": sum(
                1 for lt in link_tags if "stylesheet" in _rel_str(lt)
            ),
            
            # HasTitle: binary flag for presence of <title> element.
            # Range: 0-1; expected: 1 (all legitimate pages have title). 0 = suspicious.
            # Phishing signal: Missing title indicates minimal page setup; hastily crafted phishing.
            "HasTitle": 1 if title_text else 0,

            # ──────────────────────────────────────────────────────────────────────
            # TEXT & CONTENT QUALITY INDICATORS (6 features) — Page Legitimacy Signals
            # ──────────────────────────────────────────────────────────────────────
            # TitleLength: character count of the <title> element's text.
            # Range: 0-100 typical; expected: 10-60 for legitimate. >80 is suspicious (keyword stuffing).
            # Phishing signal: Very short or very long titles indicate low-effort or SEO spam phishing.
            "TitleLength": len(title_text) if title_text else 0,
            
            # HTMLLength: total character count of the raw HTML source.
            # Range: 1000-1000000 typical; expected: 10000-500000 for legitimate. <5000 is suspicious (minimal page).
            # Phishing signal: Extremely small HTML indicates low-effort phishing (stripped-down clone).
            "HTMLLength": len(html_content),
            
            # TextLength: character count of visible text content (HTML tags removed).
            # Range: 100-100000 typical; expected: 1000-50000 for legitimate. <500 is suspicious (minimal text).
            # Phishing signal: Minimal visible text indicates hastily assembled phishing page.
            "TextLength": len(text_approx),
            
            # TextToHTMLRatio: (TextLength) / max(HTMLLength, 1).
            # Range: 0.0-1.0; expected: 0.1-0.5 for legitimate. <0.05 is suspicious (heavy markup, minimal text).
            # Phishing signal: Very low ratio indicates overly complex HTML for minimal content (obfuscation).
            "TextToHTMLRatio": len(text_approx) / max(len(html_content), 1),
            
            # HasFavicon: binary flag for presence of <link rel="icon"> or similar favicon link.
            # Range: 0-1; expected: 1 for legitimate (branded sites include favicon). 0 is slightly suspicious.
            # Phishing signal: Missing favicon indicates low effort; legitimate sites invest in branding.
            "HasFavicon": 1 if has_favicon else 0,
            
            # SuspiciousKeywordsCount: count of occurrences of phishing-related keywords.
            # Keywords: verify, account, suspend, login, signin, update, confirm, secure, banking, urgent, etc.
            # Range: 0-20 typical; expected: 0-2 for legitimate. >5 is suspicious (keyword spam).
            # Phishing signal: Multiple phishing keywords indicate intentional impersonation attempt.
            "SuspiciousKeywordsCount": sum(
                1 for kw in _SUSPICIOUS_HTML_KEYWORDS if kw in html_lower
            ),

            # ──────────────────────────────────────────────────────────────────────
            # ENGAGEMENT & INTERACTIVE ELEMENTS (3 features) — Social Engineering Signals
            # ──────────────────────────────────────────────────────────────────────
            # NoOfButtons: count of <button> elements.
            # Range: 0-50 typical; expected: 1-10 for legitimate. >20 is suspicious (excessive CTAs).
            # Phishing signal: Multiple prominent buttons encourage hasty clicking (social engineering).
            "NoOfButtons": tag_counter["button"],
            
            # NoOfTextareas: count of <textarea> elements.
            # Range: 0-10 typical; expected: 0-2 for legitimate. >3 is suspicious (multi-field text harvest).
            # Phishing signal: Multiple textareas used to capture long-form sensitive data (credit cards, SSN, etc.).
            "NoOfTextareas": tag_counter["textarea"],
            
            # NoOfSocialLinks: count of links pointing to social media platforms (facebook, twitter, instagram, etc.).
            # Range: 0-10 typical; expected: 0-3 for legitimate. >5 is suspicious (fake social widgets).
            # Phishing signal: Fake social links build false trust or redirect to attacker's social presence.
            "NoOfSocialLinks": sum(
                1
                for h in link_hrefs
                if any(s in str(h).lower() for s in _SOCIAL_KEYWORDS)
            ),
            
            # NoOfEmailsInHTML: count of email addresses (regex match [a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}).
            # Range: 0-50 typical; expected: 0-2 for legitimate. >5 is suspicious (email harvesting or spam).
            # Phishing signal: Multiple hardcoded emails indicate attacker's contact info or spam collection.
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
    return stripped if stripped.startswith(("http://", "https://")) else f"https://{stripped}"


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
