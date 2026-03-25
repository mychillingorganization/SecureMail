# Web Agent Feature Reference

## Overview

The Web Agent uses **70 features** extracted from URLs and HTML content to train and run an XGBoost phishing detection model. This document describes all features, their semantic meaning, and expected value ranges.

**Model Architecture:**
- **Input:** 70 numeric features (normalized 0–1 range)
- **Output:** Risk score (probability of phishing, 0–1) + confidence + label
- **Framework:** XGBoost Booster
- **Inference latency:** <10ms per URL

---

## Feature Categories

### URL-Based Features (30 total)

Extracted using static parsing of the URL string. No network I/O required. All features numeric (int or float).

| Feature Name | Type | Range | Semantic Meaning | Example Phishing Signal |
|---|---|---|---|---|
| `DomainPartCount` | int | 1–6 | Number of `.` separated parts in domain | brandimilar.com (4 parts) vs. bank.com (2 parts) |
| `SubdomainCount` | int | 0–5 | Number of subdomains (parts before primary domain) | `sub1.sub2.example.com` = 2 subdomains |
| `URLLength` | int | 8–2048 | Total length of the URL string | Suspiciously long URLs (>200 chars) often phishing |
| `PathLength` | int | 0–500 | Character count in URL path | Obfuscated paths with many parameters |
| `QueryLength` | int | 0–500 | Character count in query string | Phishing redirects encoded in query params |
| `HaveDash` | binary | 0–1 | Contains `-` in domain | `secure-paypa1.com` mimics PayPal |
| `HaveAtSign` | binary | 0–1 | Contains `@` in domain (rare, suspicious) | User email in URL: `http://user@attacker.com/` |
| `HaveHyphen` | binary | 0–1 | Contains `—` (em-dash, Unicode variant) | Unicode tricks to bypass filters |
| `HavePercent` | binary | 0–1 | Contains `%` encoding | `http://example.com/%2e%2e/` (directory traversal) |
| `HaveQMark` | binary | 0–1 | Contains `?` (query separator) | Long query strings with encoded content |
| `HaveSemicolon` | binary | 0–1 | Contains `;` | URL encoding tricks |
| `HaveUnderScore` | binary | 0–1 | Contains `_` in domain | `secure_paypal.com` (mimic) |
| `HaveChars` | int | 0–300 | Count of alphabetic characters | Balance between readability and obfuscation |
| `HaveDigits` | int | 0–100 | Count of numeric characters | IP-based URLs (all digits): `192.168.1.1` |
| `CharacterToDigitRatio` | float | 0.0–1.0 | Proportion of letters to numbers | Low ratio ~= suspicious encoding |
| `HasIPAddress` | binary | 0–1 | Hostname is a raw IP address (e.g., `192.168.1.1`) | IP-based URLs are ~50x more likely to be phishing |
| `HasRedirection` | binary | 0–1 | `//` appears after position 7 (beyond scheme) | `http://safe.com//attacker.com/` |
| `HasPort` | binary | 0–1 | Custom port specified in URL | `example.com:8888` (unusual ports) |
| `HasProtocol` | binary | 0–1 | Explicitly specifies `http://` or `https://` | — |
| `ContainsAt` | binary | 0–1 | `@` character present in URL (HTTP basic auth) | `http://admin@attacker.com/` |
| `DomainNameLength` | int | 2–100 | Character count in domain part only | Abnormally long domains |
| `SubDomainNameLength` | int | 0–100 | Character count in first subdomain | — |
| `HasDoubleSlash` | binary | 0–1 | Contains `//` anywhere after protocol | — |
| `IsShortening` | binary | 0–1 | URL matches known URL shortener patterns (bit.ly, goo.gl, etc.) | Shorteners hide destination; phishers abuse them |
| `SymbolCount` | int | 0–50 | Count of special characters (!@#$%^&*) | Obfuscation via symbols |
| `SuspiciousKeywordInURL` | binary | 0–1 | URL contains phishing keywords (login, verify, update, secure, banking, etc.) | `http://verify-account.suspicious.com` |
| `SuspiciousKeywordCount` | int | 0–5 | Number of phishing keywords in URL | Multiple keywords = high suspicion |
| `ProtocolType` | int | 0–2 | Encode of protocol (0=http, 1=https, 2=other) | HTTPS is generally safer, but not absolute |
| `TLDLength` | int | 2–20 | Character count in Top-Level Domain (.com, .co.uk, etc.) | Unusually long TLDs are rare |
| `HasFileExtension` | binary | 0–1 | URL ends with file extension (.html, .php, etc.) | Phishers sometimes serve from static files |

---

### HTML-Based Features (40 total)

Extracted from fetched HTML content. Uses DOM parsing and regex. If page cannot be fetched, default values (0) are used.

#### Form & Input Analysis (10 features)
| Feature Name | Type | Range | Semantic Meaning | Phishing Signal |
|---|---|---|---|---|
| `NoOfForms` | int | 0–10 | Count of `<form>` tags in page | Legitimate pages rarely have many forms; phishing pages often have login forms |
| `NoOfInputs` | int | 0–100 | Total `<input>` elements | Excessive inputs for data harvesting |
| `NoOfPasswordFields` | int | 0–10 | Count of `<input type="password">` | Phishing pages mimic login flows |
| `NoOfEmailFields` | int | 0–10 | Count of `<input type="email">` | — |
| `NoOfHiddenFields` | int | 0–50 | Count of `<input type="hidden">` | Hidden fields for tracking or redirection |
| `NoOfButtons` | int | 0–20 | Count of `<button>` or submit widgets | Phishing forms optimize for click-through |
| `NoOfTextareas` | int | 0–10 | Count of `<textarea>` elements | — |
| `ExternalFormActions` | int | 0–10 | Count of `<form action="http://external-domain">` | Forms sending to attacker server |
| `FormActionToExternalDomain` | binary | 0–1 | At least one form submits to different domain | `action="http://attacker.com/phish"` |
| `HoveredButtonURI` | binary | 0–1 | Button onclick contains suspicious URI | — |

#### Link & Navigation Analysis (6 features)
| Feature Name | Type | Range | Semantic Meaning | Phishing Signal |
|---|---|---|---|---|
| `NoOfLinks` | int | 0–100 | Total hyperlinks on page | — |
| `NoOfExternalLinks` | int | 0–100 | Links pointing to different domains | Phishing pages link to attacker infrastructure |
| `NoOfInternalLinks` | int | 0–100 | Links to same domain | Legitimate pages have internal navigation |
| `NoOfNullLinks` | int | 0–50 | Links with `href="#"` or `href="javascript:void(0)"` | Phishing pages use null links to avoid navigation |
| `ExternalLinkRatio` | float | 0.0–1.0 | Proportion of external vs. total links | High ratio = suspicious |
| `LinkToExternalDomain` | binary | 0–1 | At least one link to different domain | — |

#### Script & Style Analysis (6 features)
| Feature Name | Type | Range | Semantic Meaning | Phishing Signal |
|---|---|---|---|---|
| `NoOfScripts` | int | 0–50 | Count of `<script>` tags | Malicious scripts, redirects, or tracking |
| `NoOfInlineScripts` | int | 0–50 | Count of inline `<script>` blocks (not external files) | Inline scripts for obfuscation |
| `NoOfIframes` | int | 0–20 | Count of `<iframe>` tags | Iframes for loading malicious content or external phishing forms |
| `NoOfStyleTags` | int | 0–10 | Count of `<style>` tags | — |
| `NoOfExternalCSS` | int | 0–10 | External CSS file references | — |
| `HasObfuscation` | binary | 0–1 | Detects common obfuscation patterns (e.g., `display:none`, hidden elements) | Hidden elements, forms, or text |

#### Content & Structure Analysis (10 features)
| Feature Name | Type | Range | Semantic Meaning | Phishing Signal |
|---|---|---|---|---|
| `NoOfMetaTags` | int | 0–50 | Count of `<meta>` tags | Legitimate pages have proper meta tags |
| `HasTitle` | binary | 0–1 | Page has a `<title>` tag | Phishing pages sometimes omit title |
| `TitleLength` | int | 0–200 | Character count in page title |— |
| `SuspiciousKeywordsInHTML` | binary | 0–1 | HTML body contains phishing keywords (verify, confirm, update, urgent, etc.) | "Your account has been suspended. Click here to verify." |
| `SuspiciousKeywordCount` | int | 0–20 | Total count of phishing keywords in HTML | Multiple keywords = high suspicion |
| `NoOfImages` | int | 0–500 | Count of `<img>` tags | — |
| `HTMLLength` | int | 0–100000 | Total HTML source code size in characters | Unusually large or small pages |
| `TextLength` | int | 0–50000 | Total plaintext content (after tag removal) | — |
| `TextToHTMLRatio` | float | 0.0–1.0 | Proportion of text to total HTML | Low ratio = mostly markup, no content. High = content-heavy. |
| `HasPopup` | binary | 0–1 | Detects popup scripts or alerts | Phishing pages often trigger popups for credibility or distraction |

#### Branding & Trust Signals (6 features)
| Feature Name | Type | Range | Semantic Meaning | Phishing Signal |
|---|---|---|---|---|
| `HasFavicon` | binary | 0–1 | Page serves a favicon (site icon) | Legitimate pages have favicons; phishing pages often miss them |
| `BrandLogoDetected` | binary | 0–1 | Image analysis detects recognizable brand logos (perceptual hashing) | Phishing pages copy brand logos to build false trust |
| `NoOfSocialLinks` | int | 0–20 | Links to Facebook, Twitter, Instagram, etc. | Phishing pages sometimes link to brand social media |
| `SocialMediaIconsPresent` | binary | 0–1 | Social media icon images detected | — |
| `HasLinkedinLink` | binary | 0–1 | Explicit LinkedIn profile link | Professional pages use LinkedIn; phishing less commonly |
| `NoOfEmailsInHTML` | int | 0–100 | Email addresses found in HTML content | Phishing pages sometimes embed contact emails for legitimacy |

#### Advanced Signals (2 features)
| Feature Name | Type | Range | Semantic Meaning | Phishing Signal |
|---|---|---|---|---|
| `DOMComplexity` | int | 0–1000 | Count of deep DOM nesting or complex selectors | Overly complex DOM could indicate packed/obfuscated JavaScript |
| `ResourceLoadTime` | float | 0.0–5000 | Simulated time to load page resources (ms) | Slow loads could indicate malicious script injection |

---

## Feature Extraction Defaults

When an HTML page cannot be fetched (network error, timeout, 4xx/5xx), the feature extractor returns these defaults:

```python
HTML_DEFAULT_FEATURES = {
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
```

---

## Model Training & Assumptions

**Dataset:** Trained on phishing corpus (TBD: provide dataset source/size)

**Feature Normalization:** Features are not normalized before input to XGBoost (XGBoost handles scaling).

**Class Balance:** (TBD: specify phishing vs. benign ratio in training set)

**Feature Importance:** (TBD: provide top 10 features ranked by XGBoost gain)

**Calibration:** Model outputs raw probabilities; confidence is computed as `|score - 0.5| * 2` to capture uncertainty.

---

## Usage in SecureMail Pipeline

1. **URL features** are extracted once per URL.
2. If HTML context available, **HTML features** are extracted from fetched content.
3. All 70 features are merged into a single dict.
4. Dict is validated (missing features default to 0, NaN/inf clamped to 0).
5. Feature vector is padded/reordered to match model's expected input shape.
6. XGBoost inference produces risk_score ∈ [0, 1].
7. Final risk clamped to [0, 1] and mapped to verdict (SAFE/SUSPICIOUS/MALICIOUS).

---

## Recommendations for Future Improvement

1. **Add feature versioning:** Track feature schema version in model metadata to ensure compatibility.
2. **Add feature importance logging:** Log top features driving each decision for explainability.
3. **Add feature monitoring:** Track feature distribution over time (data drift detection).
4. **Add time-based features:** Account for domain age (whois).
5. **Add DNS reputation:** Integrate with threat feeds (VirusTotal, Google Safe Browsing).

---

**Document generated:** 2026-03-22  
**Model version:** 1.1.0  
**XGBoost version:** 1.7.x

