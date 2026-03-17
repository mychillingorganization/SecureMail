"""
Phishing URL Detection Console Application
Uses the trained XGBoost model to detect phishing URLs in real-time.
"""
import pandas as pd
import numpy as np
import xgboost as xgb
import sys
import re
import os
import requests
from collections import Counter
from urllib.parse import urlparse
import ipaddress
from bs4 import BeautifulSoup
from colorama import init, Fore, Style

# Initialize colorama for colored console output
init(autoreset=True)


# ==================== CONFIGURATION ====================
MODEL_FILE = "xgboost_phishing_model.json"
FEATURE_IMPORTANCE_FILE = "feature_importance.csv"
WHITELIST_FILE = "whitelist.txt"
BLACKLIST_FILE = "blacklist.txt"
HTML_REQUEST_TIMEOUT = 5
BLACKLIST_FETCH_TIMEOUT = 8
BLACKLIST_SOURCE_URLS = [
    "https://openphish.com/feed.txt"
]

# URL Shortening Services
SHORTENING_SERVICES = r"bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|" \
                      r"yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|" \
                      r"short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|" \
                      r"doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|lnkd\.in|db\.tt|" \
                      r"qr\.ae|adf\.ly|bitly\.com|cur\.lv|ow\.ly|ity\.im|q\.gs|po\.st|bc\.vc|twitthis\.com|" \
                      r"u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|prettylinkpro\.com|scrnch\.me|" \
                      r"filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|tr\.im|link\.zip\.net"

# Suspicious Keywords
SUSPICIOUS_KEYWORDS = ['login', 'signin', 'account', 'verify', 'update', 'secure', 'banking',
                       'paypal', 'ebay', 'amazon', 'confirm', 'suspend', 'verify', 'luck',
                       'bonus', 'free', 'click']
SUSPICIOUS_HTML_KEYWORDS = ('verify', 'account', 'suspend', 'login', 'signin', 'update',
                            'confirm', 'secure', 'banking', 'click here', 'urgent',
                            'expired', 'verify your account', 'update your information')
SOCIAL_KEYWORDS = ('facebook', 'twitter', 'instagram', 'linkedin', 'youtube')

RE_DISPLAY_NONE = re.compile(r'display\s*:\s*none|visibility\s*:\s*hidden', re.IGNORECASE)
RE_EMAIL = re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}')
RE_TAGS = re.compile(r'<[^>]+>')

URL_FEATURES = [
    'DomainPartCount',
    'Have_IP', 'Have_At', 'URL_Length', 'URL_Depth', 'Redirection',
    'https_Domain', 'TinyURL', 'Prefix_Suffix', 'IsHTTPS', 'NoOfDots',
    'NoOfHyphen', 'NoOfUnderscore', 'NoOfSlash', 'NoOfQuestionMark',
    'NoOfEquals', 'NoOfAmpersand', 'NoOfPercent', 'NoOfDigits',
    'NoOfLetters', 'LetterRatio', 'DigitRatio', 'HasSubdomain',
    'SubdomainCount', 'DomainLength', 'PathLength', 'QueryLength',
    'HasPort', 'SuspiciousWords', 'SpecialCharCount'
]

HTML_DEFAULT_FEATURES = {
    'NoOfForms': 0, 'NoOfInputs': 0, 'NoOfPasswordFields': 0, 'NoOfEmailFields': 0,
    'NoOfHiddenFields': 0, 'NoOfLinks': 0, 'NoOfExternalLinks': 0, 'NoOfInternalLinks': 0,
    'NoOfNullLinks': 0, 'ExternalLinkRatio': 0, 'NoOfExternalFormActions': 0,
    'NoOfScripts': 0, 'NoOfInlineScripts': 0, 'NoOfIframes': 0, 'NoOfImages': 0,
    'NoOfMetaTags': 0, 'HasTitle': 0, 'TitleLength': 0, 'SuspiciousKeywordsCount': 0,
    'NoOfButtons': 0, 'NoOfTextareas': 0, 'NoOfStyleTags': 0, 'NoOfExternalCSS': 0,
    'HasObfuscation': 0, 'HasPopup': 0, 'HTMLLength': 0, 'TextLength': 0,
    'TextToHTMLRatio': 0, 'HasFavicon': 0, 'NoOfSocialLinks': 0, 'NoOfEmailsInHTML': 0
}

# Load whitelist of known legitimate domains
def load_whitelist(filepath):
    """Load legitimate domains from whitelist file."""
    domains = set()
    try:
        with open(filepath, 'r') as f:
            for line in f:
                line = line.strip()
                # Skip empty lines and comments
                if line and not line.startswith('#'):
                    domains.add(line.lower())
    except FileNotFoundError:
        print(f"{Fore.YELLOW}⚠ Warning: Whitelist file '{filepath}' not found. Using empty whitelist.{Style.RESET_ALL}")
    return domains

LEGITIMATE_DOMAINS = load_whitelist(WHITELIST_FILE)


def _normalize_blacklist_entry(raw_entry):
    """Normalize a blacklist entry into (kind, value)."""
    entry = raw_entry.strip().lower()
    if not entry or entry.startswith('#'):
        return None

    if entry.startswith(('http://', 'https://')):
        return ('url', entry)

    try:
        parsed = urlparse(entry if '://' in entry else f"http://{entry}")
    except ValueError:
        return None
    domain = parsed.netloc or parsed.path
    domain = domain.strip().lower()

    if domain.startswith('www.'):
        domain = domain[4:]
    if ':' in domain:
        domain = domain.split(':')[0]

    if domain:
        return ('domain', domain)

    return None


def _is_parseable_blacklist_line(raw_entry):
    """Return True for non-empty, non-comment lines intended for parsing."""
    line = raw_entry.strip()
    return bool(line) and not line.startswith('#')


def load_blacklist_file(filepath):
    """Load local blacklist entries from disk."""
    blacklisted_domains = set()
    blacklisted_urls = set()
    malformed_lines = 0

    if not os.path.exists(filepath):
        return blacklisted_domains, blacklisted_urls, malformed_lines

    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as file_handle:
            for line in file_handle:
                should_parse = _is_parseable_blacklist_line(line)
                normalized = _normalize_blacklist_entry(line)
                if not normalized:
                    if should_parse:
                        malformed_lines += 1
                    continue
                entry_kind, value = normalized
                if entry_kind == 'url':
                    blacklisted_urls.add(value)
                else:
                    blacklisted_domains.add(value)
    except Exception as e:
        print(f"{Fore.YELLOW}⚠ Warning: Could not read blacklist file '{filepath}': {e}{Style.RESET_ALL}")

    return blacklisted_domains, blacklisted_urls, malformed_lines


def fetch_blacklist_from_sources(urls, timeout=BLACKLIST_FETCH_TIMEOUT):
    """Fetch blacklist entries from remote text feeds."""
    fetched_domains = set()
    fetched_urls = set()
    malformed_lines = 0

    for source_url in urls:
        try:
            response = requests.get(source_url, timeout=timeout)
            response.raise_for_status()

            for line in response.text.splitlines():
                should_parse = _is_parseable_blacklist_line(line)
                normalized = _normalize_blacklist_entry(line)
                if not normalized:
                    if should_parse:
                        malformed_lines += 1
                    continue
                entry_kind, value = normalized
                if entry_kind == 'url':
                    fetched_urls.add(value)
                else:
                    fetched_domains.add(value)

            print(
                f"{Fore.CYAN}ℹ Fetched blacklist source: {source_url} "
                f"({len(fetched_domains) + len(fetched_urls)} cumulative entries){Style.RESET_ALL}"
            )
        except Exception as e:
            print(f"{Fore.YELLOW}⚠ Warning: Could not fetch blacklist source '{source_url}': {e}{Style.RESET_ALL}")

    return fetched_domains, fetched_urls, malformed_lines


def load_blacklist(local_file, source_urls):
    """Combine local and remote blacklist entries."""
    file_domains, file_urls, malformed_file_lines = load_blacklist_file(local_file)
    remote_domains, remote_urls, malformed_remote_lines = fetch_blacklist_from_sources(source_urls)

    blacklisted_domains = file_domains.union(remote_domains)
    blacklisted_urls = file_urls.union(remote_urls)
    malformed_total = malformed_file_lines + malformed_remote_lines

    print(
        f"{Fore.CYAN}ℹ Blacklist ready: {len(blacklisted_domains)} domains, "
        f"{len(blacklisted_urls)} URLs{Style.RESET_ALL}"
    )
    if malformed_total > 0:
        print(
            f"{Fore.YELLOW}⚠ Debug: skipped {malformed_total} malformed blacklist lines "
            f"(local={malformed_file_lines}, remote={malformed_remote_lines}){Style.RESET_ALL}"
        )
    return blacklisted_domains, blacklisted_urls


BLACKLISTED_DOMAINS, BLACKLISTED_URLS = load_blacklist(BLACKLIST_FILE, BLACKLIST_SOURCE_URLS)



# ==================== FUNCTIONS ====================
def extract_domain(url):
    """Extract the base domain from a URL."""
    from urllib.parse import urlparse
    try:
        parsed = urlparse(url)
        domain = parsed.netloc or parsed.path
        
        # Remove 'www.' prefix if present
        if domain.startswith('www.'):
            domain = domain[4:]
        
        # Remove port if present
        if ':' in domain:
            domain = domain.split(':')[0]
        
        return domain.lower()
    except:
        return None


def is_whitelisted_domain(url):
    """Check if the URL's domain is in the legitimate whitelist."""
    domain = extract_domain(url)
    if not domain:
        return False
    
    # Check exact match
    if domain in LEGITIMATE_DOMAINS:
        return True
    
    # Check if it's a subdomain of a whitelisted domain
    # e.g., 'mail.google.com' should match 'google.com'
    for trusted_domain in LEGITIMATE_DOMAINS:
        if domain.endswith('.' + trusted_domain):
            return True
    
    return False


def is_blacklisted(url):
    """Check if URL or its domain is in blacklist entries."""
    normalized_url = normalize_url_for_fetch(url).lower()
    if normalized_url in BLACKLISTED_URLS:
        return True

    domain = extract_domain(normalized_url)
    if not domain:
        return False

    if domain in BLACKLISTED_DOMAINS:
        return True

    for blocked_domain in BLACKLISTED_DOMAINS:
        if domain.endswith('.' + blocked_domain):
            return True

    return False


def load_model(model_path):
    """Load the trained XGBoost model."""
    try:
        model = xgb.XGBClassifier()
        model.load_model(model_path)
        print(f"{Fore.GREEN}✓ Model loaded successfully from {model_path}{Style.RESET_ALL}\n")
        return model
    except Exception as e:
        print(f"{Fore.RED}✗ Error loading model: {e}{Style.RESET_ALL}")
        sys.exit(1)


def load_expected_features(model, feature_importance_path):
    """Resolve expected feature order from model metadata or feature importance fallback."""
    try:
        booster_names = model.get_booster().feature_names
        if booster_names:
            print(f"{Fore.CYAN}ℹ Using {len(booster_names)} model feature names from booster metadata{Style.RESET_ALL}")
            return booster_names
    except Exception:
        pass

    if os.path.exists(feature_importance_path):
        try:
            importance_df = pd.read_csv(feature_importance_path)
            if 'feature' in importance_df.columns:
                expected = importance_df['feature'].dropna().astype(str).tolist()
                if expected:
                    print(f"{Fore.CYAN}ℹ Using {len(expected)} feature names from {feature_importance_path}{Style.RESET_ALL}")
                    return expected
        except Exception as e:
            print(f"{Fore.YELLOW}⚠ Could not read feature importance file: {e}{Style.RESET_ALL}")

    fallback = URL_FEATURES + list(HTML_DEFAULT_FEATURES.keys())
    print(f"{Fore.YELLOW}⚠ Falling back to built-in feature schema ({len(fallback)} features){Style.RESET_ALL}")
    return fallback


def normalize_url_for_fetch(url):
    """Ensure URL has a scheme for HTTP requests."""
    if url.startswith(('http://', 'https://')):
        return url
    return f"http://{url}"


def fetch_html_content(url, timeout=HTML_REQUEST_TIMEOUT):
    """Fetch HTML content for optional DOM-based feature extraction."""
    fetch_url = normalize_url_for_fetch(url)
    headers = {
        'User-Agent': 'Mozilla/5.0 (compatible; PhishingDetector/1.0)'
    }

    try:
        response = requests.get(
            fetch_url,
            timeout=timeout,
            allow_redirects=True,
            headers=headers
        )
        response.raise_for_status()
        content_type = response.headers.get('Content-Type', '').lower()
        if 'text/html' not in content_type and content_type != '':
            raise ValueError(f"Unsupported content type for HTML parsing: {content_type}")
        return response.text
    except Exception as e:
        raise RuntimeError(f"Failed to fetch HTML from '{fetch_url}': {e}") from e


def extract_html_features_from_content(html_content):
    """Extract HTML DOM features from fetched page content."""
    if not html_content:
        return dict(HTML_DEFAULT_FEATURES)

    features = dict(HTML_DEFAULT_FEATURES)

    try:
        soup = BeautifulSoup(html_content, 'html.parser')
        tag_counter = Counter()
        forms, inputs, link_hrefs, scripts, link_tags = [], [], [], [], []
        title_text = None

        for tag in soup.find_all(True):
            name = tag.name
            tag_counter[name] += 1
            if name == 'form':
                forms.append(tag)
            elif name == 'input':
                inputs.append(tag)
            elif name == 'a':
                href = tag.get('href')
                if href is not None:
                    link_hrefs.append(href)
            elif name == 'script':
                scripts.append(tag)
            elif name == 'link':
                link_tags.append(tag)
            elif name == 'title' and title_text is None:
                title_text = tag.string

        features['NoOfForms'] = len(forms)
        features['NoOfInputs'] = len(inputs)
        features['NoOfPasswordFields'] = sum(1 for i in inputs if i.get('type') == 'password')
        features['NoOfEmailFields'] = sum(
            1 for i in inputs
            if i.get('type') == 'email' or 'email' in str(i.get('name', '')).lower()
        )
        features['NoOfHiddenFields'] = sum(1 for i in inputs if i.get('type') == 'hidden')

        features['NoOfLinks'] = len(link_hrefs)
        external_links = sum(1 for h in link_hrefs if str(h).startswith(('http://', 'https://')))
        null_links = sum(1 for h in link_hrefs if str(h).startswith('#') or str(h) == '' or str(h).startswith('javascript:'))
        internal_links = len(link_hrefs) - external_links - null_links
        features['NoOfExternalLinks'] = external_links
        features['NoOfInternalLinks'] = internal_links
        features['NoOfNullLinks'] = null_links
        features['ExternalLinkRatio'] = external_links / max(len(link_hrefs), 1)

        features['NoOfExternalFormActions'] = sum(
            1 for form in forms
            if str(form.get('action', '')).startswith(('http://', 'https://'))
        )

        features['NoOfScripts'] = len(scripts)
        features['NoOfInlineScripts'] = sum(1 for s in scripts if s.string and s.string.strip())

        features['NoOfIframes'] = tag_counter['iframe']
        features['NoOfImages'] = tag_counter['img']
        features['NoOfMetaTags'] = tag_counter['meta']
        features['NoOfButtons'] = tag_counter['button']
        features['NoOfTextareas'] = tag_counter['textarea']

        features['HasTitle'] = 1 if title_text else 0
        features['TitleLength'] = len(title_text) if title_text else 0

        html_lower = html_content.lower()
        features['SuspiciousKeywordsCount'] = sum(1 for kw in SUSPICIOUS_HTML_KEYWORDS if kw in html_lower)

        features['NoOfStyleTags'] = tag_counter['style']
        features['NoOfExternalCSS'] = sum(
            1 for lt in link_tags
            if 'stylesheet' in (
                ' '.join(lt.get('rel', [])) if isinstance(lt.get('rel'), list)
                else str(lt.get('rel', ''))
            )
        )

        features['HasObfuscation'] = 1 if RE_DISPLAY_NONE.search(html_content) else 0
        features['HasPopup'] = 1 if 'window.open' in html_lower or 'alert(' in html_lower else 0

        text_approx = RE_TAGS.sub(' ', html_lower)
        features['HTMLLength'] = len(html_content)
        features['TextLength'] = len(text_approx)
        features['TextToHTMLRatio'] = len(text_approx) / max(len(html_content), 1)

        has_favicon = False
        for lt in link_tags:
            rel = lt.get('rel', [])
            rel_str = (' '.join(rel) if isinstance(rel, list) else str(rel)).lower()
            if 'icon' in rel_str:
                has_favicon = True
                break
        features['HasFavicon'] = 1 if has_favicon else 0

        features['NoOfSocialLinks'] = sum(
            1 for h in link_hrefs if any(s in str(h).lower() for s in SOCIAL_KEYWORDS)
        )
        features['NoOfEmailsInHTML'] = len(RE_EMAIL.findall(html_content))
    except Exception:
        return dict(HTML_DEFAULT_FEATURES)

    return features


def extract_features(url, use_html_mode=False):
    """Extract URL features and include zero-valued HTML defaults for schema compatibility."""
    try:
        features = {}
        
        # Parse URL
        try:
            parsed = urlparse(str(url))
        except:
            from urllib.parse import ParseResult
            parsed = ParseResult('', '', '', '', '', '')
        
        # 1. DomainPartCount - Number of dot-separated domain labels
        parts = [p for p in parsed.netloc.split('.') if p]
        features['DomainPartCount'] = len(parts)

        # 2. Have_IP - Check if domain is IP address
        try:
            domain = parsed.netloc.split(':')[0]
            if domain:
                ipaddress.ip_address(domain)
                features['Have_IP'] = 1
            else:
                features['Have_IP'] = 0
        except:
            features['Have_IP'] = 0
        
        # 3. Have_At - '@' symbol in URL
        features['Have_At'] = 1 if '@' in str(url) else 0
        
        # 4. URL_Length - Length of URL
        features['URL_Length'] = len(str(url))
        
        # 5. URL_Depth - Number of subdirectories
        features['URL_Depth'] = len([x for x in parsed.path.split('/') if x])
        
        # 6. Redirection - '//' after protocol
        try:
            pos = str(url).rfind('//')
            features['Redirection'] = 1 if pos > 7 else 0
        except:
            features['Redirection'] = 0
        
        # 7. https_Domain - 'http' or 'https' in domain part
        features['https_Domain'] = 1 if 'http' in parsed.netloc.lower() else 0
        
        # 8. TinyURL - URL shortening service
        try:
            features['TinyURL'] = 1 if re.search(SHORTENING_SERVICES, str(url)) else 0
        except:
            features['TinyURL'] = 0
        
        # 9. Prefix_Suffix - '-' in domain
        features['Prefix_Suffix'] = 1 if '-' in parsed.netloc else 0
        
        # 10. IsHTTPS - Uses HTTPS protocol
        features['IsHTTPS'] = 1 if parsed.scheme == 'https' else 0
        
        # 11. NoOfDots - Count of '.' in URL
        features['NoOfDots'] = str(url).count('.')
        
        # 12. NoOfHyphen - Count of '-' in URL
        features['NoOfHyphen'] = str(url).count('-')
        
        # 13. NoOfUnderscore - Count of '_' in URL
        features['NoOfUnderscore'] = str(url).count('_')
        
        # 14. NoOfSlash - Count of '/' in URL
        features['NoOfSlash'] = str(url).count('/')
        
        # 15. NoOfQuestionMark - Count of '?' in URL
        features['NoOfQuestionMark'] = str(url).count('?')
        
        # 16. NoOfEquals - Count of '=' in URL
        features['NoOfEquals'] = str(url).count('=')
        
        # 17. NoOfAmpersand - Count of '&' in URL
        features['NoOfAmpersand'] = str(url).count('&')
        
        # 18. NoOfPercent - Count of '%' in URL
        features['NoOfPercent'] = str(url).count('%')
        
        # 19. NoOfDigits - Count of digits in URL
        features['NoOfDigits'] = sum(c.isdigit() for c in str(url))
        
        # 20. NoOfLetters - Count of letters in URL
        features['NoOfLetters'] = sum(c.isalpha() for c in str(url))
        
        # 21. LetterRatio - Ratio of letters to total length
        features['LetterRatio'] = features['NoOfLetters'] / max(features['URL_Length'], 1)
        
        # 22. DigitRatio - Ratio of digits to total length
        features['DigitRatio'] = features['NoOfDigits'] / max(features['URL_Length'], 1)
        
        # 23. HasSubdomain - Has subdomain (more than domain.tld)
        features['HasSubdomain'] = 1 if len(parts) > 2 else 0
        
        # 24. SubdomainCount - Number of subdomains
        features['SubdomainCount'] = len(parts) - 2 if len(parts) > 2 else 0
        
        # 25. DomainLength - Length of domain
        features['DomainLength'] = len(parsed.netloc)
        
        # 26. PathLength - Length of path
        features['PathLength'] = len(parsed.path)
        
        # 27. QueryLength - Length of query string
        features['QueryLength'] = len(parsed.query)
        
        # 28. HasPort - URL has port number
        features['HasPort'] = 1 if ':' in parsed.netloc and parsed.netloc.split(':')[-1].isdigit() else 0
        
        # 29. SuspiciousWords - Contains suspicious keywords
        try:
            url_lower = str(url).lower()
            features['SuspiciousWords'] = 1 if any(keyword in url_lower for keyword in SUSPICIOUS_KEYWORDS) else 0
        except:
            features['SuspiciousWords'] = 0
        
        # 30. SpecialCharCount - Count of special characters
        try:
            special = '!@#$%^&*()[]{}|\\:;"\'<>,.?/~`'
            features['SpecialCharCount'] = sum(1 for c in str(url) if c in special)
        except:
            features['SpecialCharCount'] = 0

        # Add HTML defaults or populate HTML features from fetched content in optional mode.
        if use_html_mode:
            try:
                html_content = fetch_html_content(url, timeout=HTML_REQUEST_TIMEOUT)
                print(f"{Fore.GREEN}✓ HTML fetched successfully{Style.RESET_ALL}")
                html_features = extract_html_features_from_content(html_content)
                features.update(html_features)
            except Exception as e:
                print(f"{Fore.YELLOW}⚠ HTML fetch/parse failed: {e}. Using default HTML feature values.{Style.RESET_ALL}")
                features.update(HTML_DEFAULT_FEATURES)
        else:
            features.update(HTML_DEFAULT_FEATURES)
        
        return features
    except Exception as e:
        print(f"{Fore.RED}✗ Error extracting features: {e}{Style.RESET_ALL}")
        return None


def convert_feature_types(features_df):
    """Convert feature types to ensure compatibility with XGBoost."""
    # Ensure all columns are numeric
    for col in features_df.columns:
        if features_df[col].dtype == 'object':
            try:
                # Try to convert to numeric
                features_df[col] = pd.to_numeric(features_df[col], errors='coerce').fillna(0)
            except:
                pass
        
        # Ensure no NaN or inf values
        features_df[col] = features_df[col].replace([np.inf, -np.inf], 0).fillna(0)
    
    return features_df


def features_to_dataframe(features_dict, expected_features):
    """Convert features dictionary to DataFrame using model-expected feature order."""
    df = pd.DataFrame([features_dict])

    for feature in expected_features:
        if feature not in df.columns:
            df[feature] = 0

    return df[expected_features]


def predict_url(model, expected_features, url, use_html_mode=False):
    """Predict if a URL is phishing or legitimate."""
    print(f"\n{Fore.CYAN}Analyzing URL: {url}{Style.RESET_ALL}")
    print("-" * 80)
    
    # Check blacklist first
    if is_blacklisted(url):
        print(f"\n{Fore.YELLOW}PREDICTION RESULTS:{Style.RESET_ALL}")
        print("=" * 80)
        print(f"{Fore.RED}⚠️  WARNING: This URL is BLACKLISTED and treated as PHISHING!{Style.RESET_ALL}")
        print(f"\nConfidence Scores:")
        print(f"  Legitimate: {Fore.GREEN}1.00%{Style.RESET_ALL}")
        print(f"  Phishing:   {Fore.RED}99.00%{Style.RESET_ALL}")
        print(f"\nRisk Level: {Fore.RED}HIGH RISK{Style.RESET_ALL}")
        print("=" * 80)
        return

    # Check whitelist first
    if is_whitelisted_domain(url):
        print(f"\n{Fore.YELLOW}PREDICTION RESULTS:{Style.RESET_ALL}")
        print("=" * 80)
        print(f"{Fore.GREEN}✓ This URL appears to be LEGITIMATE{Style.RESET_ALL}")
        print(f"\n{Fore.CYAN}ℹ️  Domain recognized as trusted (whitelisted){Style.RESET_ALL}")
        print(f"\nConfidence Scores:")
        print(f"  Legitimate: {Fore.GREEN}99.00%{Style.RESET_ALL}")
        print(f"  Phishing:   {Fore.RED}1.00%{Style.RESET_ALL}")
        print(f"\nRisk Level: {Fore.GREEN}LOW RISK{Style.RESET_ALL}")
        print("=" * 80)
        return
    
    # Extract features
    print(f"{Fore.CYAN}Extracting features... (this may take a few seconds){Style.RESET_ALL}")
    features_dict = extract_features(url, use_html_mode=use_html_mode)
    if features_dict is None:
        return
    
    # Convert to DataFrame using helper function
    features_df = features_to_dataframe(features_dict, expected_features)
    
    # Convert feature types to ensure XGBoost compatibility
    features_df = convert_feature_types(features_df)
    
    # Make prediction
    try:
        prediction = model.predict(features_df)[0]
        probabilities = model.predict_proba(features_df)[0]
        
        # probabilities[0] is legitimate, probabilities[1] is phishing
        legitimate_prob = probabilities[0] * 100
        phishing_prob = probabilities[1] * 100
        
        # Display results
        print(f"\n{Fore.YELLOW}PREDICTION RESULTS:{Style.RESET_ALL}")
        print("=" * 80)
        
        # prediction 0 = legitimate (benign), prediction 1 = phishing
        if prediction == 1:
            print(f"{Fore.RED}⚠️  WARNING: This URL appears to be PHISHING!{Style.RESET_ALL}")
        else:
            print(f"{Fore.GREEN}✓ This URL appears to be LEGITIMATE{Style.RESET_ALL}")
        
        print(f"\nConfidence Scores:")
        print(f"  Legitimate: {Fore.GREEN}{legitimate_prob:.2f}%{Style.RESET_ALL}")
        print(f"  Phishing:   {Fore.RED}{phishing_prob:.2f}%{Style.RESET_ALL}")
        
        # Risk level based on probability
        print(f"\nRisk Level: ", end="")
        if phishing_prob >= 80:
            print(f"{Fore.RED}HIGH RISK{Style.RESET_ALL}")
        elif phishing_prob >= 50:
            print(f"{Fore.YELLOW}MEDIUM RISK{Style.RESET_ALL}")
        else:
            print(f"{Fore.GREEN}LOW RISK{Style.RESET_ALL}")
        
        print("=" * 80)
        
    except Exception as e:
        print(f"{Fore.RED}✗ Error making prediction: {e}{Style.RESET_ALL}")


def display_header():
    """Display application header."""
    print(f"\n{Fore.CYAN}{'=' * 80}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'PHISHING URL DETECTION SYSTEM':^80}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'Powered by XGBoost Machine Learning':^80}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'=' * 80}{Style.RESET_ALL}\n")


def run_interactive_mode(model, expected_features, use_html_mode=False):
    """Run the application in interactive mode."""
    display_header()
    
    while True:
        try:
            # Get URL from user
            print(f"\n{Fore.YELLOW}Enter a URL to check (or 'quit' to exit):{Style.RESET_ALL}")
            url = input("> ").strip()
            
            # Check for exit command
            if url.lower() in ['quit', 'exit', 'q']:
                print(f"\n{Fore.CYAN}Thank you for using Phishing Detection System!{Style.RESET_ALL}")
                break
            
            # Skip empty input
            if not url:
                continue
            
            # Add http:// if no protocol specified
            if not url.startswith(('http://', 'https://')):
                url = 'http://' + url
            
            # Predict
            predict_url(model, expected_features, url, use_html_mode=use_html_mode)
            
        except KeyboardInterrupt:
            print(f"\n\n{Fore.CYAN}Thank you for using Phishing Detection System!{Style.RESET_ALL}")
            break
        except Exception as e:
            print(f"{Fore.RED}✗ Unexpected error: {e}{Style.RESET_ALL}")


def run_batch_mode(model, expected_features, urls, use_html_mode=False):
    """Run the application in batch mode for multiple URLs."""
    display_header()
    print(f"{Fore.YELLOW}Processing {len(urls)} URLs...{Style.RESET_ALL}\n")
    
    results = []
    for idx, url in enumerate(urls, 1):
        print(f"\n[{idx}/{len(urls)}]", end=" ")

        # Check blacklist first
        if is_blacklisted(url):
            result = {
                'url': url,
                'prediction': 'PHISHING',
                'phishing_probability': '99.00%',
                'source': 'BLACKLIST'
            }
            results.append(result)
            print(f"{url}: {Fore.RED}PHISHING (Blacklisted){Style.RESET_ALL} (99.00%)")
            continue
        
        # Check whitelist first
        if is_whitelisted_domain(url):
            result = {
                'url': url,
                'prediction': 'LEGITIMATE',
                'phishing_probability': '1.00%',
                'source': 'WHITELIST'
            }
            results.append(result)
            print(f"{url}: {Fore.GREEN}LEGITIMATE (Whitelisted){Style.RESET_ALL} (1.00%)")
            continue
        
        features_dict = extract_features(url, use_html_mode=use_html_mode)
        if features_dict is None:
            results.append({'url': url, 'prediction': 'ERROR', 'phishing_probability': '0%', 'source': 'ERROR'})
            continue
        
        # Convert to DataFrame using helper function
        features_df = features_to_dataframe(features_dict, expected_features)
        
        # Convert feature types to ensure XGBoost compatibility
        features_df = convert_feature_types(features_df)
        
        try:
            prediction = model.predict(features_df)[0]
            probabilities = model.predict_proba(features_df)[0]
            # probabilities[0] is legitimate, probabilities[1] is phishing
            phishing_prob = probabilities[1] * 100
            
            result = {
                'url': url,
                'prediction': 'PHISHING' if prediction == 1 else 'LEGITIMATE',
                'phishing_probability': f"{phishing_prob:.2f}%",
                'source': 'MODEL'
            }
            results.append(result)
            
            # prediction 0 = legitimate, prediction 1 = phishing
            status = f"{Fore.RED}PHISHING{Style.RESET_ALL}" if prediction == 1 else f"{Fore.GREEN}LEGITIMATE{Style.RESET_ALL}"
            print(f"{url}: {status} ({phishing_prob:.2f}%)")
            
        except Exception as e:
            print(f"{url}: {Fore.RED}ERROR - {e}{Style.RESET_ALL}")
            results.append({'url': url, 'prediction': 'ERROR', 'phishing_probability': '0%', 'source': 'ERROR'})
    
    # Save results
    results_df = pd.DataFrame(results)
    output_file = "detection_results.csv"
    results_df.to_csv(output_file, index=False)
    print(f"\n{Fore.GREEN}✓ Results saved to {output_file}{Style.RESET_ALL}")


# ==================== MAIN ====================
def main():
    """Main application entry point."""
    # Load model
    model = load_model(MODEL_FILE)
    expected_features = load_expected_features(model, FEATURE_IMPORTANCE_FILE)

    use_html_mode = '--with-html' in sys.argv[1:]
    args = [arg for arg in sys.argv[1:] if arg != '--with-html']

    mode_text = "ON" if use_html_mode else "OFF"
    print(f"{Fore.CYAN}ℹ Runtime HTML fetch+parse mode: {mode_text}{Style.RESET_ALL}")
    
    # Check command line arguments
    if len(args) > 0:
        # Batch mode: URLs provided as arguments
        urls = args
        run_batch_mode(model, expected_features, urls, use_html_mode=use_html_mode)
    else:
        # Interactive mode
        run_interactive_mode(model, expected_features, use_html_mode=use_html_mode)


if __name__ == "__main__":
    main()
