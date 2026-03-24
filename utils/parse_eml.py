"""Utility script to extract analysis artifacts from a single .eml file.

Outputs are written to a directory named after the input .eml filename:
- auth_headers.json
- content.txt
- urls.json
- manifest.json
- attachments/
"""

from __future__ import annotations

import argparse
import json
import mimetypes
import re
import sys
from collections.abc import Sequence
from dataclasses import dataclass, field
from email import policy
from email.header import decode_header
from email.parser import BytesParser
from email.utils import parsedate_to_datetime
from html import unescape
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import parse_qs, unquote, unquote_to_bytes, urlparse
from urllib.request import Request, urlopen

URL_PATTERN = re.compile(r"https?://[^\s<>'\"()]+", re.IGNORECASE)
HREF_PATTERN = re.compile(r"<a\b[^>]*?\bhref\s*=\s*['\"]([^'\"]+)['\"]", re.IGNORECASE)
INVALID_FILENAME_CHARS = re.compile(r"[<>:\"/\\|?*\x00-\x1f]")
BIDI_CONTROL_CHARS = re.compile(r"[\u200e\u200f\u202a-\u202e\u2066-\u2069]")
ATTACHMENT_EXTENSIONS = {
    ".pdf",
    ".doc",
    ".docx",
    ".xls",
    ".xlsx",
    ".ppt",
    ".pptx",
    ".csv",
    ".zip",
    ".rar",
    ".7z",
    ".jpg",
    ".jpeg",
    ".png",
    ".gif",
    ".webp",
    ".mp3",
    ".mp4",
    ".txt",
    ".json",
    ".xml",
}
UNSAFE_URL_SCHEMES = ("javascript:", "data:", "vbscript:", "file:")


@dataclass
class ParsedEmail:
    """Represents extracted data from an .eml message."""

    subject: str
    sent_at: str
    sender: str | None
    receiver: str | None
    auth_headers: dict[str, list[str]]
    plain_parts: list[str]
    html_parts: list[str]
    urls: set[str]
    attachment_count: int
    linked_attachment_count: int = 0
    downloaded_attachment_urls: set[str] = field(default_factory=set)


class _HTMLTextExtractor(HTMLParser):
    """Minimal HTML to text fallback extractor when bs4 is unavailable."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self._chunks: list[str] = []
        self._skip_depth = 0

    def handle_data(self, data: str) -> None:
        if data and self._skip_depth == 0:
            self._chunks.append(data)

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag in {"script", "style"}:
            self._skip_depth += 1
            return
        if tag in {"br", "p", "div", "li", "tr", "h1", "h2", "h3", "h4", "h5", "h6"}:
            self._chunks.append("\n")

    def handle_endtag(self, tag: str) -> None:
        if tag in {"script", "style"} and self._skip_depth > 0:
            self._skip_depth -= 1

    def get_text(self) -> str:
        return "".join(self._chunks)


def decode_mime_header(value: str | None) -> str:
    """Decode MIME encoded header values safely."""
    if not value:
        return ""

    parts = decode_header(value)
    decoded_fragments: list[str] = []
    for part, charset in parts:
        if isinstance(part, bytes):
            encoding = charset or "utf-8"
            try:
                decoded_fragments.append(part.decode(encoding, errors="replace"))
            except LookupError:
                decoded_fragments.append(part.decode("utf-8", errors="replace"))
        else:
            decoded_fragments.append(part)

    return "".join(decoded_fragments).strip()


def normalize_whitespace(text: str) -> str:
    """Collapse excessive blank lines while preserving readable text."""
    lines = [line.rstrip() for line in text.splitlines()]
    cleaned: list[str] = []
    previous_blank = False

    for line in lines:
        is_blank = not line.strip()
        if is_blank and previous_blank:
            continue
        cleaned.append(line)
        previous_blank = is_blank

    return "\n".join(cleaned).strip()


def normalize_for_tokens(text: str) -> str:
    """Normalize extracted body text into compact paragraphs for token efficiency."""
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    text = re.sub(r"[\t\f\v\u00a0]+", " ", text)
    text = re.sub(r"[ ]{2,}", " ", text)

    blocks = re.split(r"\n\s*\n+", text)
    compact_blocks: list[str] = []

    for block in blocks:
        lines = [line.strip() for line in block.splitlines() if line.strip()]
        if not lines:
            continue

        merged_lines = " ".join(lines)
        merged_lines = re.sub(r"\s+([,.;:!?])", r"\1", merged_lines)
        merged_lines = re.sub(r"\s{2,}", " ", merged_lines).strip()
        if merged_lines:
            compact_blocks.append(merged_lines)

    return "\n\n".join(compact_blocks)


def sanitize_filename(name: str) -> str:
    """Remove dangerous path characters from attachment filenames."""
    safe = BIDI_CONTROL_CHARS.sub("", name)
    safe = INVALID_FILENAME_CHARS.sub("_", safe).strip(" .")
    return safe or "attachment.bin"


def is_scanable_url(url: str) -> bool:
    """Allow only HTTP(S) URLs and reject unsafe pseudo-schemes."""
    normalized = url.strip().lower()
    if not normalized:
        return False
    if normalized.startswith(UNSAFE_URL_SCHEMES):
        return False

    parsed = urlparse(normalized)
    return parsed.scheme in {"http", "https"} and bool(parsed.netloc)


def ensure_unique_path(base_dir: Path, filename: str) -> Path:
    """Generate a unique file path if a filename already exists."""
    candidate = base_dir / filename
    if not candidate.exists():
        return candidate

    stem = candidate.stem
    suffix = candidate.suffix
    counter = 1
    while True:
        alt = base_dir / f"{stem}_{counter}{suffix}"
        if not alt.exists():
            return alt
        counter += 1


def parse_filename_from_url(url: str) -> str:
    """Try to infer a filename from URL path or query parameters."""
    parsed = urlparse(url)
    path_name = Path(unquote(parsed.path)).name
    if path_name and "." in path_name:
        return sanitize_filename(path_name)

    query = parse_qs(parsed.query)
    for key in ("filename", "file", "download", "attachment"):
        values = query.get(key)
        if not values:
            continue
        candidate = Path(unquote(values[0])).name
        if candidate and "." in candidate:
            return sanitize_filename(candidate)

    return ""


def looks_like_attachment_url(url: str) -> bool:
    """Heuristic check for URLs that likely point to downloadable files."""
    lower = url.lower()
    parsed = urlparse(lower)
    suffix = Path(unquote(parsed.path)).suffix.lower()
    if suffix in ATTACHMENT_EXTENSIONS:
        return True

    query = parse_qs(parsed.query)
    for key in ("filename", "file", "download", "attachment"):
        values = query.get(key)
        if not values:
            continue
        candidate_suffix = Path(unquote(values[0])).suffix.lower()
        if candidate_suffix in ATTACHMENT_EXTENSIONS:
            return True

    return any(token in lower for token in ("download", "attachment", "file="))


def filename_from_content_disposition(content_disposition: str) -> str:
    """Extract filename from Content-Disposition header when available."""
    if not content_disposition:
        return ""

    extended_match = re.search(r"filename\*\s*=\s*([^';\s]+)'[^']*'([^;]+)", content_disposition, re.IGNORECASE)
    if extended_match:
        charset = extended_match.group(1).strip().strip('"')
        encoded_name = extended_match.group(2).strip().strip('"')
        raw_name = unquote_to_bytes(encoded_name)
        try:
            decoded_name = raw_name.decode(charset, errors="replace")
        except LookupError:
            decoded_name = raw_name.decode("utf-8", errors="replace")
        return sanitize_filename(decoded_name)

    basic_match = re.search(r'filename\s*=\s*"?([^";]+)"?', content_disposition, re.IGNORECASE)
    if basic_match:
        return sanitize_filename(unquote(basic_match.group(1).strip()))

    return ""


def download_linked_attachments(urls: set[str], attachments_dir: Path) -> tuple[int, set[str]]:
    """Download file-like URLs into attachments directory if not already in MIME parts."""
    saved_count = 0
    downloaded_urls: set[str] = set()
    timeout_seconds = 12
    read_chunk_bytes = 1024 * 1024
    max_download_bytes = 25 * 1024 * 1024

    for url in sorted(urls):
        if not is_scanable_url(url) or not looks_like_attachment_url(url):
            continue

        try:
            request = Request(url, headers={"User-Agent": "Mozilla/5.0 (EML-Parser)"})
            with urlopen(request, timeout=timeout_seconds) as response:
                content_type = (response.headers.get("Content-Type") or "").lower()
                disposition = response.headers.get("Content-Disposition") or ""

                # Skip HTML pages that are usually redirect/landing pages.
                if "text/html" in content_type and "attachment" not in disposition.lower():
                    continue

                content_length_header = response.headers.get("Content-Length")
                if content_length_header:
                    try:
                        if int(content_length_header) > max_download_bytes:
                            continue
                    except ValueError:
                        pass

                data_chunks: list[bytes] = []
                total_bytes = 0
                while True:
                    chunk = response.read(read_chunk_bytes)
                    if not chunk:
                        break
                    data_chunks.append(chunk)
                    total_bytes += len(chunk)
                    if total_bytes > max_download_bytes:
                        break

                if total_bytes > max_download_bytes:
                    continue
                data = b"".join(data_chunks)

                filename = filename_from_content_disposition(disposition)
                if not filename:
                    filename = parse_filename_from_url(url)
                if not filename:
                    guessed_ext = mimetypes.guess_extension(content_type.split(";", 1)[0].strip()) or ".bin"
                    filename = f"linked_attachment{guessed_ext}"

                target = ensure_unique_path(attachments_dir, sanitize_filename(filename))
                target.write_bytes(data)
                saved_count += 1
                downloaded_urls.add(url)
        except Exception:
            continue

    return saved_count, downloaded_urls


def decode_part_to_text(part) -> str:
    """Decode a MIME text part using charset fallback."""
    payload = part.get_payload(decode=True)
    if payload is None:
        raw_payload = part.get_payload()
        if isinstance(raw_payload, str):
            return raw_payload
        if isinstance(raw_payload, bytes):
            payload = raw_payload
        else:
            return ""

    charset_candidates = [part.get_content_charset(), "utf-8", "latin-1"]
    for charset in charset_candidates:
        if not charset:
            continue
        try:
            return payload.decode(charset, errors="replace")
        except LookupError:
            continue
        except UnicodeDecodeError:
            continue

    return payload.decode("utf-8", errors="replace")


def extract_urls_from_text(text: str) -> set[str]:
    """Extract URLs from plain text using regex."""
    urls: set[str] = set()
    for match in URL_PATTERN.findall(text):
        normalized = match.rstrip(".,);]\"'")
        if normalized and is_scanable_url(normalized):
            urls.add(normalized)
    return urls


def extract_urls_from_html(html: str) -> set[str]:
    """Extract URL values from anchor href first, then generic regex matches."""
    urls: set[str] = set()

    try:
        from bs4 import BeautifulSoup  # type: ignore

        soup = BeautifulSoup(html, "html.parser")
        for link in soup.find_all("a", href=True):
            href = str(link.get("href", "")).strip()
            if href and is_scanable_url(href):
                urls.add(href)
    except ImportError:
        for href in HREF_PATTERN.findall(html):
            normalized_href = href.strip()
            if normalized_href and is_scanable_url(normalized_href):
                urls.add(normalized_href)

    urls.update(extract_urls_from_text(html))
    return urls


def html_to_text(html: str) -> str:
    """Convert HTML into plain text after URLs were extracted."""
    try:
        from bs4 import BeautifulSoup  # type: ignore

        soup = BeautifulSoup(html, "html.parser")
        for tag in soup(["script", "style"]):
            tag.decompose()
        text = soup.get_text(separator="\n")
        return normalize_whitespace(unescape(text))
    except ImportError:
        parser = _HTMLTextExtractor()
        parser.feed(html)
        parser.close()
        return normalize_whitespace(unescape(parser.get_text()))


def collect_auth_headers(message) -> dict[str, list[str]]:
    """Collect authentication-related headers for SPF, DKIM and DMARC inspection."""
    result: dict[str, list[str]] = {
        "Authentication-Results": [],
        "Received-SPF": [],
        "DKIM-Signature": [],
        "ARC-Authentication-Results": [],
        "spf_mentions": [],
        "dkim_mentions": [],
        "dmarc_mentions": [],
    }

    for key, value in message.items():
        key_lower = key.lower()
        if key_lower == "authentication-results":
            result["Authentication-Results"].append(value)
        if key_lower == "received-spf":
            result["Received-SPF"].append(value)
        if key_lower == "dkim-signature":
            result["DKIM-Signature"].append(value)
        if key_lower == "arc-authentication-results":
            result["ARC-Authentication-Results"].append(value)

        if "spf" in value.lower() or "spf" in key_lower:
            result["spf_mentions"].append(f"{key}: {value}")
        if "dkim" in value.lower() or "dkim" in key_lower:
            result["dkim_mentions"].append(f"{key}: {value}")
        if "dmarc" in value.lower() or "dmarc" in key_lower:
            result["dmarc_mentions"].append(f"{key}: {value}")

    return result


def save_attachment(part, attachments_dir: Path, index: int) -> bool:
    """Decode and save one attachment part to disk."""
    filename = part.get_filename()
    if filename:
        safe_name = sanitize_filename(decode_mime_header(filename))
    else:
        ext = ""
        content_type = (part.get_content_type() or "").lower()
        if "/" in content_type:
            ext_guess = content_type.split("/", 1)[1].split(";", 1)[0].strip()
            if ext_guess and ext_guess.isalnum() and len(ext_guess) <= 10:
                ext = f".{ext_guess}"
        safe_name = f"attachment_{index}{ext}"

    target_path = ensure_unique_path(attachments_dir, safe_name)
    payload = part.get_payload(decode=True)
    if payload is None:
        raw_payload = part.get_payload()
        if isinstance(raw_payload, str):
            payload = raw_payload.encode("utf-8", errors="replace")
        elif isinstance(raw_payload, bytes):
            payload = raw_payload
        else:
            return False

    target_path.write_bytes(payload)
    return True


def parse_eml(eml_path: Path, attachments_dir: Path) -> ParsedEmail:
    """Parse an .eml file and extract body, auth headers, URLs and attachments."""
    with eml_path.open("rb") as handle:
        message = BytesParser(policy=policy.default).parse(handle)

    subject = decode_mime_header(message.get("Subject", "")) or "(No Subject)"
    date_header = message.get("Date", "")
    sent_at = ""
    if date_header:
        try:
            sent_at = parsedate_to_datetime(date_header).isoformat()
        except (TypeError, ValueError, IndexError):
            sent_at = date_header

    auth_headers = collect_auth_headers(message)
    
    # Extract sender and receiver from standard email headers
    sender = decode_mime_header(message.get("From", "")) or None
    receiver = decode_mime_header(message.get("To", "")) or None
    
    plain_parts: list[str] = []
    html_parts: list[str] = []
    urls: set[str] = set()

    attachment_count = 0
    attachment_index = 1

    for part in message.walk():
        if part.is_multipart():
            continue

        content_type = (part.get_content_type() or "").lower()
        disposition = (part.get_content_disposition() or "").lower()
        filename = part.get_filename()

        is_named_binary_part = filename is not None and content_type not in {"text/plain", "text/html"}
        is_attachment = disposition == "attachment" or is_named_binary_part
        if is_attachment:
            if save_attachment(part, attachments_dir, attachment_index):
                attachment_count += 1
                attachment_index += 1
            continue

        if content_type == "text/plain":
            text = decode_part_to_text(part)
            plain_parts.append(text)
            urls.update(extract_urls_from_text(text))
            continue

        if content_type == "text/html":
            html = decode_part_to_text(part)
            html_parts.append(html)
            urls.update(extract_urls_from_html(html))

    return ParsedEmail(
        subject=subject,
        sent_at=sent_at,
        sender=sender,
        receiver=receiver,
        auth_headers=auth_headers,
        plain_parts=plain_parts,
        html_parts=html_parts,
        urls=urls,
        attachment_count=attachment_count,
    )


def build_output_dir(eml_path: Path, output_root: Path | None) -> Path:
    """Build output directory path named after the input .eml file stem."""
    root = output_root if output_root is not None else eml_path.parent
    output_dir_name = eml_path.stem or f"{eml_path.name}_output"
    output_dir = root / output_dir_name
    output_dir.mkdir(parents=True, exist_ok=True)
    return output_dir


def write_outputs(output_dir: Path, parsed: ParsedEmail) -> None:
    """Write extracted artifacts to output files."""
    attachments_dir = output_dir / "attachments"
    attachments_dir.mkdir(parents=True, exist_ok=True)

    auth_file = output_dir / "auth_headers.json"
    auth_file.write_text(
        json.dumps(parsed.auth_headers, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )

    html_as_text_parts = [html_to_text(html) for html in parsed.html_parts if html.strip()]
    body_sections = [section for section in (parsed.plain_parts + html_as_text_parts) if section.strip()]
    body_text = normalize_for_tokens("\n\n".join(body_sections))
    compact_body_text = re.sub(r"\s+", " ", body_text).strip()

    content_file = output_dir / "content.txt"
    content_text = f"Subject: {parsed.subject}\nContent: {compact_body_text}\n"
    content_file.write_text(content_text, encoding="utf-8")

    sorted_urls = sorted(parsed.urls)

    urls_json_file = output_dir / "urls.json"
    urls_json_file.write_text(json.dumps({"urls": sorted_urls}, ensure_ascii=False, indent=2), encoding="utf-8")

    # Backward compatibility: keep legacy line-based output during migration.
    urls_file = output_dir / "urls.txt"
    urls_file.write_text("\n".join(sorted_urls) + ("\n" if sorted_urls else ""), encoding="utf-8")

    manifest_file = output_dir / "manifest.json"
    manifest = {
        "schema_version": "1.1.0",
        "subject": parsed.subject,
        "sent_at": parsed.sent_at,
        "counts": {
            "urls": len(sorted_urls),
            "mime_attachments": parsed.attachment_count,
            "linked_attachments_downloaded": parsed.linked_attachment_count,
            "total_attachments_saved": parsed.attachment_count + parsed.linked_attachment_count,
        },
        "downloaded_attachment_urls": sorted(parsed.downloaded_attachment_urls),
        "files": {
            "auth_headers": "auth_headers.json",
            "content": "content.txt",
            "urls_json": "urls.json",
            "urls_legacy": "urls.txt",
            "attachments": "attachments/",
        },
    }
    manifest_file.write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    """Create and parse command line arguments."""
    parser = argparse.ArgumentParser(description="Extract data artifacts from a .eml file")
    parser.add_argument("eml_path", help="Path to input .eml file")
    parser.add_argument(
        "--output-root",
        help="Optional root directory where output folder is created",
        default=None,
    )
    return parser.parse_args(argv)


def validate_input_path(path_text: str) -> Path:
    """Validate input path and return a resolved Path object."""
    eml_path = Path(path_text).expanduser().resolve()
    if not eml_path.exists() or not eml_path.is_file():
        raise FileNotFoundError(f"Input file does not exist: {eml_path}")
    if eml_path.suffix.lower() != ".eml":
        raise ValueError(f"Input file must have .eml extension: {eml_path}")
    return eml_path


def main(argv: Sequence[str] | None = None) -> int:
    """CLI entry point."""
    try:
        args = parse_args(argv)
        eml_path = validate_input_path(args.eml_path)
        output_root = Path(args.output_root).expanduser().resolve() if args.output_root else None

        output_dir = build_output_dir(eml_path, output_root)
        attachments_dir = output_dir / "attachments"
        attachments_dir.mkdir(parents=True, exist_ok=True)

        parsed = parse_eml(eml_path, attachments_dir)
        linked_attachment_count, downloaded_attachment_urls = download_linked_attachments(parsed.urls, attachments_dir)
        parsed.linked_attachment_count = linked_attachment_count
        parsed.downloaded_attachment_urls = downloaded_attachment_urls
        write_outputs(output_dir, parsed)

        print(f"[*] Extracted artifacts to: {output_dir}")
        print(f"[*] Subject: {parsed.subject}")
        print(f"[*] URLs found: {len(parsed.urls)}")
        total_attachments = parsed.attachment_count + parsed.linked_attachment_count
        print(f"[*] Attachments saved: {total_attachments}")
        print(f"[*] Linked attachments downloaded: {parsed.linked_attachment_count}")
        return 0

    except FileNotFoundError as exc:
        print(f"[!] {exc}", file=sys.stderr)
        return 2
    except PermissionError as exc:
        print(f"[!] Permission denied: {exc}", file=sys.stderr)
        return 3
    except ValueError as exc:
        print(f"[!] Invalid input: {exc}", file=sys.stderr)
        return 4
    except Exception as exc:  # broad catch to keep utility resilient for malformed .eml files
        print(f"[!] Failed to process .eml file: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
