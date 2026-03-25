#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable
from urllib.parse import urlsplit, urlunsplit

import psycopg2
from psycopg2.extras import execute_values

from utils.cli_progress import ProgressBar, StepProgress

HEX64_RE = re.compile(r"\b[a-fA-F0-9]{64}\b")
DEFAULT_LISTS_DIR = Path(__file__).resolve().parent / "data" / "lists"
DEFAULT_STATE_FILE = DEFAULT_LISTS_DIR / ".list_import_state.json"


def normalize_url(raw: str) -> str:
    value = (raw or "").strip()
    if not value:
        return ""

    parsed = urlsplit(value)
    scheme = (parsed.scheme or "http").lower()
    netloc = parsed.netloc.lower()

    # Support plain-domain entries like "example.com/path".
    if not netloc and parsed.path and "." in parsed.path:
        parsed = urlsplit(f"{scheme}://{value}")
        netloc = parsed.netloc.lower()

    return urlunsplit((scheme, netloc, parsed.path or "", parsed.query or "", ""))


def hash_url(url: str) -> str:
    return hashlib.sha256(url.encode("utf-8", errors="ignore")).hexdigest()


def _count_csv_data_rows(path: Path) -> int:
    with path.open("r", encoding="utf-8", errors="ignore", newline="") as handle:
        reader = csv.reader(handle)
        total = sum(1 for _ in reader)
    return max(0, total - 1)


def parse_url_blacklist_csv(path: Path) -> list[tuple[str, str]]:
    rows: list[tuple[str, str]] = []
    seen: set[str] = set()
    total_rows = _count_csv_data_rows(path)
    progress = ProgressBar(total=max(1, total_rows), label="Loading URL blacklist")

    with path.open("r", encoding="utf-8", errors="ignore", newline="") as handle:
        reader = csv.DictReader(handle)
        if not reader.fieldnames or "url" not in [f.strip() for f in reader.fieldnames]:
            raise ValueError(f"CSV {path} must have a 'url' column")

        for row in reader:
            progress.update()
            url = normalize_url(row.get("url", ""))
            if not url or url in seen:
                continue
            seen.add(url)
            rows.append((hash_url(url), url))

    progress.done(suffix="parsed")
    return rows


def parse_file_hash_blacklist_csv(path: Path) -> list[str]:
    hashes: list[str] = []
    seen: set[str] = set()
    total_bytes = max(1, path.stat().st_size)
    progress = ProgressBar(total=total_bytes, label="Loading file-hash blacklist")

    with path.open("rb") as handle:
        for raw_line in handle:
            progress.update(len(raw_line))
            line = raw_line.decode("utf-8", errors="ignore")
            match = HEX64_RE.search(line)
            if not match:
                continue
            h = match.group(0).lower()
            if h in seen:
                continue
            seen.add(h)
            hashes.append(h)

    progress.done(suffix="parsed")
    return hashes


def parse_url_whitelist_txt(path: Path) -> list[tuple[str, str]]:
    rows: list[tuple[str, str]] = []
    seen: set[str] = set()

    with path.open("r", encoding="utf-8", errors="ignore") as handle:
        lines = handle.readlines()

    progress = ProgressBar(total=max(1, len(lines)), label="Loading URL whitelist")

    for line in lines:
        progress.update()
        value = line.strip()
        if not value or value.startswith("#"):
            continue
        url = normalize_url(value)
        if not url or url in seen:
            continue
        seen.add(url)
        rows.append((hash_url(url), url))

    progress.done(suffix="parsed")
    return rows


def parse_db_dsn_from_env() -> str:
    database_url = os.getenv("SECUREMAIL_DATABASE_URL", "").strip()
    if not database_url:
        raise ValueError("SECUREMAIL_DATABASE_URL is not set")

    if database_url.startswith("postgresql+asyncpg://"):
        return "postgresql://" + database_url[len("postgresql+asyncpg://") :]
    if database_url.startswith("postgresql://"):
        return database_url

    raise ValueError("SECUREMAIL_DATABASE_URL must start with postgresql+asyncpg:// or postgresql://")


def chunks(items: list, size: int) -> Iterable[list]:
    for i in range(0, len(items), size):
        yield items[i : i + size]


def import_url_blacklist(cur, url_rows: list[tuple[str, str]], batch_size: int) -> int:
    sql = """
    INSERT INTO urls (url_hash, raw_url, status, is_blacklisted, is_whitelisted, last_seen)
    VALUES %s
    ON CONFLICT (url_hash)
    DO UPDATE SET
      raw_url = EXCLUDED.raw_url,
      status = 'malicious'::entitystatus,
      is_blacklisted = TRUE,
      is_whitelisted = FALSE,
      last_seen = NOW();
    """

    imported = 0
    total_batches = max(1, (len(url_rows) + batch_size - 1) // batch_size)
    progress = ProgressBar(total=total_batches, label="Importing URL blacklist")
    for batch in chunks(url_rows, batch_size):
        values = [(h, u, "malicious", True, False) for h, u in batch]
        execute_values(cur, sql, values, template="(%s, %s, %s, %s, %s, NOW())")
        imported += len(batch)
        progress.update()
    progress.done(suffix="imported")
    return imported


def import_file_hash_blacklist(cur, file_hashes: list[str], batch_size: int) -> int:
    sql = """
    INSERT INTO files (file_hash, status, is_blacklisted, is_whitelisted, last_seen)
    VALUES %s
    ON CONFLICT (file_hash)
    DO UPDATE SET
      status = 'malicious'::entitystatus,
      is_blacklisted = TRUE,
      is_whitelisted = FALSE,
      last_seen = NOW();
    """

    imported = 0
    total_batches = max(1, (len(file_hashes) + batch_size - 1) // batch_size)
    progress = ProgressBar(total=total_batches, label="Importing file-hash blacklist")
    for batch in chunks(file_hashes, batch_size):
        values = [(h, "malicious", True, False) for h in batch]
        execute_values(cur, sql, values, template="(%s, %s, %s, %s, NOW())")
        imported += len(batch)
        progress.update()
    progress.done(suffix="imported")
    return imported


def import_url_whitelist(cur, url_rows: list[tuple[str, str]], batch_size: int) -> int:
    sql = """
    INSERT INTO urls (url_hash, raw_url, status, is_blacklisted, is_whitelisted, last_seen)
    VALUES %s
    ON CONFLICT (url_hash)
    DO UPDATE SET
      raw_url = EXCLUDED.raw_url,
      status = 'benign'::entitystatus,
      is_blacklisted = FALSE,
      is_whitelisted = TRUE,
      last_seen = NOW();
    """

    imported = 0
    total_batches = max(1, (len(url_rows) + batch_size - 1) // batch_size)
    progress = ProgressBar(total=total_batches, label="Importing URL whitelist")
    for batch in chunks(url_rows, batch_size):
        values = [(h, u, "benign", False, True) for h, u in batch]
        execute_values(cur, sql, values, template="(%s, %s, %s, %s, %s, NOW())")
        imported += len(batch)
        progress.update()
    progress.done(suffix="imported")
    return imported


def _file_signature(path: Path) -> dict[str, int]:
    stat = path.stat()
    return {
        "size": int(stat.st_size),
        "mtime_ns": int(stat.st_mtime_ns),
    }


def _load_state(path: Path) -> dict:
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}


def _save_state(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=True, indent=2), encoding="utf-8")


def _sources_snapshot(url_csv: Path, file_csv: Path, whitelist_txt: Path) -> dict[str, dict[str, int]]:
    return {
        "url_csv": _file_signature(url_csv),
        "file_csv": _file_signature(file_csv),
        "whitelist_txt": _file_signature(whitelist_txt),
    }


def main() -> int:
    setup = StepProgress(total_steps=7, label="List import")
    parser = argparse.ArgumentParser(description="Import URL/file blacklist and URL whitelist into PostgreSQL")
    parser.add_argument(
        "--url-csv",
        default=str(DEFAULT_LISTS_DIR / "URL_BlackList.csv"),
        help="Path to URL blacklist CSV with 'url' column",
    )
    parser.add_argument(
        "--file-csv",
        default=str(DEFAULT_LISTS_DIR / "file_black_list.csv"),
        help="Path to file-hash blacklist CSV",
    )
    parser.add_argument(
        "--whitelist-txt",
        default=str(DEFAULT_LISTS_DIR / "whitelist.txt"),
        help="Path to URL/domain whitelist text file",
    )
    parser.add_argument(
        "--state-file",
        default=str(DEFAULT_STATE_FILE),
        help="Path to importer state file used to detect source updates",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Import even when source list files are unchanged",
    )
    parser.add_argument("--batch-size", type=int, default=2000, help="Batch size for bulk upsert")
    args = parser.parse_args()
    setup.next("Arguments parsed")

    url_csv = Path(args.url_csv)
    file_csv = Path(args.file_csv)
    whitelist_txt = Path(args.whitelist_txt)
    state_file = Path(args.state_file)

    if not url_csv.exists():
        raise FileNotFoundError(f"Missing URL blacklist file: {url_csv}")
    if not file_csv.exists():
        raise FileNotFoundError(f"Missing file-hash blacklist file: {file_csv}")
    if not whitelist_txt.exists():
        raise FileNotFoundError(f"Missing URL whitelist file: {whitelist_txt}")
    setup.next("Validated source files")

    current_sources = _sources_snapshot(url_csv, file_csv, whitelist_txt)
    previous_state = _load_state(state_file)
    previous_sources = previous_state.get("sources") if isinstance(previous_state, dict) else None

    if not args.force and previous_sources == current_sources:
        setup.next("No source changes detected")
        print("No source updates detected; skipping import. Use --force to reimport.")
        setup.done("Skipped")
        return 0
    setup.next("Source changes detected")

    url_rows = parse_url_blacklist_csv(url_csv)
    file_hashes = parse_file_hash_blacklist_csv(file_csv)
    whitelist_rows = parse_url_whitelist_txt(whitelist_txt)
    setup.next("Loaded list sources")

    dsn = parse_db_dsn_from_env()
    with psycopg2.connect(dsn) as conn:
        with conn.cursor() as cur:
            url_count = import_url_blacklist(cur, url_rows, args.batch_size)
            file_count = import_file_hash_blacklist(cur, file_hashes, args.batch_size)
            whitelist_count = import_url_whitelist(cur, whitelist_rows, args.batch_size)
        conn.commit()
    setup.next("Imported records into PostgreSQL")

    state_payload = {
        "updated_at": datetime.now(timezone.utc).isoformat(),
        "sources": current_sources,
        "counts": {
            "url_blacklist": url_count,
            "file_blacklist": file_count,
            "url_whitelist": whitelist_count,
        },
    }
    _save_state(state_file, state_payload)
    setup.next("Saved import state")

    print(f"Imported URL blacklist rows: {url_count}")
    print(f"Imported file-hash blacklist rows: {file_count}")
    print(f"Imported URL whitelist rows: {whitelist_count}")
    setup.done("Completed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
