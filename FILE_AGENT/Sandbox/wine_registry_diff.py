"""
wine_registry_diff.py — So sánh Wine registry trước/sau thực thi
Phát hiện persistence keys: Run, RunOnce, Services, Winlogon, ...

Usage:
  python3 wine_registry_diff.py <before.reg> <after.reg> <output.json>

Output JSON:
{
  "added_keys":    [...],
  "deleted_keys":  [...],
  "modified_keys": [...],
  "persistence_indicators": [...],
  "risk_score_delta": 0.0
}
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Optional


# ─────────────────────────────────────────────
# Persistence-related registry paths
# ─────────────────────────────────────────────
PERSISTENCE_PATTERNS = [
    re.compile(r"\\Run\b",         re.IGNORECASE),
    re.compile(r"\\RunOnce\b",     re.IGNORECASE),
    re.compile(r"\\RunServices\b", re.IGNORECASE),
    re.compile(r"\\Services\\",    re.IGNORECASE),
    re.compile(r"\\Winlogon\\",    re.IGNORECASE),
    re.compile(r"\\AppInit_DLLs",  re.IGNORECASE),
    re.compile(r"\\Image File Execution Options\\", re.IGNORECASE),
    re.compile(r"\\Shell Extensions\\", re.IGNORECASE),
    re.compile(r"\\Policies\\Explorer\\Run", re.IGNORECASE),
    re.compile(r"\\Browser Helper Objects\\", re.IGNORECASE),
]


def _is_persistence(key: str) -> bool:
    return any(p.search(key) for p in PERSISTENCE_PATTERNS)


# ─────────────────────────────────────────────
# Parse .reg file
# ─────────────────────────────────────────────

def parse_reg_file(path: str) -> dict[str, dict[str, str]]:
    """
    Parse a Wine .reg file into a dict:
      { "HKEY_...\\path": { "value_name": "value_data", ... }, ... }
    
    Handles multi-line values (lines ending with backslash).
    """
    registry: dict[str, dict[str, str]] = {}
    current_key: Optional[str] = None
    pending_line = ""

    try:
        with open(path, encoding="utf-16-le", errors="replace") as f:
            lines = f.readlines()
    except UnicodeDecodeError:
        try:
            with open(path, encoding="utf-8", errors="replace") as f:
                lines = f.readlines()
        except Exception:
            return registry

    for raw_line in lines:
        line = raw_line.rstrip("\r\n")

        # Handle continuation lines (\ at end)
        if pending_line:
            line = pending_line + line
            pending_line = ""

        if line.endswith("\\"):
            pending_line = line[:-1]
            continue

        line = line.strip()

        if not line or line.startswith(";"):
            continue

        # Section header: [HKEY_...]  or [-HKEY_...] (deletion marker in diff)
        if line.startswith("["):
            key_match = re.match(r"^\[(-?)([^\]]+)\]", line)
            if key_match:
                deleted_prefix = key_match.group(1)
                current_key = key_match.group(2)
                if not deleted_prefix and current_key not in registry:
                    registry[current_key] = {}
            continue

        # Value line: "Name"=data  or @=data (default value)
        if current_key is not None and "=" in line:
            if line.startswith('"'):
                # Named value
                match = re.match(r'^"([^"]*)"=(.*)', line)
                if match:
                    name = match.group(1)
                    val = match.group(2).strip()
                    registry.setdefault(current_key, {})[name] = val
            elif line.startswith("@="):
                # Default value
                val = line[2:].strip()
                registry.setdefault(current_key, {})["@"] = val

    return registry


# ─────────────────────────────────────────────
# Diff logic
# ─────────────────────────────────────────────

def diff_registry(
    before: dict[str, dict[str, str]],
    after:  dict[str, dict[str, str]],
) -> dict:
    """
    Compare two parsed registry dicts.
    Returns dict with added_keys, deleted_keys, modified_keys, persistence_indicators.
    """
    before_keys = set(before.keys())
    after_keys  = set(after.keys())

    added_keys   = sorted(after_keys - before_keys)
    deleted_keys = sorted(before_keys - after_keys)
    modified_keys: list[dict] = []

    for key in before_keys & after_keys:
        bvals = before[key]
        avals = after[key]
        if bvals != avals:
            added_values   = {k: v for k, v in avals.items() if k not in bvals}
            removed_values = {k: v for k, v in bvals.items() if k not in avals}
            changed_values = {
                k: {"before": bvals[k], "after": avals[k]}
                for k in bvals.keys() & avals.keys()
                if bvals[k] != avals[k]
            }
            if added_values or removed_values or changed_values:
                modified_keys.append({
                    "key":             key,
                    "added_values":    added_values,
                    "removed_values":  removed_values,
                    "changed_values":  changed_values,
                })

    # Persistence detection
    persistence_indicators: list[str] = []
    all_changed = added_keys + [m["key"] for m in modified_keys]

    for key in all_changed:
        if _is_persistence(key):
            persistence_indicators.append(key)

    # Risk scoring
    risk_score_delta = 0.0
    if persistence_indicators:
        risk_score_delta += min(len(persistence_indicators) * 0.25, 0.60)
    if added_keys:
        risk_score_delta += min(len(added_keys) * 0.05, 0.20)

    risk_score_delta = min(risk_score_delta, 0.80)

    return {
        "added_keys":             added_keys[:50],      # limit output size
        "deleted_keys":           deleted_keys[:20],
        "modified_keys":          modified_keys[:50],
        "persistence_indicators": persistence_indicators,
        "total_added":            len(added_keys),
        "total_deleted":          len(deleted_keys),
        "total_modified":         len(modified_keys),
        "risk_score_delta":       round(risk_score_delta, 3),
    }


# ─────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────

def main():
    if len(sys.argv) < 4:
        print("Usage: wine_registry_diff.py <before.reg> <after.reg> <output.json>")
        sys.exit(1)

    before_path = sys.argv[1]
    after_path  = sys.argv[2]
    output_path = sys.argv[3]

    print(f"[RegDiff] Đọc registry trước: {before_path}")
    before = parse_reg_file(before_path)
    print(f"[RegDiff] Đọc registry sau:   {after_path}")
    after  = parse_reg_file(after_path)

    print(f"[RegDiff] Trước: {len(before)} keys | Sau: {len(after)} keys")
    result = diff_registry(before, after)

    print(f"[RegDiff] Added={result['total_added']} "
          f"Deleted={result['total_deleted']} "
          f"Modified={result['total_modified']} "
          f"Persistence={len(result['persistence_indicators'])} "
          f"delta={result['risk_score_delta']}")

    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2, ensure_ascii=False)

    print(f"[RegDiff] Đã ghi: {output_path}")


if __name__ == "__main__":
    main()
