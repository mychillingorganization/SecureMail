from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path

# When running as a script directly (python run_protocol_verifier.py),
# add the project root to sys.path so 'email_agent' package can be found.
_project_root = Path(__file__).resolve().parent.parent
if str(_project_root) not in sys.path:
    sys.path.insert(0, str(_project_root))

from email_agent.protocol_verifier import ProtocolVerifier

# Force UTF-8 output encoding for proper Vietnamese character display
if sys.stdout.encoding != "utf-8":
    import io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

# Configure logging: only show errors from sub-libraries
logging.basicConfig(
    level=logging.WARNING,
    format="[%(levelname)s] %(message)s",
)

# Suppress debug logs from sub-libraries  
logging.getLogger("dkimpy").setLevel(logging.CRITICAL)
logging.getLogger("checkdmarc").setLevel(logging.WARNING)
logging.getLogger("email_agent.protocol_verifier").setLevel(logging.WARNING)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run ProtocolVerifier against a specific .eml file"
    )
    parser.add_argument(
        "eml_file",
        help="Path to .eml file",
    )
    return parser.parse_args()


def resolve_input_path(input_path: str) -> Path:
    resolved = Path(input_path).expanduser().resolve()
    if not resolved.exists() or not resolved.is_file():
        raise FileNotFoundError(f"Input file does not exist: {resolved}")
    if resolved.suffix.lower() != ".eml":
        raise ValueError(f"Expected a .eml file: {resolved}")
    return resolved


def main() -> int:
    try:
        args = parse_args()
        input_path = resolve_input_path(args.eml_file)
        verifier = ProtocolVerifier()
        result = verifier.verify_from_eml_file(input_path)

        print(f"Source: {input_path}")
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0
    except Exception as exc:
        print(f"Error: {exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())