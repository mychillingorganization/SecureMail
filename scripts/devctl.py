#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path
from urllib.error import URLError
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
UTILS_DIR = ROOT / "utils"
if str(UTILS_DIR) not in sys.path:
    sys.path.insert(0, str(UTILS_DIR))

from cli_progress import StepProgress

RUNTIME_DIR = ROOT / ".runtime"
RUNTIME_DIR.mkdir(parents=True, exist_ok=True)
# Use venv Python if available, otherwise fall back to sys.executable
VENV_PYTHON = ROOT / ".venv" / "bin" / "python"
PYTHON_BIN = str(VENV_PYTHON) if VENV_PYTHON.exists() else sys.executable
DEFAULT_SCAN_OUTPUT_DIR = ROOT / "orchestra" / "scan_results"

SERVICES = {
    "email": {
        "health": "http://127.0.0.1:8000/health",
        "cmd": [PYTHON_BIN, "-m", "uvicorn", "email_module.main:app", "--host", "127.0.0.1", "--port", "8000", "--log-level", "warning"],
        "cwd": ROOT,
    },
    "file": {
        "health": "http://127.0.0.1:8001/health",
        "cmd": [PYTHON_BIN, "-m", "uvicorn", "file_module.file_module.main:app", "--host", "127.0.0.1", "--port", "8001", "--log-level", "warning"],
        "cwd": ROOT,
    },
    "web": {
        "health": "http://127.0.0.1:8002/health",
        "cmd": [PYTHON_BIN, "-m", "uvicorn", "web_module.main:app", "--host", "127.0.0.1", "--port", "8002", "--log-level", "warning"],
        "cwd": ROOT,
    },
    "ai": {
        "health": "http://127.0.0.1:8003/health",
        "cmd": [PYTHON_BIN, "-m", "uvicorn", "ai_module.main:app", "--host", "127.0.0.1", "--port", "8003", "--log-level", "warning"],
        "cwd": ROOT,
    },
    "orchestrator": {
        "health": "http://127.0.0.1:8080/health",
        "cmd": [PYTHON_BIN, "-m", "uvicorn", "orchestra.main:app", "--host", "127.0.0.1", "--port", "8080", "--log-level", "warning"],
        "cwd": ROOT,
    },
}


def _is_up(url: str, timeout: float = 1.5) -> bool:
    try:
        with urlopen(url, timeout=timeout) as resp:
            return 200 <= resp.status < 300
    except URLError:
        return False
    except Exception:
        return False


def _pid_file(name: str) -> Path:
    return RUNTIME_DIR / f"{name}.pid"


def _log_file(name: str) -> Path:
    return RUNTIME_DIR / f"{name}.log"


def _default_scan_output_path(llm: bool) -> Path:
    configured_dir = os.getenv("SECUREMAIL_SCAN_OUTPUT_DIR", "").strip()
    output_dir = Path(configured_dir) if configured_dir else DEFAULT_SCAN_OUTPUT_DIR
    if not output_dir.is_absolute():
        output_dir = ROOT / output_dir
    output_dir.mkdir(parents=True, exist_ok=True)
    filename = "test7_scan_llm_ai_agent_output.json" if llm else "test7_scan_output.json"
    return output_dir / filename


def _start_service(name: str, spec: dict[str, object]) -> None:
    if _is_up(str(spec["health"])):
        print(f"[UP] {name} already healthy")
        return

    log_path = _log_file(name)
    env = os.environ.copy()
    root_path = str(ROOT)
    existing_pythonpath = env.get("PYTHONPATH", "")
    env["PYTHONPATH"] = (
        f"{root_path}{os.pathsep}{existing_pythonpath}"
        if existing_pythonpath
        else root_path
    )

    with log_path.open("a", encoding="utf-8") as log:
        proc = subprocess.Popen(
            spec["cmd"],
            cwd=spec["cwd"],
            stdout=log,
            stderr=log,
            start_new_session=True,
            env=env,
        )

    _pid_file(name).write_text(str(proc.pid), encoding="utf-8")

    for _ in range(20):
        if _is_up(str(spec["health"])):
            print(f"[OK] {name} started (pid={proc.pid})")
            return
        time.sleep(0.5)

    print(f"[WARN] {name} did not become healthy. Check {_log_file(name)}")


def cmd_up() -> int:
    progress = StepProgress(total_steps=len(SERVICES), label="Service startup")
    for name, spec in SERVICES.items():
        progress.next(f"Starting {name}")
        _start_service(name, spec)
    progress.done("All services processed")
    return 0


def cmd_status() -> int:
    progress = StepProgress(total_steps=len(SERVICES), label="Service health check")
    for name, spec in SERVICES.items():
        status = "UP" if _is_up(str(spec["health"])) else "DOWN"
        print(f"{name:12s} {status:4s} {spec['health']}")
        progress.next(f"Checked {name}")
    progress.done("Health checks complete")
    return 0


def cmd_down() -> int:
    progress = StepProgress(total_steps=len(SERVICES), label="Service shutdown")
    for name in SERVICES:
        progress.next(f"Stopping {name}")
        p = _pid_file(name)
        if not p.exists():
            continue
        try:
            pid = int(p.read_text(encoding="utf-8").strip())
            os.kill(pid, signal.SIGTERM)
            print(f"[STOP] {name} pid={pid}")
        except Exception as exc:
            print(f"[WARN] cannot stop {name}: {exc}")
        finally:
            p.unlink(missing_ok=True)
    progress.done("Shutdown complete")
    return 0


def cmd_test7(llm: bool, output: str | None) -> int:
    progress = StepProgress(total_steps=5, label="Test7 scan")
    endpoint = "/api/v1/scan-llm" if llm else "/api/v1/scan"
    timeout_seconds = 360 if llm else 120
    progress.next("Prepared scan endpoint")

    sample_candidates = [
        ROOT / "test7.eml",
        ROOT / "temporary" / "root-legacy" / "test7.eml",
    ]
    email_path = next((p for p in sample_candidates if p.exists()), None)
    if email_path is None:
        raise FileNotFoundError(
            "test7 sample email not found. Expected one of: "
            + ", ".join(str(p) for p in sample_candidates)
        )
    progress.next("Located sample email")

    payload = {
        "email_path": str(email_path),
        "user_accepts_danger": False,
    }
    req = Request(
        f"http://127.0.0.1:8080{endpoint}",
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    with urlopen(req, timeout=timeout_seconds) as resp:
        body = resp.read().decode("utf-8")
        data = json.loads(body)
    progress.next("Uploaded and received scan result")

    print(f"HTTP: {resp.status}")
    print(f"final_status={data.get('final_status')} issue_count={data.get('issue_count')} termination_reason={data.get('termination_reason')}")

    out_path = Path(output) if output else _default_scan_output_path(llm)
    if not out_path.is_absolute():
        out_path = ROOT / out_path
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    progress.next("Saved scan output")
    print(f"saved={out_path}")
    progress.done("Completed")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="SecureMail dev control helper")
    sub = parser.add_subparsers(dest="cmd", required=True)

    sub.add_parser("up", help="Start local services and wait for health")
    sub.add_parser("down", help="Stop services started by this script")
    sub.add_parser("status", help="Show service health")

    p_test7 = sub.add_parser("test7", help="Run test7.eml scan")
    p_test7.add_argument("--llm", action="store_true", help="Use /api/v1/scan-llm")
    p_test7.add_argument("--output", default=None, help="Output JSON path")

    args = parser.parse_args()
    if args.cmd == "up":
        return cmd_up()
    if args.cmd == "down":
        return cmd_down()
    if args.cmd == "status":
        return cmd_status()
    if args.cmd == "test7":
        return cmd_test7(llm=bool(args.llm), output=args.output)

    return 1


if __name__ == "__main__":
    sys.exit(main())
