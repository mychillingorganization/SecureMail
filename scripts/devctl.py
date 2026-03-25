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
RUNTIME_DIR = ROOT / ".runtime"
RUNTIME_DIR.mkdir(parents=True, exist_ok=True)

SERVICES = {
    "email": {
        "health": "http://127.0.0.1:8000/health",
        "cmd": ["python3", "-m", "uvicorn", "email_agent.main:app", "--host", "127.0.0.1", "--port", "8000", "--log-level", "warning"],
        "cwd": ROOT,
    },
    "file": {
        "health": "http://127.0.0.1:8001/health",
        "cmd": ["python3", "-m", "uvicorn", "main:app", "--host", "127.0.0.1", "--port", "8001", "--log-level", "warning"],
        "cwd": ROOT / "FILE_AGENT" / "file_agent",
    },
    "web": {
        "health": "http://127.0.0.1:8002/health",
        "cmd": ["python3", "-m", "uvicorn", "main:app", "--host", "127.0.0.1", "--port", "8002", "--log-level", "warning"],
        "cwd": ROOT / "web_agent",
    },
    "ai": {
        "health": "http://127.0.0.1:8003/health",
        "cmd": ["python3", "-m", "uvicorn", "ai_agent.main:app", "--host", "127.0.0.1", "--port", "8003", "--log-level", "warning"],
        "cwd": ROOT,
    },
    "orchestrator": {
        "health": "http://127.0.0.1:8080/health",
        "cmd": ["python3", "-m", "uvicorn", "orchestra.main:app", "--host", "127.0.0.1", "--port", "8080", "--log-level", "warning"],
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


def _start_service(name: str, spec: dict[str, object]) -> None:
    if _is_up(str(spec["health"])):
        print(f"[UP] {name} already healthy")
        return

    log_path = _log_file(name)
    with log_path.open("a", encoding="utf-8") as log:
        proc = subprocess.Popen(
            spec["cmd"],
            cwd=spec["cwd"],
            stdout=log,
            stderr=log,
            start_new_session=True,
            env=os.environ.copy(),
        )

    _pid_file(name).write_text(str(proc.pid), encoding="utf-8")

    for _ in range(20):
        if _is_up(str(spec["health"])):
            print(f"[OK] {name} started (pid={proc.pid})")
            return
        time.sleep(0.5)

    print(f"[WARN] {name} did not become healthy. Check {_log_file(name)}")


def cmd_up() -> int:
    for name, spec in SERVICES.items():
        _start_service(name, spec)
    return 0


def cmd_status() -> int:
    for name, spec in SERVICES.items():
        status = "UP" if _is_up(str(spec["health"])) else "DOWN"
        print(f"{name:12s} {status:4s} {spec['health']}")
    return 0


def cmd_down() -> int:
    for name in SERVICES:
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
    return 0


def cmd_test7(llm: bool, output: str | None) -> int:
    endpoint = "/api/v1/scan-llm" if llm else "/api/v1/scan"
    timeout_seconds = 360 if llm else 120
    payload = {
        "email_path": str(ROOT / "test7.eml"),
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

    print(f"HTTP: {resp.status}")
    print(f"final_status={data.get('final_status')} issue_count={data.get('issue_count')} termination_reason={data.get('termination_reason')}")

    out_path = Path(output) if output else ROOT / ("test7_scan_llm_ai_agent_output.json" if llm else "test7_scan_output.json")
    out_path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"saved={out_path}")
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
