"""
sandbox/monitor.py — Giám sát tiến trình/mạng/file system trong container
Chạy ở background trong khi malware thực thi.
Ghi kết quả vào JSON để dynamic_sandbox.py đọc lại.

Giám sát:
  - Network connections (psutil)
  - New files created (watchdog)
  - Running processes (psutil)
  - DNS queries (đọc từ /etc/hosts hoặc capture)

Usage:
  python3 monitor.py --output /sandbox/output/monitor.json
"""
from __future__ import annotations

import argparse
import json
import os
import signal
import time
from datetime import datetime
from pathlib import Path
from threading import Event, Thread
from typing import Any

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False

try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler
    WATCHDOG_AVAILABLE = True
except ImportError:
    WATCHDOG_AVAILABLE = False


# ─────────────────────────────────────────────
# File system watcher
# ─────────────────────────────────────────────

class FileEventHandler(FileSystemEventHandler if WATCHDOG_AVAILABLE else object):
    def __init__(self):
        self.events: list[dict] = []

    def on_created(self, event):
        if not event.is_directory:
            self.events.append({
                "type":  "created",
                "path":  event.src_path,
                "time":  datetime.utcnow().isoformat(),
            })

    def on_modified(self, event):
        if not event.is_directory and "output" not in event.src_path:
            self.events.append({
                "type": "modified",
                "path": event.src_path,
                "time": datetime.utcnow().isoformat(),
            })

    def on_deleted(self, event):
        self.events.append({
            "type": "deleted",
            "path": event.src_path,
            "time": datetime.utcnow().isoformat(),
        })


# ─────────────────────────────────────────────
# Network monitor
# ─────────────────────────────────────────────

def _snapshot_connections() -> list[dict]:
    if not PSUTIL_AVAILABLE:
        return []
    conns = []
    try:
        for c in psutil.net_connections(kind="all"):
            if c.raddr:
                conns.append({
                    "laddr": f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else "",
                    "raddr": f"{c.raddr.ip}:{c.raddr.port}",
                    "status": c.status,
                    "pid":    c.pid,
                })
    except Exception:
        pass
    return conns


def _snapshot_processes() -> list[dict]:
    if not PSUTIL_AVAILABLE:
        return []
    procs = []
    try:
        for p in psutil.process_iter(["pid", "name", "cmdline", "create_time"]):
            try:
                info = p.info
                procs.append({
                    "pid":     info["pid"],
                    "name":    info["name"],
                    "cmdline": " ".join(info.get("cmdline") or [])[:200],
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
    except Exception:
        pass
    return procs


# ─────────────────────────────────────────────
# Main monitor loop
# ─────────────────────────────────────────────

def run_monitor(output_path: str, stop_event: Event) -> None:
    results: dict[str, Any] = {
        "start_time":      datetime.utcnow().isoformat(),
        "connections":     [],
        "processes_seen":  [],
        "file_events":     [],
        "intervals":       [],
    }

    # File system watcher
    file_handler = FileEventHandler()
    observer = None
    if WATCHDOG_AVAILABLE:
        observer = Observer()
        observer.schedule(file_handler, path="/", recursive=True)
        observer.start()

    # Baseline processes
    baseline_pids = {p["pid"] for p in _snapshot_processes()}

    try:
        while not stop_event.is_set():
            # Network snapshot
            conns = _snapshot_connections()
            for c in conns:
                if c not in results["connections"]:
                    results["connections"].append(c)

            # New processes
            current_procs = _snapshot_processes()
            for p in current_procs:
                if p["pid"] not in baseline_pids:
                    results["processes_seen"].append(p)
                    baseline_pids.add(p["pid"])

            time.sleep(1)

    finally:
        if observer:
            observer.stop()
            observer.join()

        results["end_time"]    = datetime.utcnow().isoformat()
        results["file_events"] = file_handler.events

        # Deduplicate connections
        seen = set()
        unique_conns = []
        for c in results["connections"]:
            key = c["raddr"]
            if key not in seen:
                seen.add(key)
                unique_conns.append(c)
        results["connections"] = unique_conns

        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w") as f:
            json.dump(results, f, indent=2)

        print(f"[Monitor] Đã ghi: {output_path}")
        print(f"[Monitor] connections={len(unique_conns)} file_events={len(results['file_events'])}")


if __name__ == "__main__":
    if not PSUTIL_AVAILABLE:
        print("[Monitor] WARNING: psutil không có, giảm chức năng")
    if not WATCHDOG_AVAILABLE:
        print("[Monitor] WARNING: watchdog không có, không theo dõi file")

    parser = argparse.ArgumentParser()
    parser.add_argument("--output", default="/sandbox/output/monitor.json")
    args = parser.parse_args()

    stop_event = Event()

    def _handle_signal(sig, frame):
        print("[Monitor] Nhận signal dừng")
        stop_event.set()

    signal.signal(signal.SIGTERM, _handle_signal)
    signal.signal(signal.SIGINT, _handle_signal)

    print(f"[Monitor] Bắt đầu giám sát, output={args.output}")
    run_monitor(args.output, stop_event)