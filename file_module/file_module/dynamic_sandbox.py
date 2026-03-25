"""
dynamic_sandbox.py — Task 2.4
Sandbox động: Wine (.exe/.dll/.msi) + Linux container (.js/.py/.sh/.ps1/.vbs)
Tích hợp Fakenet-NG (DNS/HTTP sidecar) + psutil monitor

Flow cho .exe:
  1. Tạo isolated Docker network
  2. Khởi động Fakenet-NG sidecar
  3. Chạy Wine container với file suspect
  4. Thu thập artifacts: registry diff, network connections, dropped files
  5. Xóa TẤT CẢ containers + network sau phân tích

Flow cho scripts:
  1. Chạy Linux container với interpreter phù hợp
  2. Thu thập artifacts từ monitor.json
  3. Cleanup
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import tempfile
import time
import uuid
from pathlib import Path
from typing import Optional

from config import settings
from models import FileType, SandboxResult

logger = logging.getLogger(__name__)

SCRIPT_EXTENSIONS = {".js", ".vbs", ".vbe", ".ps1", ".psm1", ".sh", ".py", ".bat", ".cmd"}
PE_EXTENSIONS     = {".exe", ".dll", ".msi", ".scr", ".cpl"}

SANDBOX_IMAGE_WINE  = "file_agent_wine"
SANDBOX_IMAGE_LINUX = "file_agent_linux"
FAKENET_IMAGE       = "mandiant/fakenet-ng:latest"

SANDBOX_DIR = Path(__file__).parent.parent / "Sandbox"


# ─────────────────────────────────────────────
# Docker availability check
# ─────────────────────────────────────────────

def _docker_available() -> bool:
    try:
        import docker
        client = docker.from_env()
        client.ping()
        return True
    except Exception:
        return False


# ─────────────────────────────────────────────
# Parse Fakenet-NG log
# ─────────────────────────────────────────────

def _parse_fakenet_log(log_text: str) -> tuple[list[str], list[dict[str, str]]]:
    """
    Parse Fakenet-NG log to extract DNS queries and HTTP requests.
    Returns: (dns_queries, http_requests)
    """
    dns_queries: list[str] = []
    http_requests: list[dict[str, str]] = []

    for line in log_text.splitlines():
        # DNS query pattern: "DNS query for domain.com"
        dns_m = re.search(r"DNS.*query.*?([a-zA-Z0-9._-]+\.[a-zA-Z]{2,})", line, re.IGNORECASE)
        if dns_m:
            domain = dns_m.group(1)
            if domain not in dns_queries:
                dns_queries.append(domain)

        # HTTP request pattern: "GET http://..." or "POST ..."
        http_m = re.search(r"(GET|POST|PUT|DELETE|HEAD)\s+(https?://[^\s]+)", line, re.IGNORECASE)
        if http_m:
            http_requests.append({
                "method": http_m.group(1).upper(),
                "url":    http_m.group(2),
            })

    return dns_queries, http_requests


# ─────────────────────────────────────────────
# Parse monitor.json
# ─────────────────────────────────────────────

def _parse_monitor_output(monitor_json: str) -> dict:
    """Parse output from sandbox/monitor.py"""
    try:
        data = json.loads(monitor_json)
        connections = data.get("connections", [])
        processes   = data.get("processes_seen", [])
        file_events = data.get("file_events", [])

        # Extract unique remote addresses
        network_ips = list({c["raddr"] for c in connections if c.get("raddr")})

        # Extract new processes spawned
        spawned_processes = [p.get("name", "") for p in processes]

        # Extract created/modified files
        dropped_files = [
            e["path"] for e in file_events
            if e.get("type") == "created" and e.get("path")
        ]

        # Detect syscall patterns from process names
        suspicious_procs = [
            p for p in spawned_processes
            if any(s in p.lower() for s in ["cmd", "powershell", "wscript", "mshta", "regsvr"])
        ]

        return {
            "network_connections": network_ips,
            "dropped_files":       dropped_files[:20],
            "spawned_processes":   spawned_processes[:20],
            "suspicious_procs":    suspicious_procs,
        }
    except Exception as e:
        logger.warning(f"[Sandbox] Lỗi parse monitor.json: {e}")
        return {}


# ─────────────────────────────────────────────
# Wine sandbox (.exe/.dll/.msi)
# ─────────────────────────────────────────────

async def _run_wine_sandbox(
    data: bytes,
    filename: str,
    network_name: str,
    output_dir: Path,
) -> SandboxResult:
    """Chạy Wine container phân tích PE file."""
    result = SandboxResult(sandbox_type="wine")

    try:
        import docker
        client = docker.from_env()
    except ImportError:
        result.error = "docker-py chưa cài: pip install docker"
        return result
    except Exception as e:
        result.error = f"Docker không khả dụng: {e}"
        return result

    # Ghi file vào temp location để mount vào container
    suspect_path = output_dir / "suspect_input" / filename
    suspect_path.parent.mkdir(parents=True, exist_ok=True)
    suspect_path.write_bytes(data)

    container = None
    container_name = f"wine_sandbox_{uuid.uuid4().hex[:8]}"

    try:
        container = client.containers.run(
            image=SANDBOX_IMAGE_WINE,
            name=container_name,
            network=network_name,
            volumes={
                str(output_dir): {"bind": "/sandbox/output", "mode": "rw"},
                str(suspect_path): {"bind": f"/tmp/{filename}", "mode": "ro"},
            },
            environment={
                "SUSPECT_FILE": f"/tmp/{filename}",
                "EXEC_TIMEOUT": str(settings.wine_exec_timeout_seconds),
            },
            mem_limit="512m",
            cpu_period=100000,
            cpu_quota=50000,    # 50% CPU max
            detach=True,
            remove=False,
        )

        # Chờ container hoàn thành
        timeout = settings.sandbox_timeout_seconds
        deadline = time.time() + timeout

        while time.time() < deadline:
            container.reload()
            if container.status in ("exited", "dead"):
                break
            await asyncio.sleep(2)
        else:
            logger.warning(f"[Sandbox] Wine timeout sau {timeout}s, force stop")
            container.stop(timeout=5)

        # Đọc artifacts
        result.executed = True

        # Registry diff
        reg_diff_path = output_dir / "registry_diff.json"
        if reg_diff_path.exists():
            try:
                reg_data = json.loads(reg_diff_path.read_text(encoding="utf-8"))
                result.registry_changes = reg_data.get("added_keys", []) + \
                    [m["key"] for m in reg_data.get("modified_keys", [])]
                if reg_data.get("persistence_indicators"):
                    result.c2_indicators.extend([
                        f"persistence:{k}" for k in reg_data["persistence_indicators"]
                    ])
                result.risk_score_delta += reg_data.get("risk_score_delta", 0.0)
            except Exception as e:
                logger.warning(f"[Sandbox] Lỗi đọc registry diff: {e}")

        # Monitor output
        monitor_path = output_dir / "monitor.json"
        if monitor_path.exists():
            mon = _parse_monitor_output(monitor_path.read_text(encoding="utf-8"))
            result.dropped_files = mon.get("dropped_files", [])
            # Network connections từ monitor
            for addr in mon.get("network_connections", []):
                if addr not in result.c2_indicators:
                    result.c2_indicators.append(f"connect:{addr}")
            if mon.get("suspicious_procs"):
                result.risk_score_delta += 0.15

        result.risk_score_delta = min(result.risk_score_delta, 0.80)

    except Exception as e:
        result.error = str(e)
        logger.error(f"[Sandbox] Wine error: {e}")
    finally:
        # Cleanup container
        if container:
            try:
                container.remove(force=True)
                logger.info(f"[Sandbox] Container {container_name} đã xóa")
            except Exception:
                pass

    return result


# ─────────────────────────────────────────────
# Linux sandbox (scripts: .js/.py/.sh/.ps1/.vbs)
# ─────────────────────────────────────────────

async def _run_linux_sandbox(
    data: bytes,
    filename: str,
    network_name: str,
    output_dir: Path,
) -> SandboxResult:
    """Chạy Linux container phân tích script files."""
    result = SandboxResult(sandbox_type="linux")

    try:
        import docker
        client = docker.from_env()
    except ImportError:
        result.error = "docker-py chưa cài: pip install docker"
        return result
    except Exception as e:
        result.error = f"Docker không khả dụng: {e}"
        return result

    suspect_path = output_dir / "suspect_input" / filename
    suspect_path.parent.mkdir(parents=True, exist_ok=True)
    suspect_path.write_bytes(data)

    container = None
    container_name = f"linux_sandbox_{uuid.uuid4().hex[:8]}"

    try:
        container = client.containers.run(
            image=SANDBOX_IMAGE_LINUX,
            name=container_name,
            network=network_name,
            volumes={
                str(output_dir): {"bind": "/sandbox/output", "mode": "rw"},
                str(suspect_path): {"bind": f"/tmp/{filename}", "mode": "ro"},
            },
            environment={
                "SUSPECT_FILE": f"/tmp/{filename}",
                "EXEC_TIMEOUT": str(settings.wine_exec_timeout_seconds),
            },
            mem_limit="256m",
            cpu_period=100000,
            cpu_quota=25000,
            detach=True,
            remove=False,
        )

        timeout = settings.sandbox_timeout_seconds
        deadline = time.time() + timeout

        while time.time() < deadline:
            container.reload()
            if container.status in ("exited", "dead"):
                break
            await asyncio.sleep(2)
        else:
            container.stop(timeout=5)

        result.executed = True

        monitor_path = output_dir / "monitor.json"
        if monitor_path.exists():
            mon = _parse_monitor_output(monitor_path.read_text(encoding="utf-8"))
            result.dropped_files = mon.get("dropped_files", [])
            for addr in mon.get("network_connections", []):
                result.c2_indicators.append(f"connect:{addr}")
            if mon.get("suspicious_procs"):
                result.risk_score_delta += 0.15

        result.risk_score_delta = min(result.risk_score_delta, 0.60)

    except Exception as e:
        result.error = str(e)
        logger.error(f"[Sandbox] Linux error: {e}")
    finally:
        if container:
            try:
                container.remove(force=True)
            except Exception:
                pass

    return result


# ─────────────────────────────────────────────
# Fakenet-NG sidecar
# ─────────────────────────────────────────────

async def _start_fakenet(
    client,
    network_name: str,
    output_dir: Path,
) -> Optional[object]:
    """Khởi động Fakenet-NG container. Returns container object."""
    fakenet_log_dir = output_dir / "fakenet_logs"
    fakenet_log_dir.mkdir(parents=True, exist_ok=True)

    try:
        container = client.containers.run(
            image=FAKENET_IMAGE,
            name=f"fakenet_{uuid.uuid4().hex[:8]}",
            network=network_name,
            cap_add=["NET_ADMIN"],
            volumes={
                str(fakenet_log_dir): {"bind": "/fakenet/logs", "mode": "rw"},
            },
            detach=True,
            remove=False,
        )
        await asyncio.sleep(3)  # Chờ Fakenet khởi động
        logger.info("[Sandbox] Fakenet-NG đã khởi động")
        return container
    except Exception as e:
        logger.warning(f"[Sandbox] Fakenet không khởi động được: {e}")
        return None


async def _collect_fakenet_results(
    fakenet_container,
    output_dir: Path,
    result: SandboxResult,
) -> None:
    """Thu thập và parse log Fakenet-NG."""
    if fakenet_container is None:
        return

    try:
        # Đọc log từ container stdout
        log_bytes = fakenet_container.logs()
        log_text = log_bytes.decode("utf-8", errors="replace") if log_bytes else ""

        # Cũng đọc từ mounted log file
        fakenet_log_path = output_dir / "fakenet_logs" / "fakenet.log"
        if fakenet_log_path.exists():
            log_text += "\n" + fakenet_log_path.read_text(encoding="utf-8", errors="replace")

        dns_queries, http_requests = _parse_fakenet_log(log_text)
        result.dns_queries   = dns_queries[:20]
        result.http_requests = http_requests[:20]

        if dns_queries or http_requests:
            result.c2_indicators.extend([f"dns:{d}" for d in dns_queries[:5]])
            result.risk_score_delta += 0.25
            logger.info(f"[Sandbox] Fakenet: {len(dns_queries)} DNS, {len(http_requests)} HTTP")

    except Exception as e:
        logger.warning(f"[Sandbox] Lỗi đọc Fakenet logs: {e}")
    finally:
        try:
            fakenet_container.stop(timeout=5)
            fakenet_container.remove(force=True)
            logger.info("[Sandbox] Fakenet container đã xóa")
        except Exception:
            pass


# ─────────────────────────────────────────────
# Network management
# ─────────────────────────────────────────────

def _create_isolated_network(client) -> Optional[str]:
    """Tạo isolated Docker network (không có internet)."""
    net_name = f"sandbox_net_{uuid.uuid4().hex[:8]}"
    try:
        client.networks.create(
            net_name,
            driver="bridge",
            internal=True,   # Không có internet
            options={"com.docker.network.bridge.enable_icc": "true"},
        )
        logger.info(f"[Sandbox] Tạo network: {net_name}")
        return net_name
    except Exception as e:
        logger.warning(f"[Sandbox] Không tạo được network: {e}")
        return None


def _remove_network(client, net_name: str) -> None:
    try:
        net = client.networks.get(net_name)
        net.remove()
        logger.info(f"[Sandbox] Đã xóa network: {net_name}")
    except Exception:
        pass


# ─────────────────────────────────────────────
# Main entry point
# ─────────────────────────────────────────────

async def run_sandbox(
    data: bytes,
    filename: str,
    file_type: FileType,
) -> SandboxResult:
    """
    Chạy sandbox phân tích file động.

    Args:
        data:      bytes của file
        filename:  tên file gốc
        file_type: loại file đã detect

    Returns:
        SandboxResult — JSON-serializable
    """
    ext = Path(filename).suffix.lower()

    # .docm/.xlsm/.pdf → chỉ static analysis (sandbox không cần)
    if file_type == FileType.OFFICE or file_type == FileType.PDF:
        return SandboxResult(
            executed=False,
            error="Office/PDF: chỉ dùng static analysis, không cần sandbox",
        )

    # Xác định sandbox type
    if file_type == FileType.PE or ext in PE_EXTENSIONS:
        sandbox_fn = _run_wine_sandbox
        sandbox_type = "wine"
    elif file_type == FileType.SCRIPT or ext in SCRIPT_EXTENSIONS:
        sandbox_fn = _run_linux_sandbox
        sandbox_type = "linux"
    else:
        return SandboxResult(
            executed=False,
            error=f"Loại file không hỗ trợ sandbox: {ext}",
        )

    if not _docker_available():
        return SandboxResult(
            executed=False,
            sandbox_type=sandbox_type,
            error="Docker không khả dụng trên hệ thống này",
        )

    # Tạo thư mục output cho lần chạy này
    run_id = uuid.uuid4().hex[:8]
    output_dir = Path(tempfile.gettempdir()) / "file_agent_sandbox" / run_id
    output_dir.mkdir(parents=True, exist_ok=True)

    client = None
    network_name = None
    fakenet_container = None
    result = SandboxResult(sandbox_type=sandbox_type)

    try:
        import docker
        client = docker.from_env()
    except Exception as e:
        result.error = f"Docker client error: {e}"
        return result

    try:
        # 1. Tạo isolated network
        network_name = _create_isolated_network(client)

        # 2. Khởi động Fakenet-NG sidecar
        if network_name:
            fakenet_container = await _start_fakenet(client, network_name, output_dir)

        # 3. Chạy sandbox
        logger.info(f"[Sandbox] Khởi động {sandbox_type} sandbox cho {filename}")
        result = await sandbox_fn(
            data=data,
            filename=filename,
            network_name=network_name or "bridge",
            output_dir=output_dir,
        )

        # 4. Thu thập Fakenet results
        if fakenet_container:
            await _collect_fakenet_results(fakenet_container, output_dir, result)
            fakenet_container = None   # đã cleanup trong hàm trên

    except Exception as e:
        result.error = str(e)
        logger.error(f"[Sandbox] Lỗi sandbox: {e}")
    finally:
        # 5. Cleanup fakenet nếu chưa xóa
        if fakenet_container:
            try:
                fakenet_container.stop(timeout=3)
                fakenet_container.remove(force=True)
            except Exception:
                pass

        # 6. Xóa isolated network
        if client and network_name:
            _remove_network(client, network_name)

    # Cap risk score
    result.risk_score_delta = min(result.risk_score_delta, 0.80)

    logger.info(
        f"[Sandbox] Kết quả: executed={result.executed} "
        f"dns={len(result.dns_queries)} http={len(result.http_requests)} "
        f"registry={len(result.registry_changes)} "
        f"c2={len(result.c2_indicators)} delta={result.risk_score_delta:.2f}"
    )

    return result
