"""
hash_triage.py — Task 2.2
Pipeline: SHA-256 → Cache Redis → IOC PostgreSQL

Flow:
  1. Tính hashes (MD5/SHA1/SHA256) cho file bytes
  2. Check Redis cache (TTL 7 ngày) → nếu hit, trả kết quả ngay
  3. Check IOC database nội bộ (PostgreSQL)
  4. Quét ClamAV
  5. Lưu kết quả vào Redis + PostgreSQL
"""
from __future__ import annotations

import asyncio
import hashlib
import logging
from typing import Optional

import redis.asyncio as aioredis

from config import settings
from models import HashTriageResult

logger = logging.getLogger(__name__)




# ─────────────────────────────────────────────
# Hash computation
# ─────────────────────────────────────────────

def compute_hashes(data: bytes) -> dict[str, str]:
    return {
        "md5":    hashlib.md5(data).hexdigest(),
        "sha1":   hashlib.sha1(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
    }


# ─────────────────────────────────────────────
# Redis helpers
# ─────────────────────────────────────────────

def _cache_key(sha256: str) -> str:
    return f"file_module:hash:{sha256}"


async def _redis_get(redis: aioredis.Redis, sha256: str) -> Optional[HashTriageResult]:
    try:
        raw = await redis.get(_cache_key(sha256))
        if raw:
            return HashTriageResult.model_validate_json(raw)
    except Exception as e:
        logger.warning(f"[Redis] Cache GET failed: {e}")
    return None


async def _redis_set(redis: aioredis.Redis, result: HashTriageResult) -> None:
    try:
        await redis.setex(
            _cache_key(result.sha256),
            settings.redis_ttl_seconds,
            result.model_dump_json(),
        )
    except Exception as e:
        logger.warning(f"[Redis] Cache SET failed: {e}")


# ─────────────────────────────────────────────
# ClamAV scan
# ─────────────────────────────────────────────

async def _clamd_scan(data: bytes) -> tuple[Optional[str], Optional[str]]:
    """
    Quét file qua ClamAV daemon.
    Returns: (result, error)  result = "OK" hoặc tên virus
    """
    def _scan_sync(data: bytes) -> tuple[Optional[str], Optional[str]]:
        """Chạy pyclamd synchronous trong thread riêng."""
        try:
            import pyclamd
            cd = pyclamd.ClamdNetworkSocket(
                host=settings.clamd_host,
                port=settings.clamd_port,
            )
            result = cd.scan_stream(data)
            if result is None:
                return "OK", None
            status, virus_name = result.get("stream", ("OK", None))
            return (virus_name if status == "FOUND" else "OK"), None
        except Exception as e:
            return None, str(e)
    
    # Chạy trong thread pool để không block event loop
    return await asyncio.to_thread(_scan_sync, data)





# ─────────────────────────────────────────────
# IOC PostgreSQL (stub — tuỳ chỉnh theo schema của bạn)
# ─────────────────────────────────────────────

async def _ioc_db_lookup(sha256: str) -> tuple[bool, Optional[str]]:
    """
    Tra cứu hash trong IOC database nội bộ.
    Returns: (is_hit, threat_name)

    Schema gợi ý:
        CREATE TABLE ioc_hashes (
            sha256      TEXT PRIMARY KEY,
            threat_name TEXT,
            source      TEXT,
            added_at    TIMESTAMPTZ DEFAULT NOW()
        );
    """
    try:
        import asyncpg
        conn = await asyncpg.connect(settings.database_url.replace("+asyncpg", ""))
        try:
            row = await conn.fetchrow(
                "SELECT threat_name FROM ioc_hashes WHERE sha256 = $1", sha256
            )
            if row:
                return True, row["threat_name"]
            return False, None
        finally:
            await conn.close()
    except Exception as e:
        logger.debug(f"[IOC DB] Không kết nối được PostgreSQL: {e}")
        return False, None


# ─────────────────────────────────────────────
# Main entry point
# ─────────────────────────────────────────────

async def run_hash_triage(
    data: bytes,
    redis: aioredis.Redis,
) -> HashTriageResult:
    """
    Pipeline hash triage đầy đủ.

    Args:
        data:  bytes của file cần phân tích
        redis: Redis client đã kết nối

    Returns:
        HashTriageResult với đầy đủ thông tin
    """
    hashes = compute_hashes(data)
    sha256 = hashes["sha256"]

    logger.info(f"[HashTriage] SHA256={sha256[:16]}... size={len(data)} bytes")

    # ── 1. Cache Redis ──────────────────────────────────────────
    cached = await _redis_get(redis, sha256)
    if cached:
        logger.info(f"[HashTriage] Cache HIT: {sha256[:16]}...")
        cached.cache_hit = True
        return cached

    # ── 2. IOC Database ────────────────────────────────────────
    ioc_hit, ioc_threat = await _ioc_db_lookup(sha256)

    # ── 3. ClamAV (DISABLED by default — unreliable) ───────────
    clamd_result, clamd_error = None, None
    if settings.clamd_enabled:
        clamd_result, clamd_error = await _clamd_scan(data)

    # ── 4. Tính risk delta ────────────────────────────────────
    risk_delta = 0.0

    if ioc_hit:
        risk_delta += 0.60          # IOC nội bộ = rủi ro cao
    
    # ✗ ClamAV: disabled (không đáng tin)
    # if clamd_result and clamd_result != "OK":
    #     risk_delta += 0.40

    result = HashTriageResult(
        sha256=sha256,
        md5=hashes["md5"],
        sha1=hashes["sha1"],
        file_size=len(data),
        cache_hit=False,
        # IOC DB
        ioc_db_hit=ioc_hit,
        ioc_db_threat=ioc_threat,
        # ClamAV
        clamd_result=clamd_result,
        clamd_error=clamd_error,
        # Risk
        risk_score_delta=min(risk_delta, 1.0),
    )

    # ── 6. Lưu cache ───────────────────────────────────────────
    await _redis_set(redis, result)
    logger.info(
        f"[HashTriage] Done: "
        f"ioc={ioc_hit} "
        f"risk_delta={risk_delta:.2f}"
    )

    return result