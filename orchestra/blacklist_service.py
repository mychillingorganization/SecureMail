"""
Blacklist Service — Step 8 persistence logic.
Manages file hash, URL, and domain blacklists in the database.
Used when user confirms a DANGER verdict to persist threat indicators.
"""

import hashlib
import logging
from datetime import datetime

from database import Database
from db_models import DomainEmailRecord, FileRecord, UrlRecord

logger = logging.getLogger(__name__)


class BlacklistService:
    """
    Service layer cho Step 8 của PRD pipeline.
    Khi user xác nhận email là nguy hiểm, lưu file hash và URL vào blacklist.
    """

    def __init__(self, database: Database):
        self.database = database

    # --- Write operations ---

    async def save_to_file_blacklist(self, file_hash: str, file_path: str | None = None):
        """Insert/update file hash vào bảng files với status = malicious."""
        async with self.database.get_session() as session:
            async with session.begin():
                existing = await session.get(FileRecord, file_hash)
                if existing:
                    existing.status = "malicious"
                    existing.last_seen = datetime.utcnow()
                    if file_path:
                        existing.file_path = file_path
                else:
                    record = FileRecord(
                        file_hash=file_hash,
                        status="malicious",
                        file_path=file_path,
                        last_seen=datetime.utcnow(),
                    )
                    session.add(record)
        logger.info(f"File hash blacklisted: {file_hash[:16]}...")

    async def save_to_url_blacklist(self, raw_url: str):
        """Insert/update URL vào bảng urls với status = malicious."""
        url_hash = hashlib.sha256(raw_url.encode()).hexdigest()
        async with self.database.get_session() as session:
            async with session.begin():
                existing = await session.get(UrlRecord, url_hash)
                if existing:
                    existing.status = "malicious"
                    existing.last_seen = datetime.utcnow()
                else:
                    record = UrlRecord(
                        url_hash=url_hash,
                        raw_url=raw_url,
                        status="malicious",
                        last_seen=datetime.utcnow(),
                    )
                    session.add(record)
        logger.info(f"URL blacklisted: {raw_url}")

    async def save_to_domain_blacklist(self, domain: str):
        """Insert/update domain vào bảng domain_email với status = malicious."""
        async with self.database.get_session() as session:
            async with session.begin():
                existing = await session.get(DomainEmailRecord, domain)
                if existing:
                    existing.status = "malicious"
                    existing.last_seen = datetime.utcnow()
                else:
                    record = DomainEmailRecord(
                        domain_email=domain,
                        status="malicious",
                        last_seen=datetime.utcnow(),
                    )
                    session.add(record)
        logger.info(f"Domain blacklisted: {domain}")

    # --- Read operations ---

    async def check_file_blacklist(self, file_hash: str) -> bool:
        """Check if file hash is in the blacklist."""
        async with self.database.get_session() as session:
            record = await session.get(FileRecord, file_hash)
            return record is not None and record.status == "malicious"

    async def check_url_blacklist(self, raw_url: str) -> bool:
        """Check if URL is in the blacklist."""
        url_hash = hashlib.sha256(raw_url.encode()).hexdigest()
        async with self.database.get_session() as session:
            record = await session.get(UrlRecord, url_hash)
            return record is not None and record.status == "malicious"

    async def check_domain_blacklist(self, domain: str) -> bool:
        """Check if domain is in the blacklist."""
        async with self.database.get_session() as session:
            record = await session.get(DomainEmailRecord, domain)
            return record is not None and record.status == "malicious"

    # --- Batch operations for Step 8 ---

    async def persist_danger_indicators(
        self,
        file_hashes: list[str] | None = None,
        urls: list[str] | None = None,
        domains: list[str] | None = None,
    ):
        """
        Batch persist all threat indicators when user confirms DANGER.
        Called from Step 8 of the pipeline.
        """
        if file_hashes:
            for fh in file_hashes:
                await self.save_to_file_blacklist(fh)
        if urls:
            for url in urls:
                await self.save_to_url_blacklist(url)
        if domains:
            for domain in domains:
                await self.save_to_domain_blacklist(domain)
        logger.info(
            f"Persisted danger indicators: "
            f"{len(file_hashes or [])} files, "
            f"{len(urls or [])} urls, "
            f"{len(domains or [])} domains"
        )
