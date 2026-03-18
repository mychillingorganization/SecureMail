"""Visual favicon analyzer for brand spoofing detection.

This module provides a service class that:
1) discovers a website favicon URL,
2) computes a perceptual hash (pHash),
3) finds the nearest protected brand hash in PostgreSQL using DB-side bitwise XOR,
4) emits a simple risk verdict.
"""

from __future__ import annotations

from io import BytesIO
from typing import Any, cast
from urllib.parse import urljoin, urlparse

import imagehash
import requests
import sqlalchemy as sa
from bs4 import BeautifulSoup
from PIL import Image
from requests import RequestException
from sqlalchemy.dialects.postgresql import BIT
from sqlalchemy.orm import Session


Favicon = Any


class VisualAnalyzer:
    """Visual phishing analyzer using favicon pHash matching."""

    USER_AGENT: str = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/122.0.0.0 Safari/537.36"
    )
    REQUEST_TIMEOUT_SECONDS: int = 5

    def __init__(self, favicon_model: type[Any]) -> None:
        self.favicon_model = favicon_model

    def extract_favicon_url(self, target_url: str) -> str:
        """Extract favicon URL from page HTML or fallback to /favicon.ico."""
        headers = {"User-Agent": self.USER_AGENT}
        fallback = self._build_favicon_fallback(target_url)

        try:
            response = requests.get(
                target_url,
                headers=headers,
                timeout=self.REQUEST_TIMEOUT_SECONDS,
            )
            response.raise_for_status()
            soup = BeautifulSoup(response.text, "html.parser")

            icon_tag = soup.find("link", rel=lambda value: self._rel_contains_icon(value))
            if icon_tag and icon_tag.get("href"):
                href = str(icon_tag["href"]).strip()
                if href:
                    return urljoin(target_url, href)
        except RequestException:
            return fallback
        except Exception:
            return fallback

        return fallback

    def compute_phash(self, image_url: str) -> str:
        """Compute 64-bit pHash of an image and return as binary string."""
        headers = {"User-Agent": self.USER_AGENT}

        response = requests.get(
            image_url,
            headers=headers,
            timeout=self.REQUEST_TIMEOUT_SECONDS,
        )
        response.raise_for_status()

        with Image.open(BytesIO(response.content)) as image:
            hash_value = imagehash.phash(image)

        return "".join("1" if bit else "0" for bit in hash_value.hash.flatten())

    def find_similar_brand(
        self,
        db_session: Session,
        target_hash_bin: str,
        threshold: int = 5,
    ) -> Favicon | None:
        """Find nearest brand by Hamming distance in PostgreSQL.

        Query is executed fully in DB using native bitwise XOR (#), without
        loading all rows into Python memory.
        """
        if len(target_hash_bin) != 64 or any(bit not in {"0", "1"} for bit in target_hash_bin):
            return None

        target_bit = cast(Any, sa.cast(sa.bindparam("target_hash"), BIT(64)))
        db_bit = cast(Any, sa.cast(self.favicon_model.phash_value, BIT(64)))
        xor_expr = db_bit.op("#")(target_bit)
        xor_as_text = sa.cast(xor_expr, sa.Text)
        distance_expr = sa.func.length(sa.func.replace(xor_as_text, "0", ""))

        stmt = (
            sa.select(self.favicon_model)
            .where(distance_expr <= threshold)
            .order_by(distance_expr.asc())
            .limit(1)
        )

        result = db_session.execute(stmt, {"target_hash": target_hash_bin}).scalar_one_or_none()
        return cast(Favicon | None, result)

    def evaluate_visual_risk(self, db_session: Session, target_url: str) -> dict[str, str]:
        """Evaluate visual phishing risk from favicon similarity and domain allowlist."""
        try:
            favicon_url = self.extract_favicon_url(target_url)
            target_hash_bin = self.compute_phash(favicon_url)
            similar_brand = self.find_similar_brand(db_session, target_hash_bin)

            if similar_brand is None:
                return {"verdict": "UNKNOWN"}

            target_domain = self._extract_domain(target_url)
            if not target_domain:
                return {"verdict": "UNKNOWN"}

            valid_domains = [
                domain.strip().lower()
                for domain in (similar_brand.valid_domains or [])
                if isinstance(domain, str) and domain.strip()
            ]

            if target_domain.lower() in valid_domains:
                return {"verdict": "SAFE"}

            return {"verdict": "MALICIOUS", "reason": "Spoofed logo"}
        except RequestException:
            return {"verdict": "UNKNOWN"}
        except Exception:
            return {"verdict": "UNKNOWN"}

    @staticmethod
    def _extract_domain(target_url: str) -> str | None:
        parsed = urlparse(target_url)
        host = parsed.hostname
        if not host:
            return None
        return host.lower()

    @staticmethod
    def _build_favicon_fallback(target_url: str) -> str:
        parsed = urlparse(target_url)
        if parsed.scheme and parsed.netloc:
            return f"{parsed.scheme}://{parsed.netloc}/favicon.ico"
        return target_url.rstrip("/") + "/favicon.ico"

    @staticmethod
    def _rel_contains_icon(rel_value: Any) -> bool:
        if rel_value is None:
            return False

        if isinstance(rel_value, str):
            normalized = rel_value.lower().split()
        elif isinstance(rel_value, (list, tuple, set)):
            normalized = [str(item).lower() for item in rel_value]
        else:
            normalized = [str(rel_value).lower()]

        return ("icon" in normalized) or ("shortcut" in normalized and "icon" in normalized)
