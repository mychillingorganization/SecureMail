"""
Database — Kết nối PostgreSQL bất đồng bộ.
Sử dụng SQLAlchemy async engine với asyncpg.
"""
import logging

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase

logger = logging.getLogger(__name__)


class Base(DeclarativeBase):
    """Base class cho tất cả ORM models."""
    pass


class Database:
    """Quản lý kết nối PostgreSQL bất đồng bộ."""

    def __init__(self, url: str):
        self.url = url
        self.engine = None
        self.session_factory: async_sessionmaker | None = None

    async def connect(self):
        """Khởi tạo engine và session factory."""
        self.engine = create_async_engine(
            self.url,
            echo=False,
            pool_size=10,
            max_overflow=20,
        )
        self.session_factory = async_sessionmaker(
            self.engine,
            class_=AsyncSession,
            expire_on_commit=False,
        )
        logger.info(f"PostgreSQL connected: {self.url.split('@')[1] if '@' in self.url else self.url}")

    async def disconnect(self):
        """Đóng engine."""
        if self.engine:
            await self.engine.dispose()
            logger.info("PostgreSQL disconnected")

    def get_session(self) -> AsyncSession:
        """Lấy một session mới."""
        if not self.session_factory:
            raise RuntimeError("Database chưa kết nối. Gọi connect() trước.")
        return self.session_factory()

    async def create_tables(self):
        """Tạo tất cả bảng (chỉ dùng cho development/testing)."""
        async with self.engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
