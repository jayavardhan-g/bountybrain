"""Thin SQLAlchemy engine + session factory.

Also exposes `init_db()` which creates tables if they don't exist and
falls back to SQLite when Postgres isn't reachable (helpful for tests /
first-run dev). The chosen URL is remembered for later calls.
"""
from __future__ import annotations

from contextlib import contextmanager
from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import sessionmaker

from bountybrain.config import settings
from bountybrain.kg.models import Base

_engine = None
_Session = None


def _build_engine():
    url = settings.database_url
    try:
        eng = create_engine(url, pool_pre_ping=True, future=True)
        with eng.connect():
            pass
        return eng
    except OperationalError:
        # fallback for local dev without Postgres
        fallback_path = Path(settings.data_dir) / "bountybrain.sqlite"
        fallback_url = f"sqlite+pysqlite:///{fallback_path}"
        return create_engine(fallback_url, future=True)


def _init():
    global _engine, _Session
    if _engine is None:
        _engine = _build_engine()
        _Session = sessionmaker(bind=_engine, autoflush=False, expire_on_commit=False)


def init_db() -> None:
    """Create tables. Call once at startup or before ingest."""
    _init()
    Base.metadata.create_all(_engine)


def engine():
    _init()
    return _engine


@contextmanager
def Session():
    _init()
    s = _Session()
    try:
        yield s
        s.commit()
    except Exception:
        s.rollback()
        raise
    finally:
        s.close()
