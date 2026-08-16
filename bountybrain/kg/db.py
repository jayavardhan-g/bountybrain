"""SQLAlchemy engine + session factory.

SQLite is the default store (see `config.database_url`). If `DATABASE_URL`
points at Postgres and Postgres is unreachable, we fall back to a local
SQLite file rather than failing — the graph is self-contained either way.
"""
from __future__ import annotations

from contextlib import contextmanager
from pathlib import Path

from sqlalchemy import create_engine, event
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import sessionmaker

from bountybrain.config import settings
from bountybrain.kg.models import Base

_engine = None
_Session = None


def _sqlite_fallback_url() -> str:
    path = Path(settings.data_dir) / "bountybrain.sqlite"
    path.parent.mkdir(parents=True, exist_ok=True)
    return f"sqlite+pysqlite:///{path}"


def _tune_sqlite(engine) -> None:
    """WAL + a large page cache. The build writes ~130k rows in one pass and
    the default synchronous mode makes that roughly an order of magnitude
    slower for no benefit on a rebuildable derived artefact."""

    @event.listens_for(engine, "connect")
    def _set_pragma(dbapi_conn, _record):  # noqa: ANN001
        cur = dbapi_conn.cursor()
        cur.execute("PRAGMA journal_mode=WAL")
        cur.execute("PRAGMA synchronous=NORMAL")
        cur.execute("PRAGMA cache_size=-64000")  # 64 MB
        cur.execute("PRAGMA foreign_keys=ON")
        cur.close()


def _build_engine():
    url = settings.database_url
    if url.startswith("sqlite"):
        Path(settings.data_dir).mkdir(parents=True, exist_ok=True)
        eng = create_engine(url, future=True)
        _tune_sqlite(eng)
        return eng
    try:
        eng = create_engine(url, pool_pre_ping=True, future=True)
        with eng.connect():
            pass
        return eng
    except OperationalError:
        eng = create_engine(_sqlite_fallback_url(), future=True)
        _tune_sqlite(eng)
        return eng


def _init() -> None:
    global _engine, _Session
    if _engine is None:
        _engine = _build_engine()
        _Session = sessionmaker(bind=_engine, autoflush=False, expire_on_commit=False)


def init_db() -> None:
    """Create tables if they do not exist."""
    _init()
    Base.metadata.create_all(_engine)


def reset_db() -> None:
    """Drop and recreate every table — used by `build_graph.py --rebuild`."""
    _init()
    Base.metadata.drop_all(_engine)
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
