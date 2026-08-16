"""Qdrant wrapper.

Defaults to **embedded mode**: Qdrant runs in-process against a local
directory (`settings.qdrant_path`) with no server and no port. That matters
on a shared machine, where binding 6333 either collides with someone else or
requires Docker privileges. Set `QDRANT_URL` to talk to a real server instead.

Every entry point degrades to a no-op or empty result if the store is
unavailable, so lexical search still works on its own.
"""
from __future__ import annotations

import warnings
from functools import lru_cache
from pathlib import Path

from qdrant_client import QdrantClient
from qdrant_client.http import models as qm

from bountybrain.clients.embeddings import embedding_dim
from bountybrain.config import settings

_state: dict = {"checked": False, "ok": False, "collection_ready": False}


@lru_cache(maxsize=1)
def client() -> QdrantClient | None:
    """Embedded client unless QDRANT_URL is set."""
    try:
        if settings.qdrant_url:
            return QdrantClient(
                url=settings.qdrant_url, timeout=10, check_compatibility=False
            )
        path = Path(settings.qdrant_path)
        path.mkdir(parents=True, exist_ok=True)
        return QdrantClient(path=str(path))
    except Exception as e:  # noqa: BLE001
        warnings.warn(f"Qdrant unavailable ({e}); dense search disabled.")
        return None


def is_reachable() -> bool:
    if _state["checked"]:
        return _state["ok"]
    c = client()
    try:
        if c is None:
            raise RuntimeError("no client")
        c.get_collections()
        _state["ok"] = True
    except Exception as e:  # noqa: BLE001
        warnings.warn(f"Qdrant unreachable ({e}); running without dense search.")
        _state["ok"] = False
    _state["checked"] = True
    return _state["ok"]


def ensure_collection(recreate: bool = False) -> bool:
    if not is_reachable():
        return False
    c = client()
    try:
        dim = embedding_dim()
    except Exception as e:  # noqa: BLE001
        warnings.warn(f"Could not load embedding model ({e}); dense search disabled.")
        return False

    existing = {col.name for col in c.get_collections().collections}
    name = settings.qdrant_collection
    if recreate and name in existing:
        c.delete_collection(name)
        existing.discard(name)
    if name not in existing:
        c.create_collection(
            collection_name=name,
            vectors_config=qm.VectorParams(size=dim, distance=qm.Distance.COSINE),
        )
    _state["collection_ready"] = True
    return True


def upsert_points(points: list[qm.PointStruct]) -> None:
    if not points or not ensure_collection():
        return
    client().upsert(collection_name=settings.qdrant_collection, points=points, wait=False)


def count() -> int:
    if not ensure_collection():
        return 0
    try:
        return client().count(settings.qdrant_collection, exact=True).count
    except Exception:
        return 0


def search(vector: list[float], limit: int = 20, flt: dict | None = None):
    if not ensure_collection():
        return []
    try:
        return client().query_points(
            collection_name=settings.qdrant_collection,
            query=vector,
            limit=limit,
            query_filter=_dict_to_filter(flt) if flt else None,
            with_payload=True,
        ).points
    except Exception as e:  # noqa: BLE001
        warnings.warn(f"Qdrant search failed ({e}).")
        return []


def scroll_all(batch: int = 1024):
    """Yield every stored point; empty iterator if the store is unavailable."""
    if not ensure_collection():
        return
    c = client()
    offset = None
    while True:
        pts, offset = c.scroll(
            collection_name=settings.qdrant_collection,
            with_payload=True,
            with_vectors=False,
            limit=batch,
            offset=offset,
        )
        for p in pts:
            yield p
        if offset is None:
            break


def _dict_to_filter(flt: dict) -> qm.Filter:
    must = []
    for k, v in flt.items():
        if v is None:
            continue
        if isinstance(v, (list, tuple, set)):
            must.append(qm.FieldCondition(key=k, match=qm.MatchAny(any=list(v))))
        else:
            must.append(qm.FieldCondition(key=k, match=qm.MatchValue(value=v)))
    return qm.Filter(must=must)
