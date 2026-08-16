"""Qdrant client wrapper.

Wrapped so tests can swap it for an in-memory fake.

Every entry point degrades to a no-op / empty result when Qdrant is
unreachable, so the rest of the app keeps working without Docker.
"""
from __future__ import annotations

import warnings
from functools import lru_cache

from qdrant_client import QdrantClient
from qdrant_client.http import models as qm

from bountybrain.clients.embeddings import embedding_dim
from bountybrain.config import settings

_reachable_cache: dict = {"checked": False, "ok": False}


@lru_cache(maxsize=1)
def client() -> QdrantClient:
    return QdrantClient(url=settings.qdrant_url, timeout=5, check_compatibility=False)


def is_reachable() -> bool:
    """Cache result of a lightweight ping."""
    if _reachable_cache["checked"]:
        return _reachable_cache["ok"]
    try:
        client().get_collections()
        _reachable_cache["ok"] = True
    except Exception:
        warnings.warn(
            f"Qdrant unreachable at {settings.qdrant_url}; running without dense search."
        )
        _reachable_cache["ok"] = False
    _reachable_cache["checked"] = True
    return _reachable_cache["ok"]


def ensure_collection() -> bool:
    if not is_reachable():
        return False
    c = client()
    try:
        dim = embedding_dim()
    except Exception:
        return False
    existing = {col.name for col in c.get_collections().collections}
    if settings.qdrant_collection not in existing:
        c.create_collection(
            collection_name=settings.qdrant_collection,
            vectors_config=qm.VectorParams(size=dim, distance=qm.Distance.COSINE),
        )
    return True


def upsert_points(points: list[qm.PointStruct]) -> None:
    if not ensure_collection():
        return
    client().upsert(collection_name=settings.qdrant_collection, points=points)


def search(vector: list[float], limit: int = 20, flt: dict | None = None):
    if not ensure_collection():
        return []
    return client().search(
        collection_name=settings.qdrant_collection,
        query_vector=vector,
        limit=limit,
        query_filter=_dict_to_filter(flt) if flt else None,
    )


def scroll_all():
    """Yield all points; empty iterator if Qdrant is unreachable."""
    if not ensure_collection():
        return
    c = client()
    offset = None
    while True:
        pts, offset = c.scroll(
            collection_name=settings.qdrant_collection,
            with_payload=True,
            with_vectors=False,
            limit=512,
            offset=offset,
        )
        for p in pts:
            yield p
        if offset is None:
            break


def _dict_to_filter(flt: dict) -> qm.Filter:
    must = [
        qm.FieldCondition(key=k, match=qm.MatchValue(value=v))
        for k, v in flt.items()
        if v is not None
    ]
    return qm.Filter(must=must)
