"""Cross-encoder reranker. Loaded lazily.

If the reranker package or model isn't available, we degrade gracefully
to identity (just truncate to top_n).
"""
from __future__ import annotations

from functools import lru_cache
from typing import Any

from bountybrain.config import settings


@lru_cache(maxsize=1)
def _model():
    try:
        from sentence_transformers import CrossEncoder
    except Exception:
        return None
    try:
        return CrossEncoder(settings.reranker_model)
    except Exception:
        return None


def rerank(query: str, hits: list, top_n: int = 5) -> list:
    model = _model()
    if model is None or not hits:
        return hits[:top_n]
    pairs = [(query, h.text) for h in hits]
    scores = model.predict(pairs)
    ranked = sorted(zip(hits, scores), key=lambda x: -x[1])
    for h, s in ranked:
        h.score = float(s)
    return [h for h, _ in ranked[:top_n]]
