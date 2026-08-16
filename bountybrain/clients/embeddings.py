"""Local sentence-transformer embeddings.

Lazy-loaded so importing this module doesn't force the model download.
"""
from __future__ import annotations

from functools import lru_cache
from typing import Sequence

from bountybrain.config import settings


@lru_cache(maxsize=1)
def _model():
    from sentence_transformers import SentenceTransformer

    return SentenceTransformer(settings.embed_model)


def embed(texts: Sequence[str]) -> list[list[float]]:
    vecs = _model().encode(list(texts), normalize_embeddings=True, show_progress_bar=False)
    return [v.tolist() for v in vecs]


def embed_one(text: str) -> list[float]:
    return embed([text])[0]


def embedding_dim() -> int:
    m = _model()
    # newer sentence-transformers renamed this; keep both names working
    if hasattr(m, "get_embedding_dimension"):
        return m.get_embedding_dimension()
    return m.get_sentence_embedding_dimension()
