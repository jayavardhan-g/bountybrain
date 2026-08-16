"""Local sentence-transformer embeddings.

Lazy-loaded so importing this module does not force a model download.

Two details that matter for retrieval quality:

*Asymmetric prefixes.* BGE models are trained with an instruction prefix on
the query side only. Embedding a query the same way as a passage measurably
degrades recall, so `embed_query` and `embed_passages` are separate calls
rather than one `embed`.

*Device selection.* Defaults to CUDA when available. The GPU matters here:
embedding the full corpus is ~100k chunks, which is minutes on a GPU and
over an hour on CPU.
"""
from __future__ import annotations

from collections.abc import Sequence
from functools import lru_cache

from bountybrain.config import settings

# Instruction prefix BGE v1.5 expects on queries. Empty for other model
# families, which are symmetric.
_QUERY_PREFIXES = {
    "bge": "Represent this sentence for searching relevant passages: ",
}


def _query_prefix(model_name: str) -> str:
    lowered = model_name.lower()
    for key, prefix in _QUERY_PREFIXES.items():
        if key in lowered:
            return prefix
    return ""


def _resolve_device() -> str:
    want = (settings.embed_device or "auto").lower()
    if want not in ("auto", "cuda"):
        return want
    try:
        import torch

        if torch.cuda.is_available():
            return "cuda"
    except Exception:
        pass
    return "cpu"


@lru_cache(maxsize=1)
def _model():
    from sentence_transformers import SentenceTransformer

    return SentenceTransformer(settings.embed_model, device=_resolve_device())


def embed_passages(texts: Sequence[str], show_progress: bool = False) -> list[list[float]]:
    """Embed documents for indexing (no instruction prefix)."""
    if not texts:
        return []
    vecs = _model().encode(
        list(texts),
        normalize_embeddings=True,
        batch_size=settings.embed_batch_size,
        show_progress_bar=show_progress,
        convert_to_numpy=True,
    )
    return vecs.tolist()


def embed_query(text: str) -> list[float]:
    """Embed a search query (with the model's instruction prefix)."""
    prefix = _query_prefix(settings.embed_model)
    vec = _model().encode(
        [prefix + text],
        normalize_embeddings=True,
        show_progress_bar=False,
        convert_to_numpy=True,
    )
    return vec[0].tolist()


def embed_queries(texts: Sequence[str]) -> list[list[float]]:
    if not texts:
        return []
    prefix = _query_prefix(settings.embed_model)
    vecs = _model().encode(
        [prefix + t for t in texts],
        normalize_embeddings=True,
        batch_size=settings.embed_batch_size,
        show_progress_bar=False,
        convert_to_numpy=True,
    )
    return vecs.tolist()


# Backwards-compatible aliases used by older call sites.
def embed(texts: Sequence[str]) -> list[list[float]]:
    return embed_passages(texts)


def embed_one(text: str) -> list[float]:
    return embed_query(text)


def embedding_dim() -> int:
    m = _model()
    if hasattr(m, "get_sentence_embedding_dimension"):
        return m.get_sentence_embedding_dimension()
    return m.get_embedding_dimension()
