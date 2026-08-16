"""Hybrid retrieval: dense vectors + BM25, fused with Reciprocal Rank Fusion,
optionally re-ranked by a cross-encoder.

The retriever is written so each stage can be run *in isolation* — `mode` is
one of `dense`, `bm25`, `hybrid`, `hybrid_rerank`. That is not an academic
nicety: without the ability to run each arm on identical inputs there is no
honest way to claim the hybrid actually beats its parts, and "we used hybrid
search" becomes an unverifiable assertion. `eval_retrieval.py` runs all four.

Why RRF rather than score interpolation: cosine similarity and BM25 scores
live on incomparable scales, and normalising them requires per-query
statistics that shift with corpus size. RRF only uses rank position, so it
needs no tuning and is stable as the corpus grows.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Literal

from rank_bm25 import BM25Okapi

from bountybrain.clients import embeddings
from bountybrain.clients import qdrant as qc
from bountybrain.rag.index import load_chunk_cache
from bountybrain.rag.reranker import rerank

RRF_K = 60  # standard damping constant; results are insensitive to it

Mode = Literal["dense", "bm25", "hybrid", "hybrid_rerank"]
MODES: tuple[Mode, ...] = ("dense", "bm25", "hybrid", "hybrid_rerank")

_TOKEN = re.compile(r"[a-z0-9_.-]+")


@dataclass
class Hit:
    document_id: int
    chunk_idx: int
    text: str
    url: str
    title: str
    score: float
    doc_type: str = ""
    source: str = ""
    payload: dict = field(default_factory=dict)


@dataclass
class HybridResult:
    hits: list[Hit]
    query: str
    mode: str
    timings_ms: dict[str, float] = field(default_factory=dict)


# ---------------------------------------------------------------- BM25 side

_bm25_state: dict[str, Any] = {"bm25": None, "rows": []}


def _tokenize(text: str) -> list[str]:
    return _TOKEN.findall(text.lower())


def build_bm25(force: bool = False) -> None:
    """Build the lexical index from the same chunk cache the dense side used."""
    if _bm25_state["bm25"] is not None and not force:
        return
    rows = load_chunk_cache()
    if not rows:
        _bm25_state["bm25"] = None
        _bm25_state["rows"] = []
        return
    corpus = [_tokenize(r.get("text", "")) for r in rows]
    _bm25_state["bm25"] = BM25Okapi(corpus)
    _bm25_state["rows"] = rows


def invalidate_bm25() -> None:
    _bm25_state["bm25"] = None
    _bm25_state["rows"] = []


def _row_to_hit(row: dict, score: float) -> Hit:
    return Hit(
        document_id=row.get("document_id"),
        chunk_idx=row.get("chunk_idx", 0),
        text=row.get("text", ""),
        url=row.get("url", ""),
        title=row.get("title", ""),
        doc_type=row.get("doc_type", ""),
        source=row.get("source", ""),
        score=score,
        payload=row,
    )


def _bm25_search(query: str, limit: int, flt: dict | None = None) -> list[Hit]:
    build_bm25()
    bm = _bm25_state["bm25"]
    if bm is None:
        return []
    rows = _bm25_state["rows"]
    scores = bm.get_scores(_tokenize(query))
    order = sorted(range(len(scores)), key=lambda i: -scores[i])

    hits: list[Hit] = []
    for i in order:
        if scores[i] <= 0:
            break
        row = rows[i]
        if flt and not _matches(row, flt):
            continue
        hits.append(_row_to_hit(row, float(scores[i])))
        if len(hits) >= limit:
            break
    return hits


def _matches(row: dict, flt: dict) -> bool:
    for key, want in flt.items():
        if want is None:
            continue
        have = row.get(key)
        if isinstance(want, (list, tuple, set)):
            if have not in want:
                return False
        elif have != want:
            return False
    return True


# --------------------------------------------------------------- dense side


def _dense_search(query: str, limit: int, flt: dict | None = None) -> list[Hit]:
    if not qc.is_reachable():
        return []
    try:
        vec = embeddings.embed_query(query)
    except Exception:
        return []
    raw = qc.search(vec, limit=limit, flt=flt)
    hits: list[Hit] = []
    for r in raw:
        p = r.payload or {}
        hits.append(_row_to_hit(p, float(r.score)))
    return hits


# ---------------------------------------------------------------- fusion


def reciprocal_rank_fusion(runs: list[list[Hit]], k: int = RRF_K) -> list[Hit]:
    """Fuse ranked lists by 1/(k + rank), summed across runs."""
    scores: dict[tuple[int, int], float] = {}
    best: dict[tuple[int, int], Hit] = {}
    for run in runs:
        for rank, hit in enumerate(run, start=1):
            key = (hit.document_id, hit.chunk_idx)
            scores[key] = scores.get(key, 0.0) + 1.0 / (k + rank)
            if key not in best:
                best[key] = hit
    fused = []
    for key, score in sorted(scores.items(), key=lambda kv: -kv[1]):
        hit = best[key]
        hit.score = score
        fused.append(hit)
    return fused


# ---------------------------------------------------------------- public API


def search(
    query: str,
    top_k: int = 5,
    mode: Mode = "hybrid_rerank",
    candidates: int = 40,
    flt: dict | None = None,
) -> HybridResult:
    """Retrieve `top_k` chunks for `query`.

    `candidates` is the depth each arm retrieves before fusion/reranking;
    it should comfortably exceed `top_k` or reranking has nothing to work with.
    """
    depth = max(candidates, top_k)

    if mode == "dense":
        hits = _dense_search(query, depth, flt)[:top_k]
    elif mode == "bm25":
        hits = _bm25_search(query, depth, flt)[:top_k]
    else:
        dense = _dense_search(query, depth, flt)
        lexical = _bm25_search(query, depth, flt)
        runs = [r for r in (dense, lexical) if r]
        fused = reciprocal_rank_fusion(runs) if runs else []
        if mode == "hybrid_rerank":
            hits = rerank(query, fused[:depth], top_n=top_k)
        else:
            hits = fused[:top_k]

    return HybridResult(hits=hits, query=query, mode=mode)


def available_modes() -> list[str]:
    """Which arms can actually run right now, for honest eval reporting."""
    modes = ["bm25"]
    if qc.is_reachable() and qc.count() > 0:
        modes = ["dense", "bm25", "hybrid", "hybrid_rerank"]
    return modes
