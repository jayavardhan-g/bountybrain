"""Hybrid RAG: dense (Qdrant) + BM25 fused with reciprocal rank fusion,
then re-ranked with a cross-encoder.

Filters: `vuln_type`, `difficulty`, `date_from`, `date_to`, `target_tech`.
`date_*` and `target_tech` are applied post-fusion (payload-level) since
they aren't part of the base index shape.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date
from typing import Any

from rank_bm25 import BM25Okapi

from bountybrain.clients import embeddings
from bountybrain.clients import qdrant as qc
from bountybrain.kg.db import Session
from bountybrain.kg.models import Report, ReportTargetsTech, Target
from bountybrain.rag.reranker import rerank

RRF_K = 60


@dataclass
class Hit:
    report_id: int
    chunk_idx: int
    text: str
    url: str
    title: str
    score: float
    payload: dict = field(default_factory=dict)


@dataclass
class HybridResult:
    hits: list[Hit]
    query: str


# ---------- BM25 corpus (lazy, in-memory) ----------

_bm25_state: dict[str, Any] = {"bm25": None, "docs": [], "keys": []}


def _tokenize(text: str) -> list[str]:
    return [t.lower() for t in text.split() if t]


def _build_bm25() -> None:
    """Build the BM25 index from whatever chunk source is available.

    Prefer Qdrant (has pre-chunked payloads). If Qdrant is unreachable,
    fall back to chunking the Postgres `raw_markdown` on the fly so the
    zero-Docker path still has a lexical index.
    """
    docs: list[list[str]] = []
    payloads: list[dict] = []

    if qc.is_reachable():
        for p in qc.scroll_all():
            payloads.append({"id": p.id, "payload": p.payload})
            docs.append(_tokenize(p.payload.get("text", "")))
    else:
        from bountybrain.ingestion.chunker import chunk_text
        from bountybrain.kg.db import Session
        from bountybrain.kg.models import Report

        with Session() as s:
            for r in s.query(Report).all():
                for i, chunk in enumerate(chunk_text(r.raw_markdown or "")):
                    payloads.append(
                        {
                            "id": f"{r.id}-{i}",
                            "payload": {
                                "report_id": r.id,
                                "chunk_idx": i,
                                "text": chunk,
                                "url": r.url,
                                "title": r.title,
                                "date": r.date.isoformat() if r.date else None,
                                "vuln_type": None,
                                "difficulty": r.difficulty,
                                "source": r.source,
                            },
                        }
                    )
                    docs.append(_tokenize(chunk))

    _bm25_state["bm25"] = BM25Okapi(docs) if docs else None
    _bm25_state["docs"] = docs
    _bm25_state["keys"] = payloads


def invalidate_bm25() -> None:
    _bm25_state["bm25"] = None


# ---------- Dense side ----------


def _dense(query: str, limit: int, flt: dict) -> list[Hit]:
    if not qc.is_reachable():
        return []
    try:
        vec = embeddings.embed_one(query)
    except Exception:
        return []
    # only vuln_type + difficulty translate into Qdrant filters cleanly
    q_filter = {
        k: v for k, v in flt.items() if k in ("vuln_type", "difficulty", "source")
    }
    raw = qc.search(vec, limit=limit, flt=q_filter or None)
    hits: list[Hit] = []
    for r in raw:
        p = r.payload or {}
        hits.append(
            Hit(
                report_id=p.get("report_id"),
                chunk_idx=p.get("chunk_idx", 0),
                text=p.get("text", ""),
                url=p.get("url", ""),
                title=p.get("title", ""),
                score=float(r.score),
                payload=p,
            )
        )
    return hits


# ---------- BM25 side ----------


def _bm25(query: str, limit: int) -> list[Hit]:
    if _bm25_state["bm25"] is None:
        _build_bm25()
    bm = _bm25_state["bm25"]
    if bm is None:
        return []
    tokens = _tokenize(query)
    scores = bm.get_scores(tokens)
    order = sorted(range(len(scores)), key=lambda i: -scores[i])[:limit]
    hits: list[Hit] = []
    for i in order:
        row = _bm25_state["keys"][i]
        p = row["payload"] or {}
        hits.append(
            Hit(
                report_id=p.get("report_id"),
                chunk_idx=p.get("chunk_idx", 0),
                text=p.get("text", ""),
                url=p.get("url", ""),
                title=p.get("title", ""),
                score=float(scores[i]),
                payload=p,
            )
        )
    return hits


# ---------- Fusion + filters ----------


def _rrf(runs: list[list[Hit]]) -> list[Hit]:
    fused: dict[tuple, dict] = {}
    for run in runs:
        for rank, h in enumerate(run):
            key = (h.report_id, h.chunk_idx)
            slot = fused.setdefault(key, {"hit": h, "score": 0.0})
            slot["score"] += 1.0 / (RRF_K + rank + 1)
    out = []
    for v in sorted(fused.values(), key=lambda x: -x["score"]):
        v["hit"].score = v["score"]
        out.append(v["hit"])
    return out


def _apply_post_filters(hits: list[Hit], flt: dict) -> list[Hit]:
    date_from: date | None = flt.get("date_from")
    date_to: date | None = flt.get("date_to")
    target_tech: str | None = flt.get("target_tech")

    if not any([date_from, date_to, target_tech]):
        return hits

    target_report_ids: set[int] | None = None
    if target_tech:
        with Session() as s:
            rows = (
                s.query(Report.id)
                .join(ReportTargetsTech, ReportTargetsTech.report_id == Report.id)
                .join(Target, Target.id == ReportTargetsTech.target_id)
                .filter(Target.name.ilike(target_tech))
                .all()
            )
            target_report_ids = {r[0] for r in rows}

    kept = []
    for h in hits:
        d = h.payload.get("date")
        if date_from and (not d or d < date_from.isoformat()):
            continue
        if date_to and (not d or d > date_to.isoformat()):
            continue
        if target_report_ids is not None and h.report_id not in target_report_ids:
            continue
        kept.append(h)
    return kept


# ---------- Public entry ----------


def search(
    query: str,
    top_k: int = 5,
    fetch_k: int = 20,
    filters: dict | None = None,
    use_reranker: bool = True,
) -> HybridResult:
    flt = filters or {}
    dense_hits = _dense(query, limit=fetch_k, flt=flt)
    lex_hits = _bm25(query, limit=fetch_k)
    fused = _rrf([dense_hits, lex_hits])
    fused = _apply_post_filters(fused, flt)
    fused = fused[: fetch_k]
    if use_reranker and fused:
        fused = rerank(query, fused, top_n=top_k)
    else:
        fused = fused[:top_k]
    return HybridResult(hits=fused, query=query)
