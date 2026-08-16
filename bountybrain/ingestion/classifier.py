"""Assign CWE weakness classes to free-text vulnerability descriptions.

Three interchangeable strategies, all with the same signature, so the
evaluation can put them on identical inputs and report a real comparison
rather than a single unfalsifiable number:

    keyword    alias-table lookup over the CWE vocabulary. The cheap
               baseline — no model, no GPU, milliseconds.
    embedding  nearest CWE by embedding similarity against a text built from
               each class's name, aliases and description.
    llm        retrieval-augmented: take the embedding shortlist, then have
               the model pick from it.

Why the LLM does not choose freely from all ~970 classes: it cannot reliably
recall the numeric ids, and an open-ended prompt invites invented ones. The
shortlist turns an impossible recall problem into a tractable ranking problem
and makes hallucinated ids structurally impossible — anything off the list is
rejected.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

import numpy as np
from pydantic import BaseModel, Field

from bountybrain.clients import embeddings
from bountybrain.clients.llm import load_prompt, structured_many
from bountybrain.config import settings

SYSTEM = "You are a precise security analyst. You answer only with JSON."

CANDIDATE_CACHE = "cwe_candidates.npz"


class WeaknessChoice(BaseModel):
    """Schema the model is constrained to when picking from the shortlist."""

    cwe_id: int | None = None
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    reasoning: str = ""


@dataclass
class Prediction:
    cwe_id: int | None
    confidence: float
    method: str
    reasoning: str = ""


@dataclass
class CandidateIndex:
    """Embedded representation of every CWE class, for shortlisting."""

    cwe_ids: list[int]
    names: list[str]
    vectors: np.ndarray  # (n, dim), L2-normalised

    def topk(self, query_vecs: np.ndarray, k: int = 12) -> list[list[int]]:
        """Return, per query row, the indices of the k nearest classes."""
        sims = query_vecs @ self.vectors.T
        k = min(k, sims.shape[1])
        idx = np.argpartition(-sims, kth=k - 1, axis=1)[:, :k]
        # argpartition does not order within the selection; sort each row
        rows = []
        for r in range(idx.shape[0]):
            row = idx[r]
            rows.append(list(row[np.argsort(-sims[r, row])]))
        return rows


def _weakness_text(name: str, aliases: list[str], description: str) -> str:
    parts = [name]
    if aliases:
        parts.append("also known as " + ", ".join(aliases))
    if description:
        parts.append(description)
    return ". ".join(parts)


def build_candidate_index(force: bool = False) -> CandidateIndex:
    """Embed every CWE class once and cache it to disk."""
    cache = Path(settings.corpus_cache_dir) / CANDIDATE_CACHE
    if cache.exists() and not force:
        data = np.load(cache, allow_pickle=True)
        return CandidateIndex(
            cwe_ids=[int(x) for x in data["cwe_ids"]],
            names=[str(x) for x in data["names"]],
            vectors=data["vectors"],
        )

    from sqlalchemy import select

    from bountybrain.kg.db import Session
    from bountybrain.kg.models import Vulnerability

    with Session() as s:
        rows = s.execute(
            select(
                Vulnerability.cwe_id,
                Vulnerability.name,
                Vulnerability.aliases_json,
                Vulnerability.description,
            )
        ).all()

    cwe_ids, names, texts = [], [], []
    for cwe_id, name, aliases_json, description in rows:
        try:
            aliases = json.loads(aliases_json) if aliases_json else []
        except json.JSONDecodeError:
            aliases = []
        cwe_ids.append(int(cwe_id))
        names.append(name)
        texts.append(_weakness_text(name, aliases, description or ""))

    vectors = np.asarray(embeddings.embed_passages(texts), dtype=np.float32)
    cache.parent.mkdir(parents=True, exist_ok=True)
    np.savez_compressed(cache, cwe_ids=np.array(cwe_ids), names=np.array(names), vectors=vectors)
    return CandidateIndex(cwe_ids=cwe_ids, names=names, vectors=vectors)


@lru_cache(maxsize=1)
def _alias_table() -> dict[str, int]:
    """Alias -> CWE id, loaded from the catalogue on disk."""
    from bountybrain.datasets import cwe as cwe_ds
    from bountybrain.datasets.fetch import resolve_unpacked
    from bountybrain.datasets.registry import BY_NAME

    path = resolve_unpacked(BY_NAME["cwe"])
    if path is None:
        return {}
    return cwe_ds.alias_map(cwe_ds.load(path))


_WORD = re.compile(r"[a-z0-9][a-z0-9 +/'-]*")


def classify_keyword(texts: list[str]) -> list[Prediction]:
    """Baseline: longest alias occurring in the text wins.

    Longest-match matters — "sql injection" must beat "injection", or every
    specific class collapses into its parent.
    """
    table = _alias_table()
    aliases = sorted(table, key=len, reverse=True)
    out: list[Prediction] = []
    for text in texts:
        lowered = " ".join(text.lower().split())
        found = None
        for alias in aliases:
            if len(alias) < 3:
                continue
            if re.search(rf"(?<![a-z0-9]){re.escape(alias)}(?![a-z0-9])", lowered):
                found = table[alias]
                break
        out.append(
            Prediction(
                cwe_id=found,
                confidence=1.0 if found else 0.0,
                method="keyword",
                reasoning="alias match" if found else "no alias matched",
            )
        )
    return out


def classify_embedding(
    texts: list[str], index: CandidateIndex | None = None
) -> list[Prediction]:
    """Nearest CWE class by embedding cosine similarity."""
    idx = index or build_candidate_index()
    if not texts:
        return []
    qv = np.asarray(embeddings.embed_queries(texts), dtype=np.float32)
    sims = qv @ idx.vectors.T
    best = np.argmax(sims, axis=1)
    return [
        Prediction(
            cwe_id=idx.cwe_ids[int(b)],
            confidence=float(sims[i, b]),
            method="embedding",
            reasoning=f"nearest class: {idx.names[int(b)]}",
        )
        for i, b in enumerate(best)
    ]


def classify_llm(
    texts: list[str],
    index: CandidateIndex | None = None,
    k: int = 12,
    concurrency: int | None = None,
    progress_cb=None,
) -> list[Prediction]:
    """Shortlist by embedding, then let the model choose from the shortlist."""
    idx = index or build_candidate_index()
    if not texts:
        return []

    qv = np.asarray(embeddings.embed_queries(texts), dtype=np.float32)
    shortlists = idx.topk(qv, k=k)

    requests: list[tuple[str, str]] = []
    allowed: list[set[int]] = []
    for text, shortlist in zip(texts, shortlists, strict=True):
        lines = []
        ids: set[int] = set()
        for pos in shortlist:
            cwe_id = idx.cwe_ids[int(pos)]
            ids.add(cwe_id)
            lines.append(f"- CWE-{cwe_id}: {idx.names[int(pos)]}")
        allowed.append(ids)
        requests.append(
            (
                SYSTEM,
                load_prompt(
                    "classify_weakness",
                    candidates="\n".join(lines),
                    description=text[:4000],
                ),
            )
        )

    replies = structured_many(
        WeaknessChoice,
        requests,
        concurrency=concurrency,
        max_tokens=256,
        progress_cb=progress_cb,
    )

    out: list[Prediction] = []
    for reply, ids, shortlist in zip(replies, allowed, shortlists, strict=True):
        if reply is None:
            # fall back to the top embedding candidate rather than losing the row
            top = idx.cwe_ids[int(shortlist[0])] if shortlist else None
            out.append(
                Prediction(top, 0.2, "llm", "model failed; fell back to nearest neighbour")
            )
            continue
        # Reject anything not on the shortlist — makes invented ids impossible.
        if reply.cwe_id is not None and reply.cwe_id not in ids:
            out.append(Prediction(None, 0.0, "llm", "model chose an id outside the shortlist"))
            continue
        out.append(
            Prediction(reply.cwe_id, reply.confidence, "llm", reply.reasoning)
        )
    return out


STRATEGIES = {
    "keyword": classify_keyword,
    "embedding": classify_embedding,
    "llm": classify_llm,
}


def classify(texts: list[str], method: str = "llm", **kwargs) -> list[Prediction]:
    fn = STRATEGIES.get(method)
    if fn is None:
        raise ValueError(f"unknown method {method!r}; expected one of {list(STRATEGIES)}")
    return fn(texts, **kwargs)
