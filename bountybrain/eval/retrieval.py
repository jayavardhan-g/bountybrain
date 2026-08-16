"""Retrieval eval — recall@5 and MRR over a small hand-built set.

We match "expected" by URL substring so the fixture stays stable even as
seed URLs get their numeric suffix reshuffled.
"""
from __future__ import annotations

import json
from pathlib import Path

from bountybrain.rag.hybrid import search

EVAL_FILE = Path(__file__).resolve().parents[1] / "fixtures" / "retrieval_eval.json"


def _match(url: str, substrs: list[str]) -> bool:
    return any(s in url for s in substrs)


def evaluate() -> dict:
    cases = json.loads(EVAL_FILE.read_text())
    recall_hits = 0
    rr_sum = 0.0
    per_case = []
    for c in cases:
        hits = search(c["query"], top_k=5).hits
        hit_rank = None
        for i, h in enumerate(hits, start=1):
            if _match(h.url, c["expected_url_substrings"]):
                hit_rank = i
                break
        if hit_rank:
            recall_hits += 1
            rr_sum += 1.0 / hit_rank
        per_case.append(
            {
                "query": c["query"],
                "top1_url": hits[0].url if hits else None,
                "hit_rank": hit_rank,
            }
        )
    n = len(cases)
    return {
        "n": n,
        "recall@5": recall_hits / n if n else 0.0,
        "mrr": rr_sum / n if n else 0.0,
        "cases": per_case,
    }
