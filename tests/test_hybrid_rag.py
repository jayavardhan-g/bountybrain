"""RAG hybrid math test — RRF fusion is deterministic and doesn't need a
running Qdrant. We stub the two ranking sides and check fusion order.
"""
from __future__ import annotations

from bountybrain.rag import hybrid


def _hits(pairs):
    return [
        hybrid.Hit(
            report_id=i, chunk_idx=0, text=t, url=f"seed://x/{i}", title=t, score=s
        )
        for i, (t, s) in enumerate(pairs)
    ]


def test_rrf_merges_and_ranks():
    dense = _hits([("A", 0.9), ("B", 0.7), ("C", 0.5)])
    lex = _hits([("B", 3.0), ("A", 1.0), ("D", 0.5)])
    fused = hybrid._rrf([dense, lex])
    order = [h.text for h in fused]
    # B appears rank-1 in one list and rank-2 in the other; A appears
    # rank-1 dense and rank-2 lex. Both beat C and D.
    assert set(order[:2]) == {"A", "B"}
    assert order[-1] in {"C", "D"}
