"""Simple whitespace chunker.

We aim for ~500 tokens per chunk with 50 token overlap. We use a rough
1 token ≈ 4 chars heuristic so we don't need a tokenizer at ingest time.
Good enough for retrieval; the reranker takes care of precision.
"""
from __future__ import annotations

TOKENS_PER_CHUNK = 500
OVERLAP_TOKENS = 50
CHARS_PER_TOKEN = 4


def chunk_text(text: str) -> list[str]:
    if not text:
        return []
    chunk_chars = TOKENS_PER_CHUNK * CHARS_PER_TOKEN
    overlap_chars = OVERLAP_TOKENS * CHARS_PER_TOKEN
    step = chunk_chars - overlap_chars
    chunks: list[str] = []
    i = 0
    n = len(text)
    while i < n:
        chunk = text[i : i + chunk_chars]
        chunks.append(chunk.strip())
        if i + chunk_chars >= n:
            break
        i += step
    return [c for c in chunks if c]
