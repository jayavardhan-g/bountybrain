"""Chunk documents for retrieval.

The naive approach — slice every N characters — splits fenced code blocks in
half. That is actively harmful in this corpus, where a payload or a request
trace *is* the answer to the query; half a payload retrieves as noise and
reads as garbage when cited.

So this chunker walks the document as a sequence of blocks (fenced code kept
whole, paragraphs otherwise) and packs blocks into chunks up to a budget. A
code block larger than the budget is emitted alone rather than being cut.
Overlap is applied at block granularity so context carries across boundaries
without duplicating half a code fence.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

TARGET_TOKENS = 400
OVERLAP_TOKENS = 60
CHARS_PER_TOKEN = 4  # rough, avoids a tokenizer dependency at ingest time

TARGET_CHARS = TARGET_TOKENS * CHARS_PER_TOKEN
OVERLAP_CHARS = OVERLAP_TOKENS * CHARS_PER_TOKEN
MIN_CHUNK_CHARS = 80

_FENCE = re.compile(r"```.*?```", re.DOTALL)


@dataclass
class Block:
    text: str
    is_code: bool

    def __len__(self) -> int:
        return len(self.text)


def _split_blocks(text: str) -> list[Block]:
    """Split into fenced-code and prose blocks, preserving order."""
    blocks: list[Block] = []
    pos = 0
    for m in _FENCE.finditer(text):
        prose = text[pos : m.start()].strip()
        if prose:
            blocks.extend(
                Block(p.strip(), False) for p in re.split(r"\n\s*\n", prose) if p.strip()
            )
        blocks.append(Block(m.group(0).strip(), True))
        pos = m.end()
    tail = text[pos:].strip()
    if tail:
        blocks.extend(
            Block(p.strip(), False) for p in re.split(r"\n\s*\n", tail) if p.strip()
        )
    return blocks


def chunk_text(text: str, target_chars: int = TARGET_CHARS) -> list[str]:
    """Pack blocks into chunks of roughly `target_chars`, never cutting code."""
    if not text or not text.strip():
        return []
    blocks = _split_blocks(text)
    if not blocks:
        return []

    # Cap overlap relative to the target. A fixed overlap against a small
    # target degenerates into emitting near-duplicate chunks, which wastes
    # index space and lets one passage dominate a result list.
    overlap_budget = min(OVERLAP_CHARS, max(0, target_chars // 4))

    chunks: list[str] = []
    current: list[Block] = []
    size = 0

    for block in blocks:
        # An oversized block stands alone: splitting it would corrupt it.
        if len(block) > target_chars:
            if current:
                chunks.append("\n\n".join(b.text for b in current))
                current, size = [], 0
            chunks.append(block.text)
            continue

        if size + len(block) > target_chars and current:
            chunks.append("\n\n".join(b.text for b in current))
            # carry trailing blocks forward as overlap
            carry: list[Block] = []
            carried = 0
            for b in reversed(current):
                if carried + len(b) > overlap_budget:
                    break
                carry.insert(0, b)
                carried += len(b)
            # Never carry the entire chunk forward — that would make the next
            # chunk a strict superset of the one just emitted.
            if len(carry) >= len(current):
                carry = carry[1:]
                carried = sum(len(b) for b in carry)
            current = carry
            size = carried

        current.append(block)
        size += len(block)

    if current:
        chunks.append("\n\n".join(b.text for b in current))

    return [c.strip() for c in chunks if len(c.strip()) >= MIN_CHUNK_CHARS]
