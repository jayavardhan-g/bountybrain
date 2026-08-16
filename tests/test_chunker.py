"""Chunker invariants.

The critical one is that fenced code blocks survive intact. This corpus is
full of payloads and request traces where half a code block is worse than
useless — it retrieves as noise and reads as garbage when cited.
"""
from __future__ import annotations

from bountybrain.ingestion.chunker import chunk_text, _split_blocks


DOC = """# SQL Injection

An introductory paragraph that is long enough to be a meaningful block of prose
rather than being filtered out as too short to matter for retrieval purposes.

## Payload

```sql
SELECT * FROM users WHERE id = 1 OR 1=1 --
UNION SELECT username, password FROM admin
```

A paragraph between two code blocks, also long enough to survive the minimum
chunk length filter that drops trivially short fragments from the index.

```bash
sqlmap -u "http://target/?id=1" --dbs --batch --risk=3 --level=5
```

Closing notes that wrap up the document with a reasonable amount of text.
"""


def test_returns_nothing_for_empty_input():
    assert chunk_text("") == []
    assert chunk_text("   \n  ") == []


def test_code_fences_are_never_split():
    for target in (200, 300, 500, 1600):
        for chunk in chunk_text(DOC, target_chars=target):
            assert chunk.count("```") % 2 == 0, f"unbalanced fence at target={target}"


def test_no_content_is_dropped():
    chunks = chunk_text(DOC, target_chars=300)
    joined = "\n".join(chunks)
    for block in _split_blocks(DOC):
        assert block.text in joined


def test_chunks_are_not_subsets_of_each_other():
    """Overlap must not degenerate into emitting near-duplicate chunks."""
    for target in (200, 300, 800):
        chunks = chunk_text(DOC, target_chars=target)
        for i, a in enumerate(chunks):
            for j, b in enumerate(chunks):
                if i != j:
                    assert a not in b, f"chunk {i} is contained in chunk {j} (target={target})"


def test_oversized_code_block_is_emitted_whole():
    big = "```\n" + "\n".join(f"line {i} of a very long payload listing" for i in range(200)) + "\n```"
    chunks = chunk_text(f"# Title\n\nIntro paragraph long enough to count.\n\n{big}")
    assert any(c.count("```") == 2 and "line 199" in c and "line 0" in c for c in chunks)


def test_respects_target_size_for_prose():
    prose = "\n\n".join(f"Paragraph number {i} with enough words to be a real block." for i in range(40))
    chunks = chunk_text(prose, target_chars=400)
    assert len(chunks) > 1
    # allow one block of overshoot, since blocks are never split
    assert all(len(c) < 400 + 200 for c in chunks)
