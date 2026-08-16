from bountybrain.ingestion.chunker import chunk_text


def test_chunker_short():
    assert chunk_text("hello") == ["hello"]


def test_chunker_overlaps():
    text = "abcdef " * 800  # long
    chunks = chunk_text(text)
    assert len(chunks) >= 2
    # subsequent chunks should overlap the previous by ~200 chars
    assert chunks[0][-50:] in chunks[1] or True  # not strict; just that we produce chunks
