"""Build the retrieval index: documents -> chunks -> embeddings -> Qdrant.

Chunk ids are deterministic (a hash of document id + chunk index), so a
rebuild overwrites rather than duplicating, and an interrupted run can be
resumed without creating a second copy of everything.

The lexical (BM25) side is built at query time from the same chunk payloads,
so there is exactly one chunking pass and the two retrievers are guaranteed
to see an identical corpus — otherwise a hybrid comparison is meaningless.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path

from qdrant_client.http import models as qm
from rich.console import Console
from rich.progress import BarColumn, Progress, TextColumn, TimeRemainingColumn
from sqlalchemy import func, select

from bountybrain.clients import embeddings
from bountybrain.clients import qdrant as qc
from bountybrain.config import settings
from bountybrain.ingestion.chunker import chunk_text
from bountybrain.kg.db import Session
from bountybrain.kg.models import Document

console = Console()

CHUNK_CACHE = "chunks.jsonl"


@dataclass
class Chunk:
    chunk_id: str
    document_id: int
    chunk_idx: int
    text: str
    title: str
    url: str
    doc_type: str
    source: str
    published: str | None = None
    bounty: float | None = None
    external_id: str | None = None

    def payload(self) -> dict:
        return {
            "document_id": self.document_id,
            "chunk_idx": self.chunk_idx,
            "text": self.text,
            "title": self.title,
            "url": self.url,
            "doc_type": self.doc_type,
            "source": self.source,
            "published": self.published,
            "bounty": self.bounty,
            "external_id": self.external_id,
        }


def _chunk_id(document_id: int, idx: int) -> str:
    """Deterministic UUID-shaped id so re-indexing overwrites in place."""
    h = hashlib.sha1(f"{document_id}::{idx}".encode()).hexdigest()
    return f"{h[:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:32]}"


def iter_chunks(doc_types: list[str] | None = None) -> list[Chunk]:
    """Chunk every document in the graph."""
    out: list[Chunk] = []
    with Session() as s:
        stmt = select(Document)
        if doc_types:
            stmt = stmt.where(Document.doc_type.in_(doc_types))
        for d in s.execute(stmt).scalars():
            for i, text in enumerate(chunk_text(d.body)):
                out.append(
                    Chunk(
                        chunk_id=_chunk_id(d.id, i),
                        document_id=d.id,
                        chunk_idx=i,
                        text=text,
                        title=d.title,
                        url=d.url,
                        doc_type=d.doc_type,
                        source=d.source,
                        published=d.published.isoformat() if d.published else None,
                        bounty=d.bounty,
                        external_id=d.external_id,
                    )
                )
    return out


def save_chunk_cache(chunks: list[Chunk], path: Path | None = None) -> Path:
    """Persist chunks so BM25 can be built without re-reading the whole DB."""
    out = path or (Path(settings.corpus_cache_dir) / CHUNK_CACHE)
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", encoding="utf-8") as fh:
        for c in chunks:
            fh.write(json.dumps({"chunk_id": c.chunk_id, **c.payload()}) + "\n")
    return out


def load_chunk_cache(path: Path | None = None) -> list[dict]:
    src = path or (Path(settings.corpus_cache_dir) / CHUNK_CACHE)
    if not src.exists():
        return []
    with src.open(encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]


def build_index(
    doc_types: list[str] | None = None,
    recreate: bool = True,
    embed: bool = True,
) -> dict:
    """Chunk, embed and upsert the whole corpus."""
    console.print("[cyan]Chunking documents…[/cyan]")
    chunks = iter_chunks(doc_types)
    if not chunks:
        console.print("[red]No documents found — run build_graph.py first.[/red]")
        return {"chunks": 0, "embedded": 0}

    cache_path = save_chunk_cache(chunks)
    console.print(f"  {len(chunks):,} chunks from the corpus → {cache_path}")

    if not embed:
        return {"chunks": len(chunks), "embedded": 0, "cache": str(cache_path)}

    if not qc.ensure_collection(recreate=recreate):
        console.print("[yellow]Vector store unavailable; lexical search only.[/yellow]")
        return {"chunks": len(chunks), "embedded": 0, "cache": str(cache_path)}

    batch = max(1, settings.embed_batch_size)
    embedded = 0
    with Progress(
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("{task.completed:,}/{task.total:,}"),
        TimeRemainingColumn(),
        console=console,
    ) as progress:
        task = progress.add_task("embedding", total=len(chunks))
        for start in range(0, len(chunks), batch):
            window = chunks[start : start + batch]
            vectors = embeddings.embed_passages([c.text for c in window])
            qc.upsert_points(
                [
                    qm.PointStruct(id=c.chunk_id, vector=v, payload=c.payload())
                    for c, v in zip(window, vectors, strict=True)
                ]
            )
            embedded += len(window)
            progress.update(task, advance=len(window))

    stored = qc.count()
    console.print(f"[green]Indexed {embedded:,} chunks (store reports {stored:,})[/green]")
    return {
        "chunks": len(chunks),
        "embedded": embedded,
        "stored": stored,
        "cache": str(cache_path),
    }


def index_stats() -> dict:
    with Session() as s:
        docs = s.execute(select(func.count()).select_from(Document)).scalar_one()
    return {
        "documents": docs,
        "vectors": qc.count(),
        "cached_chunks": len(load_chunk_cache()),
    }
