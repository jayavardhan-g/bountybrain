"""Chunk and embed the corpus into the vector store.

    python index_corpus.py                 # full rebuild
    python index_corpus.py --no-embed      # chunk only (builds the BM25 cache)
    python index_corpus.py --stats         # what is indexed right now

Requires `python build_graph.py` to have run first.
"""
from __future__ import annotations

import json

import typer
from rich.console import Console

from bountybrain.config import settings
from bountybrain.rag.index import build_index, index_stats

app = typer.Typer(add_completion=False, help="Build the BountyBrain retrieval index")
console = Console()


@app.command()
def main(
    embed: bool = typer.Option(True, "--embed/--no-embed", help="Compute embeddings."),
    recreate: bool = typer.Option(
        True, "--recreate/--append", help="Drop the existing collection first."
    ),
    doc_type: list[str] = typer.Option(
        None, "--doc-type", help="Restrict to these document types (repeatable)."
    ),
    stats: bool = typer.Option(False, "--stats", help="Show index stats and exit."),
) -> None:
    if stats:
        console.print(index_stats())
        raise typer.Exit()

    result = build_index(
        doc_types=list(doc_type) if doc_type else None,
        recreate=recreate,
        embed=embed,
    )
    out = settings.artifact_dir / "index_build.json"
    out.write_text(json.dumps(result, indent=2))
    console.print(f"[green]Wrote {out}[/green]")


if __name__ == "__main__":
    app()
