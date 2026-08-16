"""Build the knowledge graph from the fetched datasets.

    python build_graph.py              # build (creates tables if needed)
    python build_graph.py --rebuild    # drop everything and rebuild
    python build_graph.py --metrics    # build, then write graph metrics

Requires `python fetch_data.py` to have run first.
"""
from __future__ import annotations

import json

import typer
from rich.console import Console

from bountybrain.config import settings
from bountybrain.kg.build import build
from bountybrain.kg.db import reset_db

app = typer.Typer(add_completion=False, help="Build the BountyBrain knowledge graph")
console = Console()


@app.command()
def main(
    rebuild: bool = typer.Option(
        False, "--rebuild", help="Drop all tables first (recommended after a data refresh)."
    ),
    metrics: bool = typer.Option(
        True, "--metrics/--no-metrics", help="Compute graph metrics after building."
    ),
) -> None:
    if rebuild:
        console.print("[yellow]Dropping existing tables[/yellow]")
        reset_db()

    stats = build()

    out = settings.artifact_dir / "graph_build.json"
    out.write_text(json.dumps(stats, indent=2))
    console.print(f"[green]Wrote {out}[/green]")

    if metrics:
        from bountybrain.kg.metrics import compute_and_save

        compute_and_save()


if __name__ == "__main__":
    app()
