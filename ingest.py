"""CLI entrypoint: python ingest.py --source seed --limit 100

By default only the bundled seed corpus is ingested — safe, no network.
Add `--source pentesterland` etc. to pull live reports.
"""
from __future__ import annotations

import typer

from bountybrain.ingestion.pipeline import run

app = typer.Typer(add_completion=False, help="Ingest reports into KG + vector store")


@app.command()
def ingest(
    source: list[str] = typer.Option(
        ["seed"],
        "--source",
        help="Sources to pull from. Repeat flag for multiple. "
        "Options: seed | pentesterland | portswigger | hackerone",
    ),
    limit: int = typer.Option(250, help="Max reports per source"),
    no_llm: bool = typer.Option(False, help="Skip LLM extraction, use rules only"),
    no_embed: bool = typer.Option(False, help="Skip embedding step"),
) -> None:
    run(sources=source, limit_per_source=limit, use_llm=not no_llm, embed=not no_embed)


if __name__ == "__main__":
    app()
