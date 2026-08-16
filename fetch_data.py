"""Download every external dataset.

    python fetch_data.py            # fetch anything missing
    python fetch_data.py --status   # show what is on disk
    python fetch_data.py --force    # re-fetch everything

All sources are bulk downloads (git repos or single archives) published under
open licences — see `bountybrain/datasets/registry.py` for the manifest with
per-source licence and attribution.
"""
from __future__ import annotations

import typer
from rich.console import Console
from rich.table import Table

from bountybrain.datasets.fetch import fetch_all
from bountybrain.datasets.registry import DATASETS, dataset_status

app = typer.Typer(add_completion=False, help="Fetch BountyBrain's source datasets")
console = Console()


@app.command()
def main(
    only: list[str] = typer.Option(
        None, "--only", help="Fetch just these datasets (repeatable)."
    ),
    force: bool = typer.Option(False, "--force", help="Re-fetch even if present."),
    status: bool = typer.Option(False, "--status", help="Show what is on disk and exit."),
) -> None:
    if status:
        table = Table(title="Datasets")
        table.add_column("name")
        table.add_column("present")
        table.add_column("size (MB)", justify="right")
        table.add_column("licence")
        total = 0.0
        for row in dataset_status():
            total += row["size_mb"]
            table.add_row(
                row["name"],
                "[green]yes[/green]" if row["present"] else "[red]no[/red]",
                f"{row['size_mb']:,.1f}",
                row["license"],
            )
        console.print(table)
        console.print(f"total on disk: {total:,.1f} MB")
        raise typer.Exit()

    names = list(only) if only else None
    valid = {d.name for d in DATASETS}
    if names:
        unknown = [n for n in names if n not in valid]
        if unknown:
            console.print(f"[red]Unknown dataset(s): {', '.join(unknown)}[/red]")
            console.print(f"Available: {', '.join(sorted(valid))}")
            raise typer.Exit(code=1)

    results = fetch_all(names=names, force=force)
    if not all(results.values()):
        raise typer.Exit(code=1)


if __name__ == "__main__":
    app()
