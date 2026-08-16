"""Run all three eval suites and save results to eval_results.json.

    python eval.py
"""
from __future__ import annotations

import json
from pathlib import Path

from rich.console import Console
from rich.table import Table

from bountybrain.eval import extraction, faithfulness, retrieval
from bountybrain.kg.db import init_db

console = Console()

OUT = Path("eval_results.json")


def main() -> None:
    init_db()
    results = {}

    console.rule("[bold cyan]Retrieval")
    r = retrieval.evaluate()
    results["retrieval"] = r
    console.print(f"n={r['n']}  recall@5={r['recall@5']:.3f}  MRR={r['mrr']:.3f}")

    console.rule("[bold cyan]Extraction")
    x = extraction.evaluate()
    results["extraction"] = x
    tbl = Table(title="Per-field")
    tbl.add_column("field")
    tbl.add_column("P")
    tbl.add_column("R")
    tbl.add_column("F1")
    for k, v in x["summary"].items():
        tbl.add_row(k, f"{v['precision']:.3f}", f"{v['recall']:.3f}", f"{v['f1']:.3f}")
    console.print(tbl)

    console.rule("[bold cyan]Faithfulness")
    f = faithfulness.evaluate(n=5)  # keep short by default
    results["faithfulness"] = f
    console.print(f"mean faithfulness = {f['mean_faithfulness']:.3f}")

    OUT.write_text(json.dumps(results, indent=2))
    console.print(f"[green]Wrote {OUT}[/green]")


if __name__ == "__main__":
    main()
