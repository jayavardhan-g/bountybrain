"""How often the graph can fill a complete learning path.

A path is *complete* when its first four stages — weakness, attack patterns,
disclosures, labs — are all non-empty. Each stage is counted twice: filled
directly by an edge on the class itself, or only by borrowing from a parent or
child. Reporting only the borrowed number would flatter thin classes.

Two populations:
    topics   the 30 fixed learner topics also used by the faithfulness suite
    all      every CWE class in the graph, most of which no learner asks about
"""
from __future__ import annotations

import json
from collections import Counter

from rich.console import Console
from sqlalchemy import select

from bountybrain.agent.path import learning_path
from bountybrain.config import settings
from bountybrain.eval.faithfulness import TOPICS
from bountybrain.kg.db import Session
from bountybrain.kg.models import Vulnerability

console = Console()
STAGES = ("weakness", "patterns", "writeups", "labs")


def _tally(paths: list[dict]) -> dict:
    n = len(paths)
    direct, filled = Counter(), Counter()
    complete_direct = complete_any = 0
    for p in paths:
        stages = {s["key"]: s for s in p["stages"]}
        ok_direct = ok_any = True
        for key in STAGES:
            has = bool(stages[key]["items"])
            is_direct = has and not stages[key]["inherited_from"]
            filled[key] += has
            direct[key] += is_direct
            ok_any &= has
            ok_direct &= is_direct
        complete_any += ok_any
        complete_direct += ok_direct

    def rate(x: int) -> float:
        return round(x / n, 4) if n else 0.0

    return {
        "n": n,
        "complete": rate(complete_any),
        "complete_direct_only": rate(complete_direct),
        "stage_filled": {k: rate(filled[k]) for k in STAGES},
        "stage_direct": {k: rate(direct[k]) for k in STAGES},
    }


def evaluate_and_save() -> dict:
    topic_paths = [p for p in (learning_path(t) for t in TOPICS) if p]
    with Session() as s:
        cwe_ids = s.execute(select(Vulnerability.cwe_id)).scalars().all()
    all_paths = [p for p in (learning_path(c) for c in cwe_ids) if p]

    result = {
        "topics": {
            **_tally(topic_paths),
            "unresolved": [t for t in TOPICS if not learning_path(t)],
            "incomplete": [
                p["topic"] for p in topic_paths if not p["complete"]
            ],
        },
        "all_classes": _tally(all_paths),
    }
    out = settings.artifact_dir / "eval_learning_path.json"
    out.write_text(json.dumps(result, indent=2))
    for name, r in (("topics", result["topics"]), ("all classes", result["all_classes"])):
        console.print(
            f"{name:12s} n={r['n']} complete={r['complete']:.3f} "
            f"direct-only={r['complete_direct_only']:.3f} filled={r['stage_filled']}"
        )
    console.print(f"[green]Wrote {out}[/green]")
    return result
