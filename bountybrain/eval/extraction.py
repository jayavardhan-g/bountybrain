"""Extraction eval — per-field precision/recall on 20 hand-annotated bodies.

Only compares fields we can score cleanly: vuln_type (exact), tools_used,
target_tech, cve_ids (set-overlap). Fields like `techniques` are freeform
and left out.
"""
from __future__ import annotations

import json
from pathlib import Path

from bountybrain.ingestion.extractor import extract

GOLD = Path(__file__).resolve().parents[1] / "fixtures" / "extraction_gold.json"


def _prf(pred: set, gold: set) -> tuple[float, float, float]:
    if not gold and not pred:
        return 1.0, 1.0, 1.0
    tp = len(pred & gold)
    p = tp / len(pred) if pred else 0.0
    r = tp / len(gold) if gold else 0.0
    f = 2 * p * r / (p + r) if (p + r) else 0.0
    return p, r, f


def evaluate() -> dict:
    cases = json.loads(GOLD.read_text())
    scores: dict[str, list[tuple[float, float, float]]] = {
        "vuln_type": [],
        "tools_used": [],
        "target_tech": [],
        "cve_ids": [],
    }
    per_case = []
    for c in cases:
        pred = extract(c["title"], "seed://eval", c["body"], use_llm=False)
        p_data = pred.model_dump()
        row = {"title": c["title"]}
        for field in scores:
            g = c["gold"].get(field)
            p_val = p_data.get(field)
            if field == "vuln_type":
                match = (str(p_val).lower() == str(g).lower()) if g else True
                scores[field].append((float(match), float(match), float(match)))
                row[field] = {"pred": p_val, "gold": g, "match": match}
            else:
                p_set = {str(x).lower() for x in (p_val or [])}
                g_set = {str(x).lower() for x in (g or [])}
                p_, r_, f_ = _prf(p_set, g_set)
                scores[field].append((p_, r_, f_))
                row[field] = {"pred": sorted(p_set), "gold": sorted(g_set), "f1": f_}
        per_case.append(row)

    summary = {}
    for field, ss in scores.items():
        if not ss:
            continue
        p = sum(s[0] for s in ss) / len(ss)
        r = sum(s[1] for s in ss) / len(ss)
        f = sum(s[2] for s in ss) / len(ss)
        summary[field] = {"precision": p, "recall": r, "f1": f}
    return {"per_case": per_case, "summary": summary, "n": len(cases)}
