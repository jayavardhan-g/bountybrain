"""Scale check: ingest N seed reports (rule-based only, no LLM, no embeddings)
and time each stage. Prints a small summary at the end.

    python scripts/scale_check.py            # uses whatever's in seed/reports.json
    python scripts/scale_check.py 500        # regenerates seed to 500 first
"""
from __future__ import annotations

import sys
import time
from pathlib import Path

from bountybrain.ingestion.pipeline import run
from bountybrain.kg.db import Session, init_db
from bountybrain.kg.models import Report
from bountybrain.kg.queries import corpus_stats
from bountybrain.rag.hybrid import search


def main() -> None:
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 0
    if n:
        # rebuild the seed corpus first
        import subprocess

        script = Path(__file__).parent / "build_seed_corpus.py"
        subprocess.check_call(["python", str(script), str(n)])

    print("→ ingesting seed corpus (no LLM, no embeddings)")
    t0 = time.time()
    result = run(sources=["seed"], limit_per_source=10_000, use_llm=False, embed=False)
    ingest_secs = time.time() - t0

    init_db()
    with Session() as s:
        n_reports = s.query(Report).count()

    stats = corpus_stats()

    print("→ warming BM25 index and running 3 sample queries")
    queries = ["SSRF metadata AWS", "IDOR increment order id", "GraphQL introspection admin"]
    q_times = []
    for q in queries:
        t0 = time.time()
        hits = search(q, top_k=5).hits
        q_times.append((q, time.time() - t0, len(hits)))

    print("\n=== SCALE CHECK ===")
    print(f"reports ingested this run : {result['ingested']}")
    print(f"reports in KG (total)     : {n_reports}")
    print(f"ingest wall-clock         : {ingest_secs:5.2f}s")
    print(f"vuln types in KG          : {len(stats['by_vuln'])}")
    print(f"years spanned             : {len(stats['by_year'])}")
    print()
    print("query latencies (BM25-only, no rerank warm-up):")
    for q, t, k in q_times:
        print(f"  {t*1000:6.1f}ms  hits={k}  '{q}'")


if __name__ == "__main__":
    main()
