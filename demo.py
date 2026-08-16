"""Three end-to-end queries. Run after `python ingest.py`.

    python demo.py
"""
from __future__ import annotations

import json

from rich.console import Console

from bountybrain.agent import run_agent
from bountybrain.agent.tools import get_bypass_chain, match_findings_to_kg, parse_recon_file
from bountybrain.kg.db import init_db

console = Console()


def main() -> None:
    init_db()

    console.rule("[bold]1) Learn about SSRF")
    state = run_agent("SSRF")
    console.print(state.get("report", "")[:1500] + "\n...")

    console.rule("[bold]2) Bypass chain for IDOR")
    chains = get_bypass_chain("IDOR")
    console.print(json.dumps(chains, indent=2)[:1000])

    console.rule("[bold]3) Recon match on a small fake httpx.jsonl")
    sample = "\n".join(
        [
            json.dumps({"url": "https://api.acme.com/", "host": "api.acme.com", "status_code": 200, "tech": ["rails", "nginx"]}),
            json.dumps({"url": "https://graphql.acme.com/graphql", "host": "graphql.acme.com", "tech": ["express"]}),
        ]
    )
    from pathlib import Path
    p = Path("/tmp/httpx_sample.jsonl")
    p.write_text(sample)
    findings = parse_recon_file(str(p), tool_hint="httpx")
    matches = match_findings_to_kg(findings, top_k=3)
    console.print(json.dumps(matches, indent=2)[:1500])


if __name__ == "__main__":
    main()
