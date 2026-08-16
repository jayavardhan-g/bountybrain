"""Recon planner: upload your own recon output, get a ranked plan.

Nothing here scans. You run your own tools against targets you are authorised
to test; this page parses the files you produced and reasons over the graph.
"""
from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

import streamlit as st

from bountybrain.recon.parsers import parse_recon_file
from bountybrain.recon.planner import (
    LIKELIHOOD_ONLY,
    ScoringWeights,
    plan_from_findings,
    render_markdown,
)

st.set_page_config(page_title="Recon Planner — BountyBrain", page_icon="🎯", layout="wide")
st.title("🎯 Recon planner")
st.caption(
    "Upload output from subfinder, amass, httpx, nuclei, waybackurls, gau, "
    "wappalyzer or a CSV. BountyBrain never scans anything itself."
)

st.info(
    "**Authorised testing only.** Use this against targets that are explicitly "
    "in scope for a program you are permitted to test.",
    icon="⚠️",
)

uploads = st.file_uploader(
    "Recon output files",
    accept_multiple_files=True,
    type=["txt", "json", "jsonl", "csv", "out", "log"],
)
tool_hint = st.selectbox(
    "Tool hint (optional)",
    ["auto-detect", "subfinder", "amass", "httpx", "nuclei", "waybackurls", "gau", "wappalyzer", "csv"],
)

col1, col2 = st.columns(2)
objective = col1.radio(
    "Ranking objective",
    ["Value-weighted", "Likelihood only"],
    help=(
        "Value-weighted blends in bounty economics and exploitability. "
        "Likelihood-only ranks purely by what this stack is most likely to expose — "
        "it scores slightly better on the held-out ranking evaluation."
    ),
)
top_k = col2.slider("Weakness classes per asset", 3, 15, 8)

if uploads and st.button("Build plan", type="primary"):
    findings = []
    with tempfile.TemporaryDirectory() as tmp:
        for up in uploads:
            path = Path(tmp) / up.name
            path.write_bytes(up.getvalue())
            hint = None if tool_hint == "auto-detect" else tool_hint
            try:
                findings.extend(parse_recon_file(path, tool_hint=hint))
            except Exception as e:  # noqa: BLE001
                st.warning(f"Could not parse {up.name}: {e}")

    if not findings:
        st.error("No findings parsed from those files.")
        st.stop()

    st.success(f"Parsed {len(findings):,} findings across {len({f.target for f in findings})} assets.")
    by_type: dict[str, int] = {}
    for f in findings:
        by_type[f.type] = by_type.get(f.type, 0) + 1
    st.write(by_type)

    weights = LIKELIHOOD_ONLY if objective == "Likelihood only" else ScoringWeights()
    with st.spinner("Matching against the knowledge graph…"):
        plans = plan_from_findings(findings, top_k=top_k, weights=weights)

    if not plans:
        st.warning(
            "No asset had a recognised technology or CVE. The planner needs "
            "fingerprints (httpx `-tech-detect`, wappalyzer) or CVE ids to work from."
        )
        st.stop()

    for plan in plans:
        st.header(plan.asset)
        if plan.technologies:
            st.caption("Fingerprinted: " + ", ".join(plan.technologies))
        if plan.unmatched_technologies:
            st.caption("Not in graph: " + ", ".join(plan.unmatched_technologies[:12]))

        if not plan.recommendations:
            st.info("No weakness classes matched this stack.")
            continue

        st.dataframe(
            [
                {
                    "CWE": f"CWE-{r.cwe_id}",
                    "weakness": r.name[:60],
                    "score": r.score,
                    "max EPSS": r.max_epss,
                    "public exploits": r.exploit_count,
                    "median bounty": r.median_bounty,
                    "templates": r.signature_count,
                    "writeups": r.writeup_count,
                }
                for r in plan.recommendations
            ],
            use_container_width=True,
            hide_index=True,
        )

        for r in plan.recommendations[:3]:
            with st.expander(f"What to try: CWE-{r.cwe_id} {r.name}"):
                st.caption(f"score components: {r.components}")
                if r.next_steps:
                    for step in r.next_steps:
                        st.markdown(f"**{step.phase}** — {step.description}")
                        for t in step.techniques:
                            st.caption(f"· {t}")
                        if step.capec_url:
                            st.caption(f"source: [{step.capec}]({step.capec_url})")
                else:
                    st.caption("No CAPEC execution flow recorded for this class.")

                if r.evidence.signatures:
                    st.markdown("**Detection templates**")
                    for sig in r.evidence.signatures:
                        st.markdown(f"- [{sig['name']}]({sig['url']}) — {sig['severity']}")
                if r.evidence.writeups:
                    st.markdown("**Prior disclosures**")
                    for wu in r.evidence.writeups:
                        amt = f" — ${wu['bounty']:,.0f}" if wu["bounty"] else ""
                        st.markdown(f"- [{wu['title'][:80]}]({wu['url']}){amt}")

    st.divider()
    markdown = render_markdown(plans)
    st.download_button(
        "Download plan as markdown",
        markdown,
        file_name="bountybrain_plan.md",
        mime="text/markdown",
    )
    st.download_button(
        "Download plan as JSON",
        json.dumps([p.to_dict() for p in plans], indent=2, default=str),
        file_name="bountybrain_plan.json",
        mime="application/json",
    )
