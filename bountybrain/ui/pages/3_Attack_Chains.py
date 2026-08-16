"""Attack chains: follow CAPEC `CanPrecede` edges to see how steps compose."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

import streamlit as st

from bountybrain.kg import queries

st.set_page_config(page_title="Attack Chains — BountyBrain", page_icon="⛓️", layout="wide")
st.title("⛓️ Attack chains")
st.caption(
    "MITRE records which attack patterns can precede which. Walking those edges "
    "turns isolated techniques into multi-step routes."
)

term = st.text_input("Starting weakness", value="SSRF", placeholder="SSRF, XSS, CWE-89…")
depth = st.slider("Maximum chain length", 2, 5, 3)

if term.strip():
    weakness = queries.find_weakness(term)
    if not weakness:
        st.warning("No matching weakness.")
        st.stop()

    st.subheader(f"Starting from {weakness['key']}: {weakness['name']}")
    techniques = queries.techniques_for_weakness(weakness["cwe_id"])
    if not techniques:
        st.info("No CAPEC attack pattern maps to this weakness, so no chains exist.")
        st.stop()

    found_any = False
    for t in techniques:
        chains = queries.attack_chain(t["capec_id"], depth=depth)
        if not chains:
            continue
        found_any = True
        st.markdown(f"### From {t['key']}: {t['name']}")
        for chain in chains[:8]:
            steps = " → ".join(f"**{c['name']}** ({c['key']})" for c in chain)
            st.markdown(f"- {steps}")

    if not found_any:
        st.info(
            "The mapped attack patterns have no `CanPrecede` successors recorded. "
            "Try a broader class — chaining data is denser near the taxonomy roots."
        )

    st.divider()
    st.subheader("Execution flow of the primary pattern")
    primary = techniques[0]
    flow = primary.get("execution_flow") or []
    if flow:
        for phase in ("Explore", "Experiment", "Exploit"):
            steps = [s for s in flow if s.get("phase") == phase]
            if not steps:
                continue
            st.markdown(f"**{phase}**")
            for s in steps:
                st.markdown(f"- {s.get('description','')}")
                for technique in (s.get("techniques") or [])[:4]:
                    st.caption(f"    · {technique}")
    else:
        st.caption(f"{primary['key']} has no recorded execution flow.")
