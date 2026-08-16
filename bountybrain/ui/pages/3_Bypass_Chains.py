from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

import streamlit as st

from bountybrain.kg.db import Session
from bountybrain.kg.models import Vulnerability
from bountybrain.kg.queries import get_bypass_chain

st.title("⛓️ Bypass Chains")
st.caption("Timeline of patches and bypasses within a vulnerability class.")

with Session() as s:
    vulns = [v.name for v in s.query(Vulnerability).order_by(Vulnerability.name).all()]

vuln = st.selectbox("Vulnerability class", vulns, index=0 if vulns else None)
target = st.text_input("Filter by target tech (optional)")

if vuln and st.button("Show timeline"):
    chains = get_bypass_chain(vuln, target or None)
    if not chains:
        st.info("No bypass chains recorded for that selection yet.")
    for c in chains:
        r = c["report"]
        st.markdown(f"### [{r['title']}]({r['url']}) — {r.get('date','?')}")
        st.write("bypasses:")
        for b in c["bypassed"]:
            st.markdown(f"- [{b['title']}]({b['url']}) ({b.get('date','?')})")
