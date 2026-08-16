from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

import streamlit as st

from bountybrain.kg.db import Session
from bountybrain.kg.models import Report, Technique, Tool, Vulnerability
from bountybrain.kg.queries import kg_query

st.title("🕸️ Explore the knowledge graph")

with Session() as s:
    vulns = [v.name for v in s.query(Vulnerability).order_by(Vulnerability.name).all()]

col1, col2 = st.columns([1, 2])

with col1:
    st.subheader("Vulnerabilities")
    picked = st.radio("Pick one", vulns, index=0 if vulns else None)

with col2:
    if picked:
        st.subheader(f"Reports exploiting {picked}")
        rows = kg_query("vulnerability", picked, "reports")
        for r in rows:
            st.markdown(f"**[{r['title']}]({r['url']})**  ")
            meta = []
            if r.get("date"):
                meta.append(r["date"])
            if r.get("severity"):
                meta.append(f"sev: {r['severity']}")
            if r.get("bounty"):
                meta.append(f"${int(r['bounty'])}")
            st.caption(" · ".join(meta))

st.divider()
st.subheader("Graph view (simple)")
try:
    from streamlit_agraph import Config, Edge, Node, agraph

    nodes: list = []
    edges: list = []
    with Session() as s:
        for v in s.query(Vulnerability).limit(15).all():
            nodes.append(Node(id=f"v_{v.id}", label=v.name, color="#ef4444"))
        for t in s.query(Technique).limit(20).all():
            nodes.append(Node(id=f"t_{t.id}", label=t.name, color="#3b82f6"))
        for tl in s.query(Tool).limit(20).all():
            nodes.append(Node(id=f"tl_{tl.id}", label=tl.name, color="#10b981"))
    config = Config(width=900, height=500, directed=False, physics=True)
    agraph(nodes=nodes, edges=edges, config=config)
except Exception as e:  # pragma: no cover
    st.info(f"Graph viewer unavailable: {e}")
