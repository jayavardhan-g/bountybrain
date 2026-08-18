"""Explore: walk the CWE hierarchy and everything attached to a weakness."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

import streamlit as st

from bountybrain.agent.labs import find_practice_labs
from bountybrain.kg import queries

st.set_page_config(page_title="Explore — BountyBrain", page_icon="🕸️", layout="wide")
st.title("🕸️ Explore the graph")
st.caption(
    "The CWE taxonomy is a real hierarchy, not a flat list of labels — "
    "parents, children, and 'can precede' chains are all traversable."
)

term = st.text_input("Find a weakness", value="SSRF", placeholder="SSRF, CWE-89, race condition…")

if term.strip():
    weakness = queries.find_weakness(term)
    if not weakness:
        st.warning("No match. Try a CWE number, an alias, or part of the name.")
        matches = queries.search_weaknesses(term, limit=10)
        if matches:
            st.write("Did you mean:")
            for m in matches:
                st.markdown(f"- **{m['key']}** {m['name']}")
        st.stop()

    st.header(f"{weakness['key']}: {weakness['name']}")
    cols = st.columns(4)
    cols[0].metric("Abstraction", weakness.get("abstraction") or "—")
    cols[1].metric("Likelihood", weakness.get("likelihood") or "unrated")
    cols[2].metric(
        "VRT priority", f"P{weakness['vrt_priority']}" if weakness.get("vrt_priority") else "—"
    )
    cols[3].markdown(f"[MITRE page]({weakness['url']})")

    if weakness.get("description"):
        st.write(weakness["description"])
    if weakness.get("aliases"):
        st.caption("Also known as: " + ", ".join(weakness["aliases"]))

    hierarchy = queries.weakness_hierarchy(weakness["cwe_id"])

    st.subheader("Position in the taxonomy")
    hcols = st.columns(3)
    with hcols[0]:
        st.markdown("**Parents (ChildOf)**")
        for p in hierarchy.get("parents", []) or [{"key": "—", "name": "root"}]:
            st.markdown(f"- {p.get('key')} {p.get('name','')}")
    with hcols[1]:
        st.markdown("**Children**")
        children = hierarchy.get("children", [])
        for c in children[:15]:
            st.markdown(f"- {c['key']} {c['name']}")
        if not children:
            st.caption("leaf node")
    with hcols[2]:
        st.markdown("**Peers**")
        peers = hierarchy.get("peers", [])
        for p in peers[:15]:
            st.markdown(f"- {p['key']} {p['name']}")
        if not peers:
            st.caption("none recorded")

    precede = hierarchy.get("can_precede", [])
    follow = hierarchy.get("can_follow", [])
    if precede or follow:
        st.subheader("Chaining")
        if follow:
            st.markdown("**Can follow from:** " + ", ".join(f"{p['key']}" for p in follow))
        if precede:
            st.markdown("**Can lead to:** " + ", ".join(f"{p['key']} {p['name']}" for p in precede))

    st.subheader("Attack patterns that exploit this")
    techniques = queries.techniques_for_weakness(weakness["cwe_id"])
    if techniques:
        for t in techniques:
            with st.expander(
                f"{t['key']}: {t['name']} — severity {t.get('typical_severity') or '—'}, "
                f"min skill {t.get('min_skill') or '—'}"
            ):
                st.write(t.get("description", ""))
                if t.get("prerequisites"):
                    st.markdown("**Prerequisites**")
                    for p in t["prerequisites"][:6]:
                        st.markdown(f"- {p}")
                flow = t.get("execution_flow") or []
                if flow:
                    st.markdown("**Execution flow**")
                    for step in flow:
                        st.markdown(f"- _{step.get('phase')}_ — {step.get('description','')}")
                st.markdown(f"[{t['url']}]({t['url']})")
    else:
        st.caption("No CAPEC pattern maps to this weakness.")

    st.subheader("Disclosed writeups")
    writeups = queries.documents_for_weakness(weakness["cwe_id"], limit=20, doc_type="writeup")
    if writeups:
        st.dataframe(
            [
                {
                    "title": d["title"][:80],
                    "program": d["program"],
                    "bounty": d["bounty"],
                    "published": d["published"],
                    "url": d["url"],
                }
                for d in writeups
            ],
            use_container_width=True,
            hide_index=True,
            column_config={"url": st.column_config.LinkColumn("link")},
        )
    else:
        st.caption("No disclosed writeups in the corpus map to this class.")

    labs = find_practice_labs(weakness["cwe_id"])
    if labs:
        st.subheader("Where to practise this")
        for lab in labs:
            st.markdown(f"- [{lab['name']}]({lab['url']}) ({lab['provider']})")
