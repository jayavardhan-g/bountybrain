"""Learn: cited explanation of a vulnerability class, grounded in the corpus."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

import streamlit as st

from bountybrain.agent import tools
from bountybrain.kg import queries

st.set_page_config(page_title="Learn — BountyBrain", page_icon="📚", layout="wide")
st.title("📚 Learn")
st.caption("Every claim is cited to a retrieved passage. Nothing is answered from memory.")

topic = st.text_input("Topic", value="SSRF", placeholder="SSRF, IDOR, prototype pollution…")
col_a, col_b = st.columns([1, 3])
top_k = col_a.slider("Sources to retrieve", 3, 12, 6)
mode = col_b.selectbox(
    "Retrieval mode",
    ["hybrid_rerank", "hybrid", "dense", "bm25"],
    help="hybrid_rerank is the best-scoring configuration in the evaluation.",
)

if st.button("Explain", type="primary") and topic.strip():
    with st.spinner("Consulting the knowledge graph…"):
        context = tools.kg_context(topic)

    weakness = context.get("weakness")
    if weakness:
        st.success(f"Resolved to **{weakness['key']}: {weakness['name']}**")
        meta = st.columns(4)
        meta[0].metric("Abstraction", weakness.get("abstraction") or "—")
        meta[1].metric("Likelihood of exploit", weakness.get("likelihood") or "unrated")
        meta[2].metric(
            "VRT priority",
            f"P{weakness['vrt_priority']}" if weakness.get("vrt_priority") else "—",
        )
        meta[3].metric("Attack patterns", len(context.get("techniques") or []))
    else:
        st.info(
            "That topic did not resolve to a CWE class. Retrieval will still run "
            "over the corpus."
        )

    with st.spinner("Retrieving sources…"):
        rag = tools.local_rag_search(topic, top_k=top_k)

    if not rag["hits"]:
        st.error("No passages found. Have you run `python index_corpus.py`?")
    else:
        with st.spinner("Writing…"):
            tutorial = tools.generate_tutorial(topic, rag["hits"], context)
        st.markdown(tutorial)

        st.divider()
        st.subheader("Sources")
        for i, hit in enumerate(rag["hits"], start=1):
            with st.expander(f"[{i}] {hit['title']} — {hit['doc_type']} ({hit['score']})"):
                st.markdown(f"[{hit['url']}]({hit['url']})")
                st.text(hit["text"][:2000])

        if context.get("techniques"):
            st.subheader("Attack patterns (CAPEC)")
            for t in context["techniques"][:8]:
                st.markdown(
                    f"- [{t['key']}: {t['name']}]({t['url']}) — "
                    f"severity {t.get('typical_severity') or '—'}, "
                    f"min skill {t.get('min_skill') or '—'}"
                )

        if context.get("writeups"):
            st.subheader("Real disclosures")
            st.caption(
                "Expand a report to see others connected to it — same weakness "
                "class found elsewhere, or the same program yielding a different bug."
            )
            for d in context["writeups"]:
                amount = f" — **${d['bounty']:,.0f}**" if d.get("bounty") else ""
                program = f" · {d['program']}" if d.get("program") else ""
                with st.expander(f"{d['title']}{program}"):
                    st.markdown(f"[{d['url']}]({d['url']}){amount}")
                    related = queries.related_writeups(d["id"], limit=6)
                    if not related:
                        st.caption("No other report in the corpus connects to this one.")
                    for rel in related:
                        why = []
                        if rel["shared_weaknesses"]:
                            why.append(
                                "same class: "
                                + ", ".join(f"CWE-{c}" for c in rel["shared_weaknesses"])
                            )
                        if rel["shared_program"]:
                            why.append("same program")
                        amt = f" — ${rel['bounty']:,.0f}" if rel["bounty"] else ""
                        st.markdown(
                            f"- [{rel['title'][:90]}]({rel['url']}){amt}  \n"
                            f"  <sub>{' · '.join(why)}</sub>",
                            unsafe_allow_html=True,
                        )

        labs = tools.find_practice_labs(topic)
        if labs:
            st.subheader("Where to practise this")
            for lab in labs:
                st.markdown(f"- [{lab['name']}]({lab['url']}) ({lab['provider']})")
        elif weakness:
            st.caption(
                f"No curated practice lab for {weakness['key']} yet — "
                "see `bountybrain/agent/labs.py` to add one."
            )
