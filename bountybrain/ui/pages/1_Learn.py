from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

import streamlit as st

from bountybrain.agent import run_agent

st.title("📚 Learn")
st.write("Pick a topic (e.g. `SSRF`, `IDOR`, `GraphQL introspection`).")

topic = st.text_input("Topic", placeholder="SSRF")
if st.button("Generate tutorial", type="primary", disabled=not topic):
    with st.spinner("Retrieving and composing..."):
        state = run_agent(topic)
    st.markdown(state.get("report", "_no output_"))
    with st.expander("Retrieved sources"):
        for h in state.get("rag", {}).get("hits", []):
            st.markdown(f"**[{h['title']}]({h['url']})** — score {h['score']:.3f}")
            st.caption(h["text"][:400] + "...")
    web = state.get("web", []) or []
    if web:
        with st.expander("Live web results"):
            for w in web:
                st.markdown(f"**[{w['title']}]({w['url']})**")
                st.write(w.get("summary") or w.get("snippet") or "")
