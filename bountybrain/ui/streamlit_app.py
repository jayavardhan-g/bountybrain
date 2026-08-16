"""BountyBrain UI entrypoint.

Streamlit multi-page app. Individual pages live under `pages/` and
are auto-discovered by Streamlit.
"""
from __future__ import annotations

import sys
from pathlib import Path

# Make the project root importable without needing `pip install -e .`
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import streamlit as st

st.set_page_config(page_title="BountyBrain", page_icon="🐛", layout="wide")

st.title("🐛 BountyBrain")
st.caption(
    "A research assistant for beginner bug bounty hunters — "
    "RAG + knowledge graph over disclosed reports."
)

st.markdown(
    """
Use the sidebar to navigate:

- **Learn** — generate a beginner-friendly tutorial on a vuln topic.
- **Explore** — walk the knowledge graph.
- **Bypass Chains** — timeline of patches and bypasses for a vuln class.
- **Recon Match** — upload your recon output; get matched reports.
- **Corpus Stats** — what's indexed.

This tool does **not** run scanning against arbitrary targets.
"""
)
