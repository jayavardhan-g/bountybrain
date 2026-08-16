from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

import pandas as pd
import streamlit as st

from bountybrain.kg.queries import corpus_stats

st.title("📊 Corpus stats")

s = corpus_stats()
st.metric("Total reports", s["total_reports"])

col1, col2 = st.columns(2)
with col1:
    st.subheader("By vulnerability")
    if s["by_vuln"]:
        df = pd.DataFrame(
            [{"vuln": k, "count": v} for k, v in s["by_vuln"].items()]
        ).sort_values("count", ascending=False)
        st.bar_chart(df.set_index("vuln"))
    else:
        st.info("Empty — run `python ingest.py` first.")

with col2:
    st.subheader("By year")
    if s["by_year"]:
        df = pd.DataFrame(
            [{"year": k, "count": v} for k, v in s["by_year"].items()]
        ).sort_values("year")
        st.bar_chart(df.set_index("year"))
    else:
        st.info("No dated reports yet.")
