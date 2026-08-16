"""BountyBrain UI entrypoint.

Streamlit multi-page app; pages live under `pages/` and are auto-discovered.

    streamlit run bountybrain/ui/streamlit_app.py
"""
from __future__ import annotations

import sys
from pathlib import Path

# Importable without `pip install -e .`
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import streamlit as st

from bountybrain.kg.queries import corpus_summary

st.set_page_config(page_title="BountyBrain", page_icon="🐛", layout="wide")

st.title("🐛 BountyBrain")
st.caption(
    "A knowledge graph and retrieval system for learning bug bounty hunting — "
    "built on MITRE CWE/CAPEC, nuclei templates, Exploit-DB and 6.4k disclosed writeups."
)

try:
    summary = corpus_summary()
except Exception:
    summary = None

if summary:
    cols = st.columns(6)
    cols[0].metric("Weaknesses (CWE)", f"{summary['weaknesses']:,}")
    cols[1].metric("Attack patterns", f"{summary['techniques']:,}")
    cols[2].metric("Documents", f"{summary['documents']:,}")
    cols[3].metric("Detection templates", f"{summary['signatures']:,}")
    cols[4].metric("Public exploits", f"{summary['exploits']:,}")
    cols[5].metric("CVEs", f"{summary['cves']:,}")
else:
    st.warning(
        "No graph found. Run `python fetch_data.py` then `python build_graph.py --rebuild`."
    )

st.markdown(
    """
### Pages

| page | what it does |
|---|---|
| **Learn** | Ask about a vulnerability class; get a cited explanation grounded in the corpus. |
| **Explore** | Walk the CWE hierarchy — parents, children, attack patterns, real disclosures. |
| **Attack Chains** | Follow CAPEC `CanPrecede` edges to see how techniques chain together. |
| **Recon Planner** | Upload your own recon output; get a ranked, cited plan of what to test next. |
| **Metrics** | Graph structure, coverage, and evaluation results. |

### Scope and safety

BountyBrain **never scans anything**. It parses recon files *you* produced with
your own tools against targets you are authorised to test, and reasons over a
local knowledge graph. There is no network egress at query time.
"""
)

with st.expander("Where the data comes from"):
    st.markdown(
        """
Every source is bulk-downloadable and openly licensed — nothing is scraped:

| dataset | licence | role |
|---|---|---|
| MITRE CWE | MITRE Terms of Use | weakness taxonomy + hierarchy |
| MITRE CAPEC | MITRE Terms of Use | attack patterns + execution flows |
| nuclei-templates | MIT | detection signatures, CVSS/EPSS/CWE labels |
| Exploit-DB | GPL-2.0 | public exploit availability |
| pentester.land | public JSON feed (metadata only) | disclosed writeups + bounties |
| PayloadsAllTheThings | MIT | technique prose |
| OWASP WSTG | CC-BY-SA-4.0 | testing methodology |
| Bugcrowd VRT | Apache-2.0 | payout priority |
"""
    )
