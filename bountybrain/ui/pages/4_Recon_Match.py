from __future__ import annotations

import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

import streamlit as st

from bountybrain.recon import match_findings, parse_recon_file

st.title("🔎 Recon Match")
st.caption(
    "Upload output from your own recon tools. We parse them and match against "
    "the report corpus. No scanning is done here."
)

files = st.file_uploader(
    "Upload one or more files",
    accept_multiple_files=True,
    type=None,
)

tool_hint = st.selectbox(
    "Tool hint (optional)",
    ["auto", "subfinder", "amass", "httpx", "nuclei", "waybackurls", "gau", "wappalyzer", "csv"],
    index=0,
)

if files and st.button("Match", type="primary"):
    all_findings = []
    for f in files:
        with tempfile.NamedTemporaryFile(
            "wb", suffix=Path(f.name).suffix, delete=False
        ) as tf:
            tf.write(f.read())
            tmp = tf.name
        hint = None if tool_hint == "auto" else tool_hint
        all_findings.extend(parse_recon_file(tmp, tool_hint=hint))

    st.success(f"Parsed {len(all_findings)} findings.")
    grouped = match_findings(all_findings, top_k=5)
    for key, entries in grouped.items():
        st.subheader(key)
        for entry in entries:
            f = entry["finding"]
            st.markdown(f"**{f['type']}**: `{f['value']}` (tool: {f['source_tool']})")
            for m in entry["matches"]:
                bounty = f" · ${int(m['bounty'])}" if m.get("bounty") else ""
                st.markdown(
                    f"  • [{m['title']}]({m['url']}) — {m['reason']}{bounty}"
                )
