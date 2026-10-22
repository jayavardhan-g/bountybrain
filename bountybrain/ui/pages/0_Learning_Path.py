"""Learning path: an ordered study plan for one weakness class, from the graph."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

import streamlit as st

from bountybrain.agent.path import learning_path

st.set_page_config(page_title="Learning Path — BountyBrain", page_icon="🧭", layout="wide")
st.title("🧭 Learning path")
st.caption(
    "Weakness → how it is attacked → real disclosures → hands-on practice → what to "
    "learn next. Every step is an edge in the knowledge graph, not model output."
)

topic = st.text_input("What do you want to learn?", value="SSRF", placeholder="SSRF, IDOR, CWE-89…")

if topic.strip():
    path = learning_path(topic)
    if not path:
        st.warning("That did not resolve to a weakness class. Try a CWE number or a common name.")
        st.stop()

    st.success(f"Resolved to **{path['weakness']['key']}: {path['weakness']['name']}**")

    for step, stage in enumerate(path["stages"], start=1):
        st.subheader(f"{step}. {stage['title']}")
        st.caption(stage["why"])
        if stage["inherited_from"]:
            st.info(
                f"Nothing in the graph links directly to this class here, so these "
                f"come from the related class **{stage['inherited_from']}**.",
                icon="↪️",
            )
        items = stage["items"]
        if not items:
            st.caption("The graph has nothing for this step yet.")
            continue

        if stage["key"] == "weakness":
            w = items[0]
            st.markdown(f"[{w['key']}]({w['url']}) · abstraction: {w['abstraction'] or '—'}")
            if w["description"]:
                st.write(w["description"])
            if w["aliases"]:
                st.caption("Also known as: " + ", ".join(w["aliases"]))
            if w["parents"]:
                st.caption(
                    "Belongs to: " + ", ".join(f"{p['key']} {p['name']}" for p in w["parents"])
                )
        elif stage["key"] == "patterns":
            for t in items:
                with st.expander(
                    f"{t['key']}: {t['name']} — skill {t['min_skill'] or 'unrated'}, "
                    f"severity {t['typical_severity'] or '—'}"
                ):
                    for s in t["explore_steps"]:
                        st.markdown(f"- _Explore_ — {s}")
                    st.markdown(f"[{t['url']}]({t['url']})")
        elif stage["key"] == "writeups":
            for d in items:
                amount = f" — **${d['bounty']:,.0f}**" if d.get("bounty") else ""
                program = f" · {d['program']}" if d.get("program") else ""
                st.markdown(f"- [{d['title'][:100]}]({d['url']}){program}{amount}")
        elif stage["key"] == "labs":
            for lab in items:
                st.markdown(f"- [{lab['name']}]({lab['url']}) ({lab['provider']})")
        else:
            for n in items:
                st.markdown(f"- **{n['key']}** {n['name']} — _{n['relation']}_")
