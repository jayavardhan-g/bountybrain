# Progress and handover

Status as of **2026-10-22**. Written so a fresh session can pick this up
without re-deriving context. Metrics live in [RESULTS.md](RESULTS.md);
environment gotchas in [SETUP.md](SETUP.md).

---

## Where the project stands

**Working end to end, and now shown to.** Corpus → knowledge graph → retrieval
index → evaluation → API and UI, all run against the real graph and a served
Qwen2.5-14B (`e2e.py` → `artifacts/e2e.json`). Every headline number in the
README is regenerated from `artifacts/` by `report.py`.

| area | state |
|---|---|
| Dataset fetchers (8 sources) | done, licensed, tested |
| Knowledge graph (111,896 nodes / 96,805 edges; core 35,278 / 63,340) | done; rebuilt 2026-10-22 with curated aliases persisted |
| Entity resolution (1,389 aliases, 93.1% coverage) | done; exact-alias resolution fixed 2026-10-22 |
| Chunking + hybrid retrieval (4 modes) | done, ablated, reproduced 2026-10-22 |
| Recon planner + per-host plans | done, beats baseline, reproduced 2026-10-22 |
| Classification evaluation | **fair comparison done** — keyword still wins; shortlist recall is the ceiling |
| Tutorial faithfulness evaluation | **done** — judge calibrated on 2×40 blind hand labels; prompt fixed (5.1% → 32.6% of sentences cited and supported) |
| Learning path (graph-ordered study plan, UI + `/path`) | **done** — complete for 25 of 29 learner topics |
| Streamlit UI (6 pages) | **run end to end** — 7/7 pages with the real model; live server 2/2 |
| FastAPI (13 routes) | **run end to end** — 13/13 checks over HTTP; warms retrieval at startup |
| Tests | 84, no network/GPU; smoke tests render every page and route |
| Lint | ruff clean |
| CI | workflow installs the smoke tests' deps now; still never executed on GitHub |

---

## Git

Work from 2026-10-22 is on branch **`upgrade-2026-10`**, pushed to origin.
`main` is untouched. Commit identity is `Jayavardhan
<jayavardhan.gollapalli@gmail.com>`.

---

## Rebuilding from scratch

Nothing derived is committed except the small JSON metrics and the eval
samples, so a clean machine needs the full pipeline. Steps 1–3 need **no GPU
and no LLM**.

```bash
mamba activate bountybrain                 # python 3.11.17 — see README for versions
python fetch_data.py                       # ~1 GB, ~5 min
python build_graph.py --rebuild            # ~1 min, writes artifacts/graph_metrics.json
python index_corpus.py                     # ~1 min on GPU
python serve_llm.py --gpu N                # minutes; far longer from a cold NFS cache (SETUP.md)
python eval.py --all
python report.py
```

If you change aliases or anything the candidate index embeds, `rm
data/corpus/cwe_candidates.npz` first: `build_candidate_index()` returns the
cached file unless forced, and a stale cache makes the change a silent no-op.

`data/` is gitignored in full. `artifacts/*.json(l)` and `*.md` are committed;
`artifacts/*.graphml` and `*.csv` are not.

---

## What to do next, in priority order

### 1. Mark uncited sentences in the Learn page

The faithfulness eval shows 45% of tutorial sentences cite nothing. The page
renders them exactly like cited ones. The splitter in
`bountybrain/eval/faithfulness.py` (`split_claims`) already finds them;
showing them dimmed or flagged is a small change and the most honest one
available. A regenerate-once when a tutorial has no citations at all would
also catch the worst case.

### 2. Improve CWE candidate retrieval, not the choosing model

Shortlist recall@12 is 0.45 (nuclei) / 0.53 (titles), and the LLM is 83% /
69% right whenever gold is on the list. Options, cheapest first: feed each
candidate's CWE description to the model rather than a bare name; rerank the
top 50 classes with the cross-encoder already in the stack; embed class texts
with the curated aliases weighted up. Measure shortlist recall first each
time — `eval.py --classification` reports it.

### 3. Fill the learning-path gaps

No curated lab for subdomain takeover, clickjacking or CRLF injection
(`bountybrain/agent/labs.py`); no CAPEC pattern for mass assignment; "NoSQL
injection" does not resolve because CWE-943's alternate term is stored as the
single string "NoSQL Injection, NoSQLi" — split alternate terms on ", " in
the CWE parser, behind a test, then rebuild.

### 4. Improve coverage where the planner is thin

Only 17.1% of weakness classes have a detection signature, so the planner is
strong on well-represented stacks and silent elsewhere. Map CAPEC
prerequisites onto recon-observable conditions, or add a second signature
source.

### 5. Optional polish

- A second judge model for the faithfulness eval (it currently judges its own
  generator), and a second human labeller.
- Screenshots of the Learning Path, Learn and Recon Planner pages for the
  README (no headless browser on this machine).
- Tune `SMOOTHING_ALPHA` and the planner weights — hand-set, never swept.
- Move the API's `on_event("startup")` to a lifespan handler (deprecated in
  FastAPI 0.136, still works).

---

## Design decisions worth not re-litigating

Recorded so they are not accidentally reversed:

- **Bulk-download only, never scrape.** The point is that anyone can reproduce
  the metrics. HackerOne was explicitly ruled out by the user.
- **pentester.land metadata only.** The 6,421 linked articles are on ~500
  third-party blogs and are deliberately not crawled.
- **SQLite + embedded Qdrant by default.** No servers, no ports to collide with
  on a shared machine; `git clone && build` reproduces the numbers anywhere.
- **No web-search tool.** An earlier Brave-backed version returned nothing
  silently without an API key, so the agent would claim to have searched and
  ground answers in nothing. Removed rather than left as a stub. There is no
  Brave key available.
- **Two GPUs maximum** (user constraint): one vLLM, one embeddings/reranker
  (on 2026-10-22 both shared a single GPU comfortably).
  `serve_llm.py` requests 40% of a card, not vLLM's 0.9 default.
- **Code fences are never split when chunking.** In this corpus a payload *is*
  the answer.
- **Negative results stay in the README.** The planner's earlier loss to the
  prior, and the LLM classifier's current loss to keyword, are both documented.

---

## Known environment traps

Full detail in [SETUP.md](SETUP.md); the short version, because each of these
cost real time:

1. Root filesystem is full — export `TMPDIR` somewhere you own before any pip
   install or archive extraction.
2. vLLM on Python 3.11 needs `--enforce-eager` **and** a one-line flashinfer
   patch (`array.array[int]` is 3.12-only). Python 3.12 avoids both. Still
   true on flashinfer 0.6.16.post3 (2026-10-22); `serve_llm.py` now passes
   `--enforce-eager` by default below 3.12, the patch is still manual.
3. Triton/Inductor caches cannot be created on GlusterFS — point them at local
   disk. `serve_llm.py` now does this automatically.
4. `ninja` must be on `PATH` or JIT compilation fails *after* the ten-minute
   weight load. `serve_llm.py` now handles this too.
5. Loading a 14B checkpoint from network storage took ~11 minutes at ~83s per
   shard in August. It is not hung. (It was much faster on 2026-10-22, with
   the weights freshly written to warm storage.)
6. vLLM 0.27 **silently ignores** `extra_body={"guided_json": …}` — no error,
   no warning, unconstrained output. Use `response_format` json_schema (the
   client does now).
7. `pkill -f <pattern>` / `pgrep -f` match the shell running them when the
   pattern is in its own command line, and kill your session. Find a server
   by its port (`ss -ltnp | grep :PORT`) and kill that PID.
8. PyPI downloads were throttled to ~200 kB/s at times while HF and
   download.pytorch.org were fast. torch is on
   `https://download.pytorch.org/whl/cu130`; the vLLM wheel is also on its
   GitHub release, byte-identical (check the sha256 against PyPI's JSON).

Only `/data/jayavardhan` and `/mnt/warm_storage/jayavardhan` belong to the
user on this shared machine. Nothing else may be written to.
