# Results

Graph, retrieval and planner numbers were first produced on 2026-08-16 and
reproduced on 2026-10-22 in a rebuilt environment (same August datasets).
Classification (§3) was re-run on 2026-10-22 after the alias fix; §5–§7 are
new on 2026-10-22. Raw JSON for every table is in `artifacts/`, which is
committed precisely so these can be checked rather than taken on trust.

Reproduce with:

```bash
python fetch_data.py
python build_graph.py --rebuild     # graph + metrics
python index_corpus.py              # chunk + embed
python serve_llm.py                 # only needed for the LLM arms
python eval.py --all                # includes --faithfulness and --learning-path
python report.py                    # re-render the README tables
python e2e.py --api URL / --ui      # §7, against a running API / in-process pages
```

Environment: one H100-class GPU, shared by vLLM (Qwen2.5-14B-Instruct at 40%
memory, `--enforce-eager`) and the embedder (`bge-small-en-v1.5`) and reranker
(`bge-reranker-base`). Env `bountybrain`, Python 3.11.17, torch 2.13.0+cu130,
vllm 0.27.1 — full list in the README.

---

## 1. Corpus and knowledge graph

Built from eight bulk-downloaded, openly licensed datasets. No scraping.

| | count |
|---|---:|
| **Nodes** | **111,896** |
| **Edges** | **96,805** |
| exploit | 46,647 |
| CVE | 29,971 |
| signature (nuclei) | 13,569 |
| product | 10,901 |
| document (retrievable) | 9,224 |
| weakness (CWE) | 969 |
| technique (CAPEC) | 615 |

Documents by type: 6,397 disclosed writeup records · 1,243 prose articles ·
969 CWE pages · 615 CAPEC patterns. Chunked into **11,355** indexed passages.

### Structure

| metric | value |
|---|---|
| density | 1.55 × 10⁻⁵ |
| mean / median / max degree | 1.73 / 1.0 / 3,761 |
| connected components | 46,998 |
| largest component | 35,425 (31.7%) |
| isolated nodes | 24,905 |

The whole-graph figures look sparse, and that is honest rather than
disappointing: 77k of the 112k nodes are CVE and exploit records that no
nuclei template references, so they sit in two-node components. Excluding them
(`export_graph.py --core-only`, and `core_structure` in
`artifacts/graph_metrics.json`) leaves the part that carries the reasoning —
**35,278 nodes, 63,340 edges, mean degree 3.59**, largest component 32,457
nodes in 2,491 components.

### CWE taxonomy

10 pillar roots · 687 leaves · max depth 5 · mean leaf depth 2.58
(299 Variant, 539 Base, 114 Class, 10 Pillar, 7 Compound), from 1,441 typed
weakness→weakness edges.

### Coverage of the 969 weakness classes

| backed by | count | share |
|---|---:|---:|
| an observed CVE | 581 | 60.0% |
| an external document (writeup / article / CAPEC) | 365 | 37.7% |
| a CAPEC attack pattern | 336 | 34.7% |
| a nuclei detection signature | 166 | 17.1% |
| a disclosed bug bounty writeup | 89 | 9.2% |
| a Bugcrowd VRT payout priority | 57 | 5.9% |

"Has *any* document" is 100% by construction — every CWE has its own catalogue
page in the corpus — so it is excluded as meaningless.

### Entity resolution

**1,389 aliases → 969 classes**, from three layers: official CWE names,
official `Alternate_Terms` plus short names hidden in parentheticals, and 109
hand-curated community terms (IDOR, SSTI, WAF bypass, …).

Applied to pentester.land's 671 distinct curated labels this resolves **93.1%**
of vulnerability-labelled writeups (up from **76.5%** before the parenthetical
and curated layers). 22 labels are platform/engagement tags ("Android",
"Cloud", "Security code review") and are excluded from the denominator rather
than force-mapped.

### Economics (from disclosed bounties)

Best-paying weakness classes with ≥10 paid writeups:

| CWE | name | paid | mean | median | max |
|---|---|---:|---:|---:|---:|
| CWE-787 | Out-of-bounds Write | 30 | $42,326 | $20,000 | $215,000 |
| CWE-78 | OS Command Injection | 11 | $29,964 | $4,000 | $288,500 |
| CWE-94 | Code Injection | 134 | $21,184 | $5,550 | $288,500 |
| CWE-269 | Improper Privilege Management | 52 | $20,806 | $8,000 | $200,000 |
| CWE-89 | SQL Injection | 40 | $12,934 | $3,000 | $288,500 |
| CWE-918 | SSRF | 67 | $12,695 | $3,500 | $288,500 |

---

## 2. Retrieval — four-way ablation

200 model-generated queries over held-out passages, stratified across the four
document types. Queries are committed to `bountybrain/fixtures/retrieval_queries.json`.

Re-run 2026-10-22 (torch 2.13, transformers 5.20); the August run differed
only in dense R@5 (0.880), the third decimal of a few MRR/nDCG values, and
latency within a few ms.

| mode | R@1 | R@5 | R@10 | MRR | nDCG@10 | median ms |
|---|---:|---:|---:|---:|---:|---:|
| BM25 (lexical only) | 0.655 | 0.850 | 0.890 | 0.735 | 0.764 | 16 |
| dense (embeddings only) | 0.665 | 0.885 | 0.925 | 0.759 | 0.791 | 39 |
| hybrid (RRF fusion) | 0.675 | 0.910 | 0.955 | 0.773 | 0.809 | 56 |
| **hybrid + cross-encoder rerank** | **0.800** | **0.965** | **0.975** | **0.861** | **0.873** | 154 |

By document type (hybrid + rerank):

| document type | n | R@5 | MRR |
|---|---:|---:|---:|
| writeup | 50 | 1.000 | 0.952 |
| technique (CAPEC) | 50 | 0.980 | 0.881 |
| article | 50 | 0.940 | 0.794 |
| weakness (CWE) | 50 | 0.940 | 0.819 |

**Reading it.** Fusion buys little on its own (R@1 0.675 vs 0.665 dense) — the
two retrievers largely agree on *which* documents matter. The cross-encoder is
what pays: +0.125 R@1 over fusion, because the win is in *ordering* the
candidates, not in finding them. It costs ~3× latency, so the cheaper arms
remain the right default for bulk work.

**Caveats.**
- Relevance is known-item: only the source document counts, so genuinely
  relevant results from other documents are scored as misses. Absolute recall
  is a **lower bound**; the between-arm comparison is unaffected.
- Queries are LLM-generated with an instruction not to copy distinctive tokens.
  That instruction is not verified mechanically — some lexical overlap
  certainly survives, which flatters BM25.
- Writeup documents are short metadata records, which is why they score
  highest: less text, less ambiguity.

**Bug found and fixed here.** The first run reported nDCG@10 = 1.113. The ideal
DCG assumed a single relevant item, but a gold document is chunked and can
contribute several relevant hits. Normalising against all relevant hits found
fixes it (0.873). The impossible value is what exposed the bug.

---

## 3. CWE classification — a negative result, now on a fair comparison

**What changed.** The August run was confounded: `classify_keyword` read the
alias table straight from the CWE catalogue and so had all 109 curated
community terms (IDOR, SSTI, …), while `classify_embedding` and
`classify_llm` shortlist from `build_candidate_index()`, which embeds each
class from its *stored* `aliases_json` — and the builder never persisted the
curated layer. On 2026-10-22 the graph was rebuilt with the curated aliases
persisted, `data/corpus/cwe_candidates.npz` was deleted so the candidate index
was re-embedded from them, and classification was re-run. Same seed, same 500
items per gold set (the keyword arm's scores are bit-identical to August,
which confirms the pairing).

Two independent gold sets, identical inputs. `keyword→llm` is derived from the
other arms' predictions with no extra model calls: keyword when it fires, the
LLM only on keyword's abstentions.

**Gold set: nuclei templates** (name + description + impact)

| strategy | accuracy | hierarchy ±2 | macro F1 | abstained | accuracy when answered | August |
|---|---:|---:|---:|---:|---:|---:|
| keyword | 0.398 | 0.444 | 0.216 | 0.354 | 0.616 | 0.398 |
| llm | 0.374 | 0.456 | 0.105 | 0.290 | 0.527 | 0.368 |
| embedding | 0.210 | 0.314 | 0.050 | 0.000 | 0.210 | 0.184 |
| **keyword→llm** | **0.404** | 0.452 | 0.165 | 0.276 | 0.558 | — |

**Gold set: disclosed writeups** (title only)

| strategy | accuracy | hierarchy ±2 | macro F1 | abstained | accuracy when answered | August |
|---|---:|---:|---:|---:|---:|---:|
| keyword | 0.402 | 0.426 | 0.299 | 0.524 | 0.845 | 0.402 |
| llm | 0.364 | 0.416 | 0.168 | 0.356 | 0.565 | 0.280 |
| embedding | 0.330 | 0.412 | 0.102 | 0.000 | 0.330 | 0.188 |
| **keyword→llm** | **0.474** | 0.526 | 0.233 | 0.288 | 0.666 | — |

The LLM rows are from the run with constrained decoding actually in effect
(see defect table, `guided_json`). The run before that fix, otherwise
identical, gave 0.372 / 0.364 — within one item per set — with 0 model
failures in the fixed run.

**Reading it.**

- **Keyword still beats the LLM on both sets.** The confound was real and hit
  where predicted — writeup titles, where slang dominates: LLM +0.084,
  embedding +0.142. On nuclei prose it barely mattered (LLM +0.006).
- **The shortlist is the ceiling, not the model.** Embedding shortlist recall:

  | gold set | R@1 | R@5 | R@12 | R@20 | R@50 | hierarchy ±2 R@12 |
  |---|---:|---:|---:|---:|---:|---:|
  | nuclei | 0.210 | 0.372 | 0.450 | 0.508 | 0.622 | 0.618 |
  | writeup titles | 0.330 | 0.464 | 0.530 | 0.558 | 0.622 | 0.652 |

  The LLM chooses from the top 12. When gold is among them it is right
  **83.1%** (nuclei, n=225) / **68.7%** (titles, n=265) of the time; when it is
  not, it scores zero by construction and abstains 49% / 61% of the time. Even
  R@50 is only 0.62, so a bigger k alone will not fix it — the bi-encoder's
  class embeddings are the bottleneck.
- **Routing wins.** keyword→llm is the best arm on both sets: +0.006 over
  keyword on nuclei (one or two items — treat as a tie) and +0.072 on titles.
- **Macro F1 stays low for the LLM** (0.105 / 0.168 vs keyword 0.216 /
  0.299): it concentrates on common classes.

**A fairness problem with the writeup gold set** (unchanged). Its gold labels
are produced by applying the alias table to the curated `Bugs` field, while
the keyword baseline searches the *title* for entries from that same table.
The inputs differ, but the shared vocabulary hands the keyword arm — and so
keyword→llm — free wins whenever a title names the bug. **The nuclei set is
the fair comparison**, and there keyword, LLM and routing are within 0.03.

**What this changes.** Keyword (or keyword→llm) is the right default for bulk
CWE assignment. The next lever is candidate retrieval — feeding the shortlist
CWE descriptions or a cross-encoder over class texts — not the choosing model.

---

## 4. Recon planner — next-move ranking

400 held-out cases across 147 products. For each, 20% of a product's detection
templates are held out as gold **and excluded from the evidence pool**, so the
planner must generalise from the rest of the stack rather than being graded on
the fact it was handed.

| strategy | P@1 | P@3 | P@5 | P@10 | MRR |
|---|---:|---:|---:|---:|---:|
| **planner (value-weighted)** | **0.427** | 0.562 | 0.650 | 0.720 | 0.517 |
| planner (likelihood-only) | 0.422 | **0.570** | **0.662** | **0.738** | **0.522** |
| prior (global class frequency) | 0.325 | 0.532 | 0.598 | 0.720 | 0.445 |
| random | 0.095 | 0.282 | 0.440 | 0.720 | 0.245 |

**Beating the prior is the bar that matters** — it is what shows the planner
uses the recon fingerprint rather than the base rate of XSS being common. It
clears it by +31% relative on P@1 and +16% on MRR.

**A defect this evaluation caught.** The first version *lost* to the prior
(P@1 0.280 vs 0.325). Its applicability term was a log-scaled count of matching
templates, which saturates at 1.0 for any popular product — every ranking was
then decided by stack-independent terms. Replacing it with a smoothed
conditional estimate, P(weakness | product) shrunk toward the global prior by a
pseudo-count of 25, took P@1 from **0.280 → 0.427**.

**Value weighting costs ranking accuracy, as it should.** Likelihood-only is
slightly better at predicting the next finding (P@3 0.570 vs 0.562); the
value-weighted variant deliberately trades that to surface findings worth more.
Both are exposed in the UI; reporting only the flattering one would hide a real
trade-off.

**Residual leak, stated.** The global prior used for smoothing is computed over
all templates including held-out ones. That is ~5% of edges spread across
classes, and the `prior` baseline is computed the same way, so the comparison
stands — but the per-product evidence exclusion is the strict part, and this is
not.

---

## 5. Tutorial faithfulness — are the citations real?

`bountybrain/eval/faithfulness.py`, 30 fixed topics chosen before any tutorial
was generated, run through the Learn page's own path (graph context →
hybrid + rerank top 6 → tutorial prompt → Qwen2.5-14B). Each tutorial is split
into sentences deterministically; each `[n]` is checked against the sources
given (`invalid_citation_rate`); an LLM judge — the same Qwen2.5-14B — reads
only the cited excerpts, truncated exactly as the generator saw them, and
labels each cited sentence supported / partial / unsupported.

**The judge is calibrated, not trusted.** For each prompt, 40 judged
sentences were sampled (stratified on the judge's verdict, seed 7) and
labelled by hand **blind to the verdicts**, against the excerpts only. The
labeller was Claude (Opus 5.5), not the project owner. Labels and a one-line
reason for each are in `bountybrain/fixtures/faithfulness_handcheck*.json`.
Because the sample is stratified, the population estimate reweights each
judge bucket by its hand-supported share (`hand_calibrated_supported_rate`).

| | baseline prompt | current prompt |
|---|---:|---:|
| sentences | 530 | 424 |
| sentences carrying a citation | 13.2% | **54.5%** |
| citation numbers pointing at no source | 0 | 0 |
| judge, of cited: supported / partial / unsupported | 15.7% / 61.4% / 22.9% | 42.4% / 48.5% / 9.1% |
| hand-calibrated: cited sentences supported | 38.6% | **59.7%** |
| hand-calibrated: all sentences cited *and* supported | 5.1% | **32.6%** |

Files: `eval_faithfulness_v1.json` / `eval_faithfulness.json`, with the
samples, judged claims and blind sheets beside them.

**Judge vs hand labels** (n = 40 each):

| claims from | 3-way agreement | κ | supported-or-not agreement | κ | judge "supported" held | judge "unsupported" held |
|---|---:|---:|---:|---:|---:|---:|
| baseline prompt | 0.600 | 0.42 | 0.725 | 0.41 | 8/10 | 8/10 |
| current prompt | 0.825 | 0.71 | 0.875 | 0.75 | 20/20 | 6/6 |

The judge is **stricter than a careful reader**: its "partial" bucket is a
catch-all that, by hand, held 7 supported + 5 unsupported (baseline) and 5
supported + 2 unsupported (current). Its two confident labels are reliable.
Agreement is higher on the current prompt's claims, which cite real passages
more often; the baseline's cited the metadata-only writeup records more,
where judgement is harder.

**How the prompt was changed — and not tuned on the test set.** The baseline
showed two causes: the knowledge-graph summary was offered "for framing"
with no number, so facts from it went uncited (one SSRF tutorial attached the
class's top bounty, $288,500, to an unrelated metadata example); and the
citation rules sat above ~7k characters of sources. The current prompt makes
the graph summary the last numbered source and moves the rules, with an
example, after the sources. Iterated on 10 dev topics disjoint from the test
topics (`eval_faithfulness_dev_v1/v2/v3.json`):

| dev prompt | sentences | cited | judge-supported of cited | judge-unsupported of cited | supported of all |
|---|---:|---:|---:|---:|---:|
| baseline | 174 | 12.1% | 23.8% | 9.5% | 2.9% |
| v2: graph numbered, rules after sources | 142 | 58.5% | 36.1% | 16.9% | 21.1% |
| v3: + "no source numbers on the safety rule" | 140 | 51.4% | 47.2% | 8.3% | 24.3% |

v3 was frozen and the 30 test topics run once.

**Still wrong.** 45% of sentences cite nothing. Four of the eight
hand-unsupported sentences in the current sample are safety reminders the
model still tags with a source number. Each topic is one sample at
temperature 0, and vLLM output is not bit-stable under batching: the same
`/learn` request produced a cited tutorial in one run and an uncited one in
the next under the baseline prompt. Re-judging the same claims is not perfectly
repeatable either.

---

## 6. Learning path completeness

`bountybrain/agent/path.py` orders a study plan from graph edges — weakness →
CAPEC patterns, lowest skill first → disclosed writeups → labs → next — and
borrows from a parent or child class when a stage is empty, saying so.
`eval.py --learning-path` (`artifacts/eval_learning_path.json`):

| population | n | complete | complete without borrowing | has patterns | has writeups | has labs |
|---|---:|---:|---:|---:|---:|---:|
| the 30 learner topics (29 resolve) | 29 | **86.2%** | 69.0% | 96.5% | 100.0% | 89.7% |
| every CWE class | 969 | 16.2% | 2.5% | 66.7% | 31.2% | 16.4% |

The first measurement was lower because of a resolver bug it exposed (§8):
"SQL injection" resolved to the Hibernate variant. Remaining
gaps are real data gaps: no curated lab for subdomain takeover, clickjacking
or CRLF injection, and no CAPEC pattern for mass assignment. "NoSQL
injection" resolves to nothing because MITRE's alternate term for CWE-943 is
stored as one string, "NoSQL Injection, NoSQLi".

---

## 7. End to end

`e2e.py` against the real stack — built graph, Qdrant index, reranker,
Qwen2.5-14B on vLLM — writing `artifacts/e2e.json`:

| surface | passed | notes |
|---|---:|---|
| API over HTTP (uvicorn) | 13/13 | `/learn` must return a model tutorial with citations (9.1 s); `/search` 159 ms |
| Streamlit pages (AppTest, in-process) | 7/7 | Learn clicks Explain and must render a cited model tutorial (28.8 s) |
| live `streamlit run` | 2/2 | health endpoint + app shell |

The API now loads the embedder, reranker and BM25 index at startup, so it
takes longer to become healthy but the first `/search` is as fast as any
other. Before, the first user's `/search` paid the whole load — minutes, in
one-off timings on a cold network-storage cache.
AppTest cannot drive `st.file_uploader`, so the Recon Planner page is
checked for rendering and the plan itself through `/recon/plan`.
`tests/test_app_smoke.py` runs the same routes and pages in CI against a
fixture graph with retrieval and the model stubbed.

---

## 8. Defects found and fixed

Recorded because they are the substance of the work, not incidental:

| defect | consequence | fix |
|---|---|---|
| nDCG ideal assumed one relevant chunk | nDCG@10 = 1.113, impossible | normalise against all relevant hits found |
| planner applicability saturated at 1.0 | lost to the trivial prior baseline | smoothed conditional P(weakness \| product) |
| curated aliases never persisted to the graph | "IDOR" resolved nowhere in the UI/API, **and** the classification comparison was confounded — only the keyword baseline could see the curated vocabulary | builder merges the curated layer into `aliases_json` |
| chain walk followed `CanPrecede` only | CAPEC states half its links as `CanFollow`, so the Attack Chains page was empty for every topic | traverse both directions |
| nuclei `cve-id` is a string, not a list | `"CVE-2021-22205"` became 14 findings, one per character | normalise to a list before iterating |
| every parser grouped by registrable domain | GitLab and Jira hosts merged into one blended plan | carry `host`; plan per host |
| host spellings differ across tools | `git.acme.example` and `https://git.acme.example` became two assets | normalise at every assignment site |
| 6 curated aliases pointed at CWE-840/CWE-16 | those are *categories*, not weaknesses — dangling edges | remapped; a test now asserts every alias resolves |
| ExploitDB ships ~460 duplicate rows | `edb_id` UNIQUE constraint violation | de-duplicate in the loader |
| Qdrant closed from `__del__` at teardown | ImportError traceback after every successful run | deterministic `atexit` close |
| *2026-10-22* topic resolver fell from exact name straight to substring | "SQL injection" → CWE-564 (Hibernate), "path traversal" → CWE-24, "race condition" → CWE-1223 on every page and the API | exact alias match before the substring fallback |
| vLLM 0.27 silently ignores `extra_body={"guided_json": …}` | every "constrained" call decoded unconstrained; no error, so the fallback never fired (measured effect on classification: ≤0.002) | send `response_format` json_schema |
| async OpenAI client left to garbage collection | "Event loop is closed" traceback after every batch | close it inside its own loop |
| tutorial prompt: graph facts unnumbered, rules above the sources | 13.2% of sentences cited; graph facts used uncited and misattached | graph summary is a numbered source; rules after sources (§5) |
| Metrics page rebuilt the retrieval frame with `reset_index(names="mode")` | page crashed on the committed results: rows already carry `mode` | build the frame from the rows |
| first `/search` loaded three models lazily | the first user waited minutes on a cold cache | load at API startup |
| `serve_llm.py` never passed `--enforce-eager` | the documented Python 3.11 launch did not match the documented fix | on by default below 3.12 |
| `eval.py` overwrote `eval_summary.json` | running one suite erased the others' results | merge |

---

## 9. Honest limitations

- **Writeup bodies were never fetched.** Only pentester.land metadata is
  ingested. Writeup "documents" are short records, not article text.
- **Retrieval recall is a lower bound** (known-item relevance).
- **CWE classification is capped by candidate retrieval** — shortlist recall@12
  is 0.45 / 0.53 (§3). The writeup gold set shares vocabulary with the keyword
  arm.
- **Coverage is thin in places** — only 17.1% of weakness classes have a
  detection signature and 9.2% a disclosed writeup, which limits the planner to
  well-represented stacks.
- **Planner weights are hand-set, not learned.** The evaluation measures
  whether they work; it does not claim they are optimal.
- **Tutorial faithfulness is measured but modest**: 32.6% of sentences are
  cited and supported (hand-calibrated), 45% cite nothing (§5). The judge is
  the generator's own model; the hand labels are one labeller's (Claude's),
  40 per prompt; each topic is a single generation.
- **The Learn page does not mark uncited sentences.** A reader cannot yet see
  which sentences are backed — the obvious next product step.
