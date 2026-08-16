# Setup

## Environment

| | |
|---|---|
| Conda env name | `bountybrain` |
| Python | 3.11.15 |
| Package manager | `mamba` / `pip` (miniforge3) |
| Env path | `$CONDA_PREFIX/envs/bountybrain` |

Created with:

```bash
mamba create -n bountybrain python=3.11 -y
conda activate bountybrain
pip install vllm                 # pins torch; install first
pip install -r requirements.txt
```

Key pinned versions actually installed:

| package | version |
|---|---|
| torch | 2.13.0+cu130 |
| vllm | 0.27.1 |
| transformers | 5.15.0 |
| sentence-transformers | (see `pip freeze`) |
| sqlalchemy | 2.x |
| networkx | 3.6.1 |
| numpy | 2.3.5 |

## Shared-machine notes

This was developed on a shared multi-user GPU server, which imposed two
constraints worth recording:

**Redirect temp.** The root filesystem was full and `/tmp` lives on it, so
pip's wheel extraction failed with `No space left on device`. Export a temp
directory on a volume you own before installing:

```bash
export TMPDIR=/path/you/own/tmp
export PIP_CACHE_DIR=/path/you/own/.cache/pip
```

**Pick a free GPU explicitly.** Never assume GPU 0 is idle. Check first and
set `CUDA_VISIBLE_DEVICES` to what is actually free:

```bash
nvidia-smi --query-gpu=index,memory.used,memory.total,utilization.gpu --format=csv
```

The project uses at most two GPUs: one serves the LLM via vLLM, one runs
embeddings and the cross-encoder reranker.

## Running the pipeline

```bash
python fetch_data.py                    # download all datasets (~1 GB, bulk only)
python build_graph.py --rebuild         # parse -> knowledge graph + metrics
python index_corpus.py                  # chunk + embed -> vector store
python serve_llm.py                     # start vLLM on a free GPU (optional)
python eval.py --all                    # run every evaluation suite
```

Steps 1–3 need no GPU and no LLM. Step 4's classification and
retrieval suites use the LLM if one is reachable and skip those arms
cleanly if not.

## Vector store

Qdrant runs **embedded** by default, writing to `./data/qdrant` — no server,
no port binding, which matters on a shared box. Set `QDRANT_URL` in `.env` to
use a standalone server instead.

## Knowledge graph store

SQLite by default (`./data/bountybrain.sqlite`). Set `DATABASE_URL` to point
at Postgres if you want concurrent writers.
