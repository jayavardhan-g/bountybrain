"""Bulk security datasets that back the knowledge graph.

Every source here is *bulk-downloadable* and openly licensed — no scraping,
no rate limits, no ToS grey area. That is a deliberate design choice: it
means anyone can clone this repo, run `python fetch_data.py`, and reproduce
the exact corpus and the exact metrics reported in the README.

See `registry.DATASETS` for the manifest (url, license, attribution).
"""

from bountybrain.datasets.registry import DATASETS, Dataset, dataset_status

__all__ = ["DATASETS", "Dataset", "dataset_status"]
