"""Central config loaded from env / .env.

All modules import `settings` from here. Keeps env-lookup out of the code.
"""
from __future__ import annotations

from pathlib import Path
from typing import Literal

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # LLM. Default target is a local vLLM server speaking the OpenAI API;
    # `openai_base_url` points at it. Nothing leaves the machine.
    llm_provider: Literal["vllm", "ollama", "openai", "anthropic"] = "vllm"
    llm_model: str = "Qwen/Qwen2.5-14B-Instruct"
    llm_extraction_model: str = "Qwen/Qwen2.5-14B-Instruct"
    llm_tutorial_model: str = "Qwen/Qwen2.5-14B-Instruct"
    vllm_base_url: str = "http://localhost:8010/v1"
    vllm_api_key: str = "EMPTY"  # vLLM ignores it but the OpenAI client requires one
    ollama_base_url: str = "http://localhost:11434"
    openai_api_key: str | None = None
    openai_base_url: str | None = None
    anthropic_api_key: str | None = None
    # Concurrency for batch extraction against the local server.
    llm_max_concurrency: int = 32
    llm_timeout_seconds: float = 180.0

    # Embeddings / rerank
    embed_model: str = "BAAI/bge-small-en-v1.5"
    reranker_model: str = "BAAI/bge-reranker-base"

    # Vector store. `qdrant_path` runs Qdrant embedded against a local
    # directory — no server, no port to collide with on a shared machine.
    # Set `qdrant_url` to use a running server instead.
    qdrant_url: str | None = None
    qdrant_path: Path = Field(default=Path("./data/qdrant"))
    qdrant_collection: str = "bountybrain"
    embed_batch_size: int = 256
    embed_device: str = "cuda"

    # Knowledge graph store. SQLite by default: the whole graph is ~150 MB,
    # it needs no server, and it means `git clone && python build_graph.py`
    # reproduces the published metrics on any machine. Point DATABASE_URL at
    # Postgres instead if you want concurrent writers.
    database_url: str = "sqlite+pysqlite:///./data/bountybrain.sqlite"

    # Runtime
    data_dir: Path = Field(default=Path("./data"))
    corpus_cache_dir: Path = Field(default=Path("./data/corpus"))
    raw_cache_dir: Path = Field(default=Path("./data/raw"))
    artifact_dir: Path = Field(default=Path("./artifacts"))
    log_level: str = "INFO"

    def ensure_dirs(self) -> None:
        for p in [
            self.data_dir,
            self.corpus_cache_dir,
            self.raw_cache_dir,
            self.artifact_dir,
        ]:
            p.mkdir(parents=True, exist_ok=True)


settings = Settings()
settings.ensure_dirs()
