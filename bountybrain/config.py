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

    # LLM
    llm_provider: Literal["ollama", "openai", "anthropic"] = "ollama"
    llm_model: str = "qwen2.5:7b-instruct"
    llm_extraction_model: str = "qwen2.5:7b-instruct"
    llm_tutorial_model: str = "llama3.1:8b-instruct"
    ollama_base_url: str = "http://localhost:11434"
    openai_api_key: str | None = None
    anthropic_api_key: str | None = None

    # Embeddings / rerank
    embed_model: str = "BAAI/bge-small-en-v1.5"
    reranker_model: str = "BAAI/bge-reranker-base"

    # Qdrant
    qdrant_url: str = "http://localhost:6333"
    qdrant_collection: str = "bountybrain_reports"

    # Postgres
    database_url: str = (
        "postgresql+psycopg://bountybrain:bountybrain@localhost:5432/bountybrain"
    )

    # Web search
    brave_api_key: str | None = None

    # Runtime
    data_dir: Path = Field(default=Path("./data"))
    corpus_cache_dir: Path = Field(default=Path("./data/reports"))
    raw_cache_dir: Path = Field(default=Path("./data/raw"))
    log_level: str = "INFO"

    # Ingestion
    fetch_delay_seconds: float = 1.5
    max_reports_per_source: int = 250

    def ensure_dirs(self) -> None:
        for p in [self.data_dir, self.corpus_cache_dir, self.raw_cache_dir]:
            p.mkdir(parents=True, exist_ok=True)


settings = Settings()
settings.ensure_dirs()
