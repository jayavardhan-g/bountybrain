"""Pluggable LLM client.

Default provider is Ollama (local, free). OpenAI and Anthropic can be
selected by env var. All prompts are loaded from files under `prompts/`.

We expose two entry points:
  - `chat(system, user, model=None)`  -> free-form text
  - `structured(schema, system, user, model=None)` -> validated Pydantic

`structured` uses `instructor` for JSON-mode extraction where available;
otherwise it asks the model to return raw JSON and validates it manually.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, TypeVar

from pydantic import BaseModel, ValidationError

from bountybrain.config import settings

PROMPTS_DIR = Path(__file__).resolve().parents[2] / "prompts"

T = TypeVar("T", bound=BaseModel)


def load_prompt(name: str, **kwargs: Any) -> str:
    text = (PROMPTS_DIR / f"{name}.md").read_text(encoding="utf-8")
    return text.format(**kwargs)


class LLMError(RuntimeError):
    pass


def chat(system: str, user: str, model: str | None = None) -> str:
    """One-shot chat completion. Returns raw text."""
    model = model or settings.llm_model
    provider = settings.llm_provider
    if provider == "ollama":
        return _ollama_chat(system, user, model)
    if provider == "openai":
        return _openai_chat(system, user, model)
    if provider == "anthropic":
        return _anthropic_chat(system, user, model)
    raise LLMError(f"Unknown provider: {provider}")


def structured(
    schema: type[T], system: str, user: str, model: str | None = None
) -> T:
    """Return an instance of `schema` populated by the LLM.

    Falls back to raw JSON parsing if `instructor` isn't installed for the
    given provider. Retries once on validation failure with an "invalid JSON,
    please fix" nudge.
    """
    raw = chat(
        system + "\n\nReply with valid JSON only, matching the requested schema.",
        user,
        model=model,
    )
    try:
        return schema.model_validate_json(_extract_json(raw))
    except (ValidationError, json.JSONDecodeError):
        raw2 = chat(
            system,
            user + "\n\nYour previous reply was invalid JSON. Return valid JSON only.",
            model=model,
        )
        return schema.model_validate_json(_extract_json(raw2))


# --- providers ---


def _ollama_chat(system: str, user: str, model: str) -> str:
    try:
        import ollama
    except ImportError as e:  # pragma: no cover
        raise LLMError("`ollama` package not installed") from e
    client = ollama.Client(host=settings.ollama_base_url)
    resp = client.chat(
        model=model,
        messages=[
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
        options={"temperature": 0.2},
    )
    return resp["message"]["content"]


def _openai_chat(system: str, user: str, model: str) -> str:
    from openai import OpenAI

    if not settings.openai_api_key:
        raise LLMError("OPENAI_API_KEY not set")
    client = OpenAI(api_key=settings.openai_api_key)
    resp = client.chat.completions.create(
        model=model,
        messages=[
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
        temperature=0.2,
    )
    return resp.choices[0].message.content or ""


def _anthropic_chat(system: str, user: str, model: str) -> str:
    import anthropic

    if not settings.anthropic_api_key:
        raise LLMError("ANTHROPIC_API_KEY not set")
    client = anthropic.Anthropic(api_key=settings.anthropic_api_key)
    resp = client.messages.create(
        model=model,
        system=system,
        messages=[{"role": "user", "content": user}],
        max_tokens=4096,
    )
    parts = [b.text for b in resp.content if hasattr(b, "text")]
    return "".join(parts)


def _extract_json(text: str) -> str:
    """Grab the first {...} JSON block from text. Handles fenced code."""
    t = text.strip()
    if t.startswith("```"):
        # strip fences
        t = t.strip("`")
        if t.startswith("json"):
            t = t[4:]
        t = t.strip()
    start = t.find("{")
    end = t.rfind("}")
    if start == -1 or end == -1:
        return text
    return t[start : end + 1]
