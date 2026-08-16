"""Pluggable LLM client.

Default provider is **vllm**: a local vLLM server speaking the OpenAI API.
Nothing leaves the machine, and vLLM's continuous batching makes classifying
tens of thousands of documents practical (throughput is roughly two orders of
magnitude better than sequential calls to a naive local server).

Entry points:
    chat(system, user)                  -> text
    structured(schema, system, user)    -> validated pydantic model
    achat_many(requests)                -> concurrent batch, order preserved
    structured_many(schema, requests)   -> concurrent batch, validated

Structured output uses vLLM's **guided decoding** (`guided_json`) where
available, which constrains generation to the schema at the token level.
That removes the whole class of "model returned prose around the JSON"
failures rather than trying to repair them after the fact; the manual
`_extract_json` path remains as a fallback for providers without it.
"""
from __future__ import annotations

import asyncio
import json
import re
from pathlib import Path
from typing import Any, Sequence, TypeVar

from pydantic import BaseModel, ValidationError

from bountybrain.config import settings

PROMPTS_DIR = Path(__file__).resolve().parents[2] / "prompts"

T = TypeVar("T", bound=BaseModel)


class LLMError(RuntimeError):
    pass


def load_prompt(name: str, **kwargs: Any) -> str:
    """Load a prompt template and substitute `{placeholders}`.

    Uses an explicit replace rather than `str.format` because these templates
    embed JSON schemas full of literal braces.
    """
    text = (PROMPTS_DIR / f"{name}.md").read_text(encoding="utf-8")
    for key, value in kwargs.items():
        text = text.replace("{" + key + "}", str(value))
    return text


# --------------------------------------------------------------------------
# client construction
# --------------------------------------------------------------------------


def _openai_style_client(async_client: bool = False):
    """Build an OpenAI SDK client pointed at whichever backend is configured."""
    provider = settings.llm_provider
    if provider == "vllm":
        base_url, api_key = settings.vllm_base_url, settings.vllm_api_key
    elif provider == "openai":
        base_url, api_key = settings.openai_base_url, settings.openai_api_key
        if not api_key:
            raise LLMError("OPENAI_API_KEY is not set")
    else:
        raise LLMError(f"{provider} does not use the OpenAI client")

    try:
        from openai import AsyncOpenAI, OpenAI
    except ImportError as e:  # pragma: no cover
        raise LLMError("openai package not installed") from e

    kwargs: dict[str, Any] = {"api_key": api_key, "timeout": settings.llm_timeout_seconds}
    if base_url:
        kwargs["base_url"] = base_url
    return (AsyncOpenAI if async_client else OpenAI)(**kwargs)


def is_available() -> bool:
    """Cheap liveness probe so callers can degrade instead of erroring."""
    provider = settings.llm_provider
    try:
        if provider in ("vllm", "openai"):
            _openai_style_client().models.list()
            return True
        if provider == "ollama":
            import ollama

            ollama.Client(host=settings.ollama_base_url).list()
            return True
        if provider == "anthropic":
            return bool(settings.anthropic_api_key)
    except Exception:
        return False
    return False


# --------------------------------------------------------------------------
# single-shot
# --------------------------------------------------------------------------


def chat(
    system: str,
    user: str,
    model: str | None = None,
    temperature: float = 0.0,
    max_tokens: int = 1024,
) -> str:
    model = model or settings.llm_model
    provider = settings.llm_provider

    if provider in ("vllm", "openai"):
        client = _openai_style_client()
        resp = client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            temperature=temperature,
            max_tokens=max_tokens,
        )
        return resp.choices[0].message.content or ""

    if provider == "ollama":
        return _ollama_chat(system, user, model, temperature)
    if provider == "anthropic":
        return _anthropic_chat(system, user, model, max_tokens)
    raise LLMError(f"Unknown provider: {provider}")


def structured(
    schema: type[T],
    system: str,
    user: str,
    model: str | None = None,
    temperature: float = 0.0,
    max_tokens: int = 1024,
) -> T:
    """Return an instance of `schema`, using guided decoding when available."""
    model = model or settings.llm_extraction_model
    provider = settings.llm_provider

    if provider in ("vllm", "openai"):
        client = _openai_style_client()
        kwargs: dict[str, Any] = {}
        if provider == "vllm":
            kwargs["extra_body"] = {"guided_json": schema.model_json_schema()}
        else:
            kwargs["response_format"] = {"type": "json_object"}
        resp = client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            temperature=temperature,
            max_tokens=max_tokens,
            **kwargs,
        )
        raw = resp.choices[0].message.content or ""
        return schema.model_validate_json(_extract_json(raw))

    raw = chat(
        system + "\n\nReply with valid JSON only, matching the requested schema.",
        user,
        model=model,
        temperature=temperature,
        max_tokens=max_tokens,
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


# --------------------------------------------------------------------------
# batch
# --------------------------------------------------------------------------


async def _abatch(
    requests: Sequence[tuple[str, str]],
    model: str,
    schema: type[BaseModel] | None,
    temperature: float,
    max_tokens: int,
    concurrency: int,
    progress_cb=None,
) -> list[str | None]:
    """Fire `requests` concurrently, preserving input order.

    A failed request yields None rather than aborting the batch — over tens of
    thousands of documents a handful will hit a context limit or a decode
    error, and losing the whole run to one of them is not acceptable.
    """
    client = _openai_style_client(async_client=True)
    sem = asyncio.Semaphore(concurrency)
    results: list[str | None] = [None] * len(requests)
    done = 0
    lock = asyncio.Lock()

    # Guided decoding constrains generation to the schema at the token level.
    # The parameter name has moved between vLLM releases, so if the server
    # rejects it we fall back to unconstrained decoding plus `_extract_json`
    # rather than losing the whole batch. `guided_ok` is flipped once, on the
    # first rejection, so the remaining requests skip straight to the fallback.
    extra: dict[str, Any] = {}
    if schema is not None and settings.llm_provider == "vllm":
        extra["extra_body"] = {"guided_json": schema.model_json_schema()}
    guided_ok = {"value": bool(extra)}

    async def _call(system: str, user: str, use_guided: bool):
        kwargs = dict(extra) if (use_guided and extra) else {}
        return await client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            temperature=temperature,
            max_tokens=max_tokens,
            **kwargs,
        )

    async def one(i: int, system: str, user: str) -> None:
        nonlocal done
        async with sem:
            try:
                try:
                    resp = await _call(system, user, guided_ok["value"])
                except Exception as e:  # noqa: BLE001
                    if not guided_ok["value"]:
                        raise
                    text = str(e).lower()
                    if "guided" not in text and "structured" not in text and "extra" not in text:
                        raise
                    guided_ok["value"] = False
                    resp = await _call(system, user, False)
                results[i] = resp.choices[0].message.content or ""
            except Exception:
                results[i] = None
            finally:
                async with lock:
                    done += 1
                    if progress_cb is not None:
                        progress_cb(done)

    await asyncio.gather(*(one(i, s, u) for i, (s, u) in enumerate(requests)))
    return results


def achat_many(
    requests: Sequence[tuple[str, str]],
    model: str | None = None,
    temperature: float = 0.0,
    max_tokens: int = 1024,
    concurrency: int | None = None,
    progress_cb=None,
) -> list[str | None]:
    """Batch of (system, user) prompts -> list of replies, order preserved."""
    if not requests:
        return []
    return asyncio.run(
        _abatch(
            requests,
            model or settings.llm_model,
            None,
            temperature,
            max_tokens,
            concurrency or settings.llm_max_concurrency,
            progress_cb,
        )
    )


def structured_many(
    schema: type[T],
    requests: Sequence[tuple[str, str]],
    model: str | None = None,
    temperature: float = 0.0,
    max_tokens: int = 1024,
    concurrency: int | None = None,
    progress_cb=None,
) -> list[T | None]:
    """Batch structured extraction. Unparseable replies come back as None."""
    if not requests:
        return []
    raw = asyncio.run(
        _abatch(
            requests,
            model or settings.llm_extraction_model,
            schema,
            temperature,
            max_tokens,
            concurrency or settings.llm_max_concurrency,
            progress_cb,
        )
    )
    out: list[T | None] = []
    for r in raw:
        if not r:
            out.append(None)
            continue
        try:
            out.append(schema.model_validate_json(_extract_json(r)))
        except (ValidationError, json.JSONDecodeError, ValueError):
            out.append(None)
    return out


# --------------------------------------------------------------------------
# other providers
# --------------------------------------------------------------------------


def _ollama_chat(system: str, user: str, model: str, temperature: float) -> str:
    try:
        import ollama
    except ImportError as e:
        raise LLMError("ollama package not installed") from e
    try:
        resp = ollama.Client(host=settings.ollama_base_url).chat(
            model=model,
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            options={"temperature": temperature},
        )
    except Exception as e:
        raise LLMError(f"ollama call failed: {e}") from e
    return resp["message"]["content"]


def _anthropic_chat(system: str, user: str, model: str, max_tokens: int) -> str:
    try:
        import anthropic
    except ImportError as e:
        raise LLMError("anthropic package not installed") from e
    if not settings.anthropic_api_key:
        raise LLMError("ANTHROPIC_API_KEY is not set")
    client = anthropic.Anthropic(api_key=settings.anthropic_api_key)
    resp = client.messages.create(
        model=model,
        max_tokens=max_tokens,
        system=system,
        messages=[{"role": "user", "content": user}],
    )
    return "".join(block.text for block in resp.content if block.type == "text")


_JSON_FENCE = re.compile(r"```(?:json)?\s*(.*?)```", re.DOTALL)


def _extract_json(text: str) -> str:
    """Pull the JSON object out of a reply that may be fenced or padded."""
    if not text:
        raise ValueError("empty response")
    fenced = _JSON_FENCE.search(text)
    if fenced:
        text = fenced.group(1)
    start, end = text.find("{"), text.rfind("}")
    if start == -1 or end == -1 or end < start:
        raise ValueError("no JSON object in response")
    return text[start : end + 1]
