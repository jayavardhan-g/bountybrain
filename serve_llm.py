"""Start a local vLLM server for extraction and classification.

    python serve_llm.py                 # pick the freest GPU automatically
    python serve_llm.py --gpu 3         # pin to a specific GPU
    python serve_llm.py --status        # is a server already up?

Everything stays on this machine — no API keys, no data leaving the host.

On a shared server this script deliberately does two things:

1. It **picks a GPU that is actually free** at launch time rather than
   defaulting to device 0, which is usually the one everybody else grabbed.
2. It requests a modest `--gpu-memory-utilization` rather than the default
   0.9. vLLM pre-allocates that fraction of the card for its KV cache, so
   the default would reserve ~130 GB of a 143 GB card for a 14B model that
   needs a fraction of it, locking other users out for no benefit.
"""
from __future__ import annotations

import os
import subprocess
import sys
import time
from pathlib import Path

import httpx
import typer
from rich.console import Console
from rich.table import Table

from bountybrain.config import settings

app = typer.Typer(add_completion=False, help="Serve the local LLM with vLLM")
console = Console()


def gpu_status() -> list[dict]:
    try:
        out = subprocess.run(
            [
                "nvidia-smi",
                "--query-gpu=index,memory.used,memory.total,utilization.gpu",
                "--format=csv,noheader,nounits",
            ],
            capture_output=True,
            text=True,
            check=True,
        ).stdout
    except (subprocess.CalledProcessError, FileNotFoundError):
        return []
    rows = []
    for line in out.strip().splitlines():
        idx, used, total, util = (p.strip() for p in line.split(","))
        rows.append(
            {
                "index": int(idx),
                "used_mb": int(used),
                "total_mb": int(total),
                "free_mb": int(total) - int(used),
                "util_pct": int(util),
            }
        )
    return rows


def pick_gpu(min_free_gb: int = 40) -> int | None:
    """Freest GPU with enough headroom, or None."""
    rows = sorted(gpu_status(), key=lambda r: (-r["free_mb"], r["util_pct"]))
    for r in rows:
        if r["free_mb"] >= min_free_gb * 1024:
            return r["index"]
    return None


def server_up(timeout: float = 3.0) -> bool:
    try:
        r = httpx.get(f"{settings.vllm_base_url}/models", timeout=timeout)
        return r.status_code == 200
    except Exception:
        return False


@app.command()
def main(
    gpu: int = typer.Option(None, "--gpu", help="GPU index to pin (default: freest)."),
    model: str = typer.Option(None, "--model", help="HF model id (default: config)."),
    port: int = typer.Option(None, "--port", help="Port (default: from vllm_base_url)."),
    gpu_memory_utilization: float = typer.Option(
        0.40,
        "--gpu-mem",
        help="Fraction of the card vLLM may reserve. Kept low deliberately: "
        "on a shared machine the 0.9 default hoards the whole card.",
    ),
    max_model_len: int = typer.Option(8192, "--max-len", help="Max context length."),
    enforce_eager: bool = typer.Option(
        sys.version_info < (3, 12),
        "--enforce-eager/--no-enforce-eager",
        help="Skip CUDA-graph/compile passes. On by default below Python 3.12, where "
        "the compile pass imports a flashinfer module that fails to import (SETUP.md).",
    ),
    status: bool = typer.Option(False, "--status", help="Show GPU + server status and exit."),
) -> None:
    if status:
        t = Table(title="GPUs")
        for c in ("index", "used MB", "free MB", "util %"):
            t.add_column(c, justify="right")
        for r in gpu_status():
            t.add_row(str(r["index"]), f"{r['used_mb']:,}", f"{r['free_mb']:,}", str(r["util_pct"]))
        console.print(t)
        console.print(
            f"vLLM at {settings.vllm_base_url}: "
            + ("[green]up[/green]" if server_up() else "[yellow]not running[/yellow]")
        )
        raise typer.Exit()

    if server_up():
        console.print(f"[green]Server already running at {settings.vllm_base_url}[/green]")
        raise typer.Exit()

    chosen = gpu if gpu is not None else pick_gpu()
    if chosen is None:
        console.print(
            "[red]No GPU with enough free memory. Check `python serve_llm.py --status`.[/red]"
        )
        raise typer.Exit(code=1)

    model_id = model or settings.llm_model
    listen_port = port or int(settings.vllm_base_url.rstrip("/").split(":")[-1].split("/")[0])

    env = dict(os.environ)
    env["CUDA_VISIBLE_DEVICES"] = str(chosen)

    # vLLM's JIT kernel compilation shells out to `ninja`, which pip installs
    # into the interpreter's own bin directory. If that directory is not on
    # PATH — common when launching outside an activated env — startup fails
    # with FileNotFoundError *after* the full weight load, which reads like a
    # model problem rather than a PATH one.
    bin_dir = str(Path(sys.executable).parent)
    if bin_dir not in env.get("PATH", "").split(os.pathsep):
        env["PATH"] = bin_dir + os.pathsep + env.get("PATH", "")

    # Triton and Inductor caches cannot be created on some network filesystems
    # (GlusterFS returns Errno 61). Default them next to the project unless the
    # caller has already chosen somewhere.
    cache_root = Path(settings.data_dir).parent / ".cache"
    for var, sub in (
        ("TRITON_CACHE_DIR", "triton"),
        ("TORCHINDUCTOR_CACHE_DIR", "inductor"),
        ("VLLM_CACHE_ROOT", "vllm"),
    ):
        if not env.get(var):
            path = cache_root / sub
            path.mkdir(parents=True, exist_ok=True)
            env[var] = str(path)

    cmd = [
        sys.executable,
        "-m",
        "vllm.entrypoints.openai.api_server",
        "--model",
        model_id,
        "--port",
        str(listen_port),
        "--gpu-memory-utilization",
        str(gpu_memory_utilization),
        "--max-model-len",
        str(max_model_len),
    ]
    if enforce_eager:
        cmd.append("--enforce-eager")
    console.print(f"[cyan]Starting {model_id} on GPU {chosen}, port {listen_port}[/cyan]")
    console.print(f"[dim]{' '.join(cmd)}[/dim]")
    proc = subprocess.Popen(cmd, env=env)

    console.print("[dim]waiting for the server to come up…[/dim]")
    for _ in range(240):  # up to ~20 min, model download included
        if server_up():
            console.print(f"[green]Ready at {settings.vllm_base_url}[/green]")
            break
        if proc.poll() is not None:
            console.print("[red]vLLM exited during startup.[/red]")
            raise typer.Exit(code=1)
        time.sleep(5)
    proc.wait()


if __name__ == "__main__":
    app()
