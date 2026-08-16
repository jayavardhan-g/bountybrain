"""Download every dataset in the registry.

Idempotent: an existing dataset is left alone unless `force=True`. Git
sources are shallow-cloned (or fast-forwarded); archives are unpacked in
place. Nothing here is page-by-page scraping, so there is no rate limiting
to respect beyond ordinary politeness.
"""
from __future__ import annotations

import shutil
import subprocess
import zipfile
from pathlib import Path

import httpx
from rich.console import Console

from bountybrain.config import settings
from bountybrain.datasets.registry import BY_NAME, DATASETS, Dataset

console = Console()

_TIMEOUT = httpx.Timeout(60.0, read=300.0)


def _download(url: str, dest: Path) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_suffix(dest.suffix + ".part")
    with httpx.stream("GET", url, timeout=_TIMEOUT, follow_redirects=True) as r:
        r.raise_for_status()
        with tmp.open("wb") as fh:
            for chunk in r.iter_bytes(chunk_size=1 << 16):
                fh.write(chunk)
    tmp.replace(dest)


def _unzip(archive: Path) -> None:
    with zipfile.ZipFile(archive) as zf:
        zf.extractall(archive.parent)


def _git(ds: Dataset) -> None:
    dest = ds.path
    if (dest / ".git").exists():
        subprocess.run(
            ["git", "-C", str(dest), "fetch", "--depth", str(ds.git_depth), "origin"],
            check=False,
            capture_output=True,
        )
        subprocess.run(
            ["git", "-C", str(dest), "reset", "--hard", "origin/HEAD"],
            check=False,
            capture_output=True,
        )
        return
    dest.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        ["git", "clone", "--depth", str(ds.git_depth), "--quiet", ds.url, str(dest)],
        check=True,
    )


def fetch_one(ds: Dataset, force: bool = False) -> bool:
    """Fetch a single dataset. Returns True if it is present afterwards."""
    if ds.exists() and not force:
        console.print(f"  [dim]· {ds.name} already present[/dim]")
        return True
    console.print(f"  [cyan]↓ {ds.name}[/cyan] ({ds.license})")
    try:
        if ds.kind == "git":
            if force and ds.path.exists():
                shutil.rmtree(ds.path)
            _git(ds)
        else:
            _download(ds.url, ds.path)
            if ds.kind == "archive":
                _unzip(ds.path)
        return True
    except Exception as e:  # noqa: BLE001 - report and continue with other sets
        console.print(f"  [red]✗ {ds.name}: {e}[/red]")
        return False


def fetch_all(names: list[str] | None = None, force: bool = False) -> dict[str, bool]:
    """Fetch the whole manifest (or a named subset)."""
    Path(settings.raw_cache_dir).mkdir(parents=True, exist_ok=True)
    targets = [BY_NAME[n] for n in names] if names else DATASETS
    console.print(f"[bold]Fetching {len(targets)} dataset(s) → {settings.raw_cache_dir}[/bold]")
    results = {d.name: fetch_one(d, force=force) for d in targets}
    ok = sum(results.values())
    console.print(f"[green]{ok}/{len(targets)} datasets ready[/green]")
    return results


def resolve_unpacked(ds: Dataset) -> Path | None:
    """For archive datasets, return the unpacked file matching `unpacked_glob`."""
    if not ds.unpacked_glob:
        return ds.path if ds.path.exists() else None
    matches = sorted(Path(settings.raw_cache_dir).glob(ds.unpacked_glob))
    return matches[-1] if matches else None
