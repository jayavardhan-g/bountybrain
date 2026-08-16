"""Load the prose corpus: PayloadsAllTheThings and the OWASP WSTG.

These two supply what the structured datasets cannot — narrative technical
writing about *how* to find and exploit a class of bug, which is what the
retrieval layer is actually for.

Both are shipped as large markdown files (PayloadsAllTheThings averages ~30 KB
per page). Indexing a whole page as one unit retrieves badly: a query about
time-based blind injection would return the entire SQL Injection page and bury
the relevant paragraph. So we split on H2 headings, which in both corpora
correspond to individual techniques, and index each section as its own
document with a deep-link back to the heading anchor.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import quote

# Repo -> canonical browse URL, so every chunk can cite a real source.
REPO_URLS = {
    "payloadsallthethings": "https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master",
    "wstg": "https://github.com/OWASP/wstg/blob/master",
}

_H2 = re.compile(r"^##\s+(.+?)\s*$", re.MULTILINE)
_WSTG_ID = re.compile(r"\b(WSTG-[A-Z]{4}-\d{2})\b")
# A "## Summary" bullet list of links is a table of contents, not content.
_TOC_HEADINGS = {"summary", "table of contents", "contents", "toc"}

MIN_SECTION_CHARS = 200


@dataclass
class Article:
    source: str  # payloadsallthethings | wstg
    title: str  # page title
    section: str | None  # H2 heading, when split
    body: str
    path: str  # repo-relative
    url: str
    doc_id: str | None = None  # e.g. WSTG-INPV-05
    tags: list[str] = field(default_factory=list)

    @property
    def full_title(self) -> str:
        return f"{self.title} — {self.section}" if self.section else self.title

    def to_document(self) -> str:
        head = f"# {self.full_title}"
        if self.doc_id:
            head += f" ({self.doc_id})"
        return f"{head}\n\n{self.body}".strip()


def _anchor(heading: str) -> str:
    """GitHub heading anchor: lowercase, spaces to dashes, punctuation dropped."""
    slug = re.sub(r"[^\w\s-]", "", heading.lower()).strip()
    return re.sub(r"[\s]+", "-", slug)


def _looks_like_toc(heading: str, body: str) -> bool:
    if heading.strip().lower() in _TOC_HEADINGS:
        link_lines = [ln for ln in body.splitlines() if ln.strip().startswith(("*", "-"))]
        if link_lines and sum(1 for ln in link_lines if "](" in ln) >= len(link_lines) * 0.6:
            return True
    return False


def _page_title(text: str, fallback: str) -> str:
    m = re.search(r"^#\s+(.+?)\s*$", text, re.MULTILINE)
    return m.group(1).strip() if m else fallback


def split_sections(text: str) -> list[tuple[str | None, str]]:
    """Split markdown on H2 headings -> [(heading, body), ...].

    Content before the first H2 is returned with a `None` heading so page
    intros are not lost.
    """
    matches = list(_H2.finditer(text))
    if not matches:
        return [(None, text.strip())]
    out: list[tuple[str | None, str]] = []
    intro = text[: matches[0].start()].strip()
    if intro:
        out.append((None, intro))
    for i, m in enumerate(matches):
        end = matches[i + 1].start() if i + 1 < len(matches) else len(text)
        out.append((m.group(1).strip(), text[m.end() : end].strip()))
    return out


def _load_markdown_tree(
    root: Path, source: str, skip_dirs: set[str] | None = None
) -> list[Article]:
    skip = skip_dirs or set()
    base_url = REPO_URLS.get(source, "")
    articles: list[Article] = []

    for path in sorted(root.rglob("*.md")):
        rel = path.relative_to(root)
        parts = set(rel.parts)
        if parts & skip or any(p.startswith(".") for p in rel.parts):
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if len(text) < MIN_SECTION_CHARS:
            continue

        title = _page_title(text, rel.stem.replace("_", " "))
        doc_id_match = _WSTG_ID.search(text)
        doc_id = doc_id_match.group(1) if doc_id_match else None
        rel_path = "/".join(rel.parts)
        # Directory names contain spaces ("SQL Injection/README.md"); percent-
        # encode them or the citation links are not valid URLs.
        rel_url = quote(rel_path)

        for heading, body in split_sections(text):
            if len(body) < MIN_SECTION_CHARS:
                continue
            if heading and _looks_like_toc(heading, body):
                continue
            url = f"{base_url}/{rel_url}"
            if heading:
                url += f"#{_anchor(heading)}"
            articles.append(
                Article(
                    source=source,
                    title=title,
                    section=heading,
                    body=body,
                    path=rel_path,
                    url=url,
                    doc_id=doc_id,
                    tags=[p for p in rel.parts[:-1]],
                )
            )
    return articles


def load_payloads(repo_dir: str | Path) -> list[Article]:
    return _load_markdown_tree(
        Path(repo_dir),
        "payloadsallthethings",
        skip_dirs={"_template_vuln", ".github"},
    )


def load_wstg(repo_dir: str | Path) -> list[Article]:
    # Only the guide body; skip translations, licence and stylesheet assets.
    document_root = Path(repo_dir) / "document"
    if not document_root.exists():
        return []
    return _load_markdown_tree(document_root, "wstg")


def load_all(patt_dir: str | Path, wstg_dir: str | Path) -> list[Article]:
    return load_payloads(patt_dir) + load_wstg(wstg_dir)
