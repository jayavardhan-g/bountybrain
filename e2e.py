"""End-to-end check of the API and the UI against the real graph and model.

    uvicorn bountybrain.api.app:app --port 8765 &
    python e2e.py --api http://localhost:8765     # every route, over HTTP
    python e2e.py --ui                            # every page, real data, real LLM
    streamlit run bountybrain/ui/streamlit_app.py --server.port 8502 --server.headless true &
    python e2e.py --streamlit http://localhost:8502  # the real server answers

The unit and smoke tests stub retrieval and the model; this does not. It
needs the built graph, the index and (for generated tutorials) a served LLM.
Embedded Qdrant takes an exclusive lock, so stop the API before `--ui`.

Results go to `artifacts/e2e.json`: per check, pass/fail, latency, and the
facts it asserted, so "the app runs end to end" is a file, not a claim.
"""
from __future__ import annotations

import json
import time
from pathlib import Path

import httpx
import typer
from rich.console import Console

from bountybrain.config import settings

app = typer.Typer(add_completion=False, help="End-to-end API and UI check")
console = Console()

ROOT = Path(__file__).resolve().parent
UI = ROOT / "bountybrain" / "ui"
OUT = settings.artifact_dir / "e2e.json"


class Checks:
    def __init__(self, kind: str):
        self.kind = kind
        self.rows: list[dict] = []

    def run(self, name: str, fn) -> None:
        t0 = time.perf_counter()
        try:
            facts = fn() or {}
            ok, err = True, None
        except Exception as e:  # noqa: BLE001 - recorded, not swallowed
            facts, ok, err = {}, False, f"{type(e).__name__}: {e}"
        ms = round((time.perf_counter() - t0) * 1000)
        self.rows.append({"check": name, "ok": ok, "ms": ms, "facts": facts, "error": err})
        mark = "[green]ok[/green]" if ok else f"[red]FAIL[/red] {err}"
        console.print(f"  {name:38s} {ms:>7,} ms  {mark}")

    def save(self) -> None:
        data = json.loads(OUT.read_text()) if OUT.exists() else {}
        data[self.kind] = {
            "passed": sum(r["ok"] for r in self.rows),
            "total": len(self.rows),
            "llm_model": settings.llm_model,
            "checks": self.rows,
        }
        OUT.write_text(json.dumps(data, indent=2))
        console.print(f"[green]{data[self.kind]['passed']}/{len(self.rows)} passed → {OUT}[/green]")


def _expect(cond: bool, msg: str) -> None:
    if not cond:
        raise AssertionError(msg)


# --------------------------------------------------------------------- API


def check_api(base: str) -> Checks:
    c = Checks("api")
    http = httpx.Client(base_url=base, timeout=300)

    def get(path, **params):
        r = http.get(path, params=params)
        r.raise_for_status()
        return r.json()

    def post(path, body):
        r = http.post(path, json=body)
        r.raise_for_status()
        return r.json()

    def health():
        _expect(get("/health") == {"ok": True}, "health not ok")

    def stats():
        s = get("/stats")
        _expect(s["weaknesses"] == 969, f"weaknesses={s['weaknesses']}")
        return {k: s[k] for k in ("weaknesses", "techniques", "documents", "signatures", "exploits", "cves")}

    def weakness():
        w = get("/weakness/918")
        _expect(w["techniques"] and w["writeups"], "SSRF has no patterns or writeups")
        return {"techniques": len(w["techniques"]), "writeups": len(w["writeups"])}

    def weakness_404():
        _expect(http.get("/weakness/999999").status_code == 404, "expected 404")

    def resolve():
        got = {q: get("/weakness", q=q)["cwe_id"] for q in ("IDOR", "SQL injection", "path traversal")}
        _expect(got == {"IDOR": 639, "SQL injection": 89, "path traversal": 22}, str(got))
        return got

    def search():
        hits = post("/search", {"query": "server-side request forgery cloud metadata", "top_k": 5})["hits"]
        _expect(len(hits) == 5, f"{len(hits)} hits")
        return {"top_hit": hits[0]["title"][:80], "mode": "hybrid_rerank"}

    def learn():
        r = post("/learn", {"topic": "SSRF"})
        tut = r["tutorial"]
        _expect("No LLM server was reachable" not in tut, "template fallback, not the model")
        _expect("[1]" in tut or "[2]" in tut, "no citations in generated tutorial")
        return {"tutorial_chars": len(tut), "sources": len(r["sources"]), "labs": len(r["labs"])}

    def chains():
        ch = post("/chains", {"topic": "XSS"})["chains"]
        _expect(ch, "no chains for XSS")
        return {"chains": len(ch)}

    def labs():
        got = {t: len(get("/labs", topic=t)["labs"]) for t in ("IDOR", "CWE-639", "Insecure Direct Object Reference")}
        _expect(len(set(got.values())) == 1 and min(got.values()) > 0, str(got))
        return got

    def path():
        p = get("/path", topic="SSRF")
        _expect(p["complete"], "SSRF path incomplete")
        return {s["key"]: len(s["items"]) for s in p["stages"]}

    def related():
        doc_id = get("/weakness/918")["writeups"][0]["id"]
        return {"related": get(f"/reports/related/{doc_id}")["count"]}

    def products():
        r = post("/product/signatures", {"name": "wordpress"})
        _expect(r["signatures"], "no wordpress signatures")
        return {"signatures": len(r["signatures"]), "weaknesses": len(r["weaknesses"])}

    def recon():
        findings = []
        for name in ("subfinder.txt", "httpx.jsonl", "nuclei.jsonl"):
            with (ROOT / "examples" / name).open("rb") as f:
                r = http.post("/recon/parse", files={"file": (name, f)})
            r.raise_for_status()
            findings += r.json()["findings"]
        plan = post("/recon/plan", {"findings": findings})
        _expect(plan["assets"] > 0, "no plans")
        return {"findings": len(findings), "assets": plan["assets"]}

    for name, fn in [
        ("GET /health", health), ("GET /stats", stats), ("GET /weakness/918", weakness),
        ("GET /weakness/999999 → 404", weakness_404), ("GET /weakness?q= (aliases)", resolve),
        ("POST /search", search), ("POST /learn (LLM tutorial)", learn), ("POST /chains", chains),
        ("GET /labs (3 spellings)", labs), ("GET /path", path),
        ("GET /reports/related/{id}", related), ("POST /product/signatures", products),
        ("POST /recon/parse + /recon/plan", recon),
    ]:
        c.run(name, fn)
    return c


# ---------------------------------------------------------------------- UI


def check_ui() -> Checks:
    from streamlit.testing.v1 import AppTest

    c = Checks("ui")

    def page(rel: str, timeout: int = 60) -> AppTest:
        at = AppTest.from_file(str(UI / rel), default_timeout=timeout)
        at.run()
        _expect(not at.exception, str([e.value for e in at.exception]))
        return at

    def home():
        at = page("streamlit_app.py")
        return {"weaknesses_metric": at.metric[0].value}

    def learning_path():
        at = page("pages/0_Learning_Path.py")
        heads = [h.value for h in at.subheader]
        _expect(len(heads) == 5, f"{len(heads)} stages")
        return {"stages": heads}

    def learn():
        at = page("pages/1_Learn.py", timeout=600)
        at.button[0].click().run(timeout=600)
        _expect(not at.exception, str([e.value for e in at.exception]))
        md = " ".join(m.value for m in at.markdown)
        _expect("No LLM server was reachable" not in md, "template fallback, not the model")
        _expect("[1]" in md, "no citations rendered")
        return {"expanders": len(at.expander), "subheaders": [s.value for s in at.subheader]}

    def explore():
        at = page("pages/2_Explore.py")
        return {"header": at.header[0].value, "subheaders": len(at.subheader)}

    def chains():
        # XSS's CAPEC patterns chain; SSRF's only pattern (CAPEC-664) has no
        # CanPrecede/CanFollow edge in CAPEC, so the page must say so instead.
        out = {}
        for topic in ("XSS", "SQL injection", "SSRF"):
            at = AppTest.from_file(str(UI / "pages/3_Attack_Chains.py"), default_timeout=60)
            at.run()
            at.text_input[0].input(topic).run()
            _expect(not at.exception, str([e.value for e in at.exception]))
            chains = [m.value for m in at.markdown if "→" in m.value]
            out[topic] = len(chains)
            if topic == "SSRF":
                _expect(not chains and at.info, "SSRF should report no recorded successors")
            else:
                _expect(chains, f"no chain rendered for {topic}")
        return {"chains_rendered": out}

    def planner():
        # AppTest cannot drive st.file_uploader, so this checks the page
        # renders; the plan itself is exercised through /recon/plan.
        at = page("pages/4_Recon_Planner.py")
        return {"info_boxes": len(at.info)}

    def metrics():
        at = page("pages/5_Metrics.py")
        return {"tabs": len(at.tabs), "dataframes": len(at.dataframe)}

    for name, fn in [
        ("Home", home), ("Learning Path (SSRF)", learning_path),
        ("Learn → Explain (LLM tutorial)", learn), ("Explore (SSRF)", explore),
        ("Attack Chains (XSS, SQLi, SSRF)", chains), ("Recon Planner (render)", planner),
        ("Metrics", metrics),
    ]:
        c.run(name, fn)
    return c


def check_server(base: str) -> Checks:
    """A real `streamlit run` process answers over HTTP."""
    c = Checks("streamlit_server")
    http = httpx.Client(base_url=base, timeout=30)

    def health():
        r = http.get("/_stcore/health")
        _expect(r.status_code == 200 and r.text.strip() == "ok", f"{r.status_code} {r.text[:40]}")

    def index():
        r = http.get("/")
        _expect(r.status_code == 200 and "<html" in r.text.lower(), f"{r.status_code}")
        return {"bytes": len(r.content)}

    c.run("GET /_stcore/health", health)
    c.run("GET / (app shell)", index)
    return c


@app.command()
def main(
    api: str = typer.Option(None, "--api", help="Base URL of a running API."),
    ui: bool = typer.Option(False, "--ui", help="Drive every Streamlit page."),
    streamlit: str = typer.Option(None, "--streamlit", help="Base URL of a running `streamlit run`."),
) -> None:
    if api:
        console.rule(f"API at {api}")
        check_api(api).save()
    if streamlit:
        console.rule(f"Streamlit server at {streamlit}")
        check_server(streamlit).save()
    if ui:
        console.rule("Streamlit pages")
        check_ui().save()


if __name__ == "__main__":
    app()
