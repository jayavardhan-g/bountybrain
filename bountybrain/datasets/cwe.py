"""Parse the MITRE CWE catalog into weakness nodes and typed edges.

CWE gives us three things nothing else in the corpus can:

1. A **canonical vocabulary** for vulnerability classes, with official
   `Alternate_Terms` (so "SQLi", "SQL injection" and CWE-89 collapse to one
   node instead of three).
2. A **real hierarchy** — ChildOf / PeerOf / CanPrecede / Requires edges
   between weaknesses. This is what makes the graph multi-hop rather than a
   star of reports around vuln labels.
3. Per-weakness prose (description, consequences, detection methods,
   mitigations) that is good enough to serve as retrievable corpus text.
"""
from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path

NS = "{http://cwe.mitre.org/cwe-7}"

# Relationship natures we keep as graph edges. "ChildOf" carries the
# taxonomy; the rest describe how weaknesses chain in real attacks.
KEPT_NATURES = {"ChildOf", "PeerOf", "CanPrecede", "CanFollow", "Requires", "CanAlsoBe"}


@dataclass
class Weakness:
    cwe_id: int
    name: str
    abstraction: str  # Pillar | Class | Base | Variant | Compound
    status: str
    description: str
    extended_description: str = ""
    likelihood: str | None = None
    aliases: list[str] = field(default_factory=list)
    languages: list[str] = field(default_factory=list)
    technologies: list[str] = field(default_factory=list)
    consequences: list[dict] = field(default_factory=list)
    detection_methods: list[dict] = field(default_factory=list)
    mitigations: list[dict] = field(default_factory=list)
    observed_cves: list[str] = field(default_factory=list)
    # (nature, target_cwe_id)
    relations: list[tuple[str, int]] = field(default_factory=list)

    @property
    def key(self) -> str:
        return f"CWE-{self.cwe_id}"

    def to_document(self) -> str:
        """Flatten into retrievable prose for the RAG index."""
        parts = [f"# {self.key}: {self.name}", "", self.description]
        if self.extended_description:
            parts += ["", self.extended_description]
        if self.aliases:
            parts += ["", f"**Also known as:** {', '.join(self.aliases)}"]
        if self.likelihood:
            parts += ["", f"**Likelihood of exploit:** {self.likelihood}"]
        if self.languages or self.technologies:
            scope = ", ".join(self.languages + self.technologies)
            parts += ["", f"**Applicable platforms:** {scope}"]
        if self.consequences:
            parts += ["", "## Impact"]
            for c in self.consequences:
                scopes = ", ".join(c.get("scopes", []))
                impacts = ", ".join(c.get("impacts", []))
                line = f"- {scopes}: {impacts}"
                if c.get("note"):
                    line += f" — {c['note']}"
                parts.append(line)
        if self.detection_methods:
            parts += ["", "## How to detect it"]
            for d in self.detection_methods:
                parts.append(f"- **{d.get('method', '')}**: {d.get('description', '')}")
        if self.mitigations:
            parts += ["", "## Mitigations"]
            for m in self.mitigations:
                phase = "/".join(m.get("phases", []))
                parts.append(f"- ({phase}) {m.get('description', '')}")
        if self.observed_cves:
            parts += ["", f"**Observed in:** {', '.join(self.observed_cves[:20])}"]
        return "\n".join(parts)


def _text(el: ET.Element | None) -> str:
    """Collapse an element's full subtree into plain text.

    CWE embeds XHTML (<html:p>, <html:ul>) inside description fields, so a
    plain `.text` read would silently truncate most entries.
    """
    if el is None:
        return ""
    return " ".join("".join(el.itertext()).split())


def _findall(parent: ET.Element, path: str) -> list[ET.Element]:
    return parent.findall(path.replace("<>", NS))


def _parse_weakness(w: ET.Element) -> Weakness:
    cwe_id = int(w.attrib["ID"])
    wk = Weakness(
        cwe_id=cwe_id,
        name=w.attrib.get("Name", ""),
        abstraction=w.attrib.get("Abstraction", ""),
        status=w.attrib.get("Status", ""),
        description=_text(w.find(NS + "Description")),
        extended_description=_text(w.find(NS + "Extended_Description")),
        likelihood=_text(w.find(NS + "Likelihood_Of_Exploit")) or None,
    )

    for rel in _findall(w, f"{NS}Related_Weaknesses/{NS}Related_Weakness"):
        nature = rel.attrib.get("Nature", "")
        target = rel.attrib.get("CWE_ID")
        if nature in KEPT_NATURES and target and target.isdigit():
            pair = (nature, int(target))
            if pair not in wk.relations:
                wk.relations.append(pair)

    for term in _findall(w, f"{NS}Alternate_Terms/{NS}Alternate_Term"):
        t = _text(term.find(NS + "Term"))
        if t:
            wk.aliases.append(t)

    for lang in _findall(w, f"{NS}Applicable_Platforms/{NS}Language"):
        name = lang.attrib.get("Name") or lang.attrib.get("Class")
        if name:
            wk.languages.append(name)
    for tech in _findall(w, f"{NS}Applicable_Platforms/{NS}Technology"):
        name = tech.attrib.get("Name") or tech.attrib.get("Class")
        if name:
            wk.technologies.append(name)

    for c in _findall(w, f"{NS}Common_Consequences/{NS}Consequence"):
        wk.consequences.append(
            {
                "scopes": [_text(s) for s in c.findall(NS + "Scope")],
                "impacts": [_text(i) for i in c.findall(NS + "Impact")],
                "note": _text(c.find(NS + "Note")),
            }
        )

    for d in _findall(w, f"{NS}Detection_Methods/{NS}Detection_Method"):
        wk.detection_methods.append(
            {
                "method": _text(d.find(NS + "Method")),
                "description": _text(d.find(NS + "Description")),
                "effectiveness": _text(d.find(NS + "Effectiveness")),
            }
        )

    for m in _findall(w, f"{NS}Potential_Mitigations/{NS}Mitigation"):
        wk.mitigations.append(
            {
                "phases": [_text(p) for p in m.findall(NS + "Phase")],
                "description": _text(m.find(NS + "Description")),
            }
        )

    for o in _findall(w, f"{NS}Observed_Examples/{NS}Observed_Example"):
        ref = _text(o.find(NS + "Reference"))
        if ref.startswith("CVE-"):
            wk.observed_cves.append(ref)

    return wk


def load(xml_path: str | Path) -> list[Weakness]:
    """Parse the catalog. Returns every weakness, including deprecated ones."""
    root = ET.parse(str(xml_path)).getroot()
    container = root.find(NS + "Weaknesses")
    if container is None:
        return []
    return [_parse_weakness(w) for w in container]


# Community shorthand MITRE does not carry as an Alternate_Term. Bug bounty
# writeups use these constantly, so without them a large slice of the corpus
# fails to normalise onto the CWE backbone. Hand-curated — kept small and
# explicit rather than guessed at by string similarity.
COMMUNITY_ALIASES: dict[str, int] = {
    "idor": 639,  # Authorization Bypass Through User-Controlled Key
    "insecure direct object reference": 639,
    "broken access control": 284,
    "broken authorization": 285,
    "broken authentication": 287,
    "auth bypass": 287,
    "authentication bypass": 287,
    "account takeover": 640,
    "ato": 640,
    "ssti": 1336,  # Improper Neutralization of Special Elements Used in a Template Engine
    "template injection": 1336,
    "server-side template injection": 1336,
    "rce": 94,
    "remote code execution": 94,
    "command injection": 77,
    "os command injection": 78,
    "lfi": 98,
    "local file inclusion": 98,
    "rfi": 98,
    "remote file inclusion": 98,
    "path traversal": 22,
    "directory traversal": 22,
    "prototype pollution": 1321,
    "race condition": 362,
    "toctou": 367,
    # CWE-840 "Business Logic Errors" is a *category*, not a weakness, so it
    # has no node in the hierarchy. CWE-841 is the weakness underneath it.
    "business logic": 841,
    "logic flaw": 841,
    "information disclosure": 200,
    "info leak": 200,
    "sensitive data exposure": 200,
    "subdomain takeover": 350,
    "dos": 400,
    "denial of service": 400,
    "deserialization": 502,
    "insecure deserialization": 502,
    "cors misconfiguration": 942,
    "clickjacking": 1021,
    "request smuggling": 444,
    "http request smuggling": 444,
    "cache poisoning": 524,
    "privilege escalation": 269,
    "xspa": 918,
    "csti": 1336,
    "crlf injection": 93,
    "host header injection": 644,
    "graphql introspection": 200,
    "mass assignment": 915,
    "open redirect": 601,
    "session fixation": 384,
    "weak cryptography": 327,
    "hardcoded credentials": 798,
    "api key leak": 798,
    "xxe": 611,
    "ssrf": 918,
    # --- XSS subtypes: real-world writeups name the delivery vector, but
    # MITRE keeps them all under CWE-79 ---
    "stored xss": 79,
    "reflected xss": 79,
    "dom xss": 79,
    "dom based xss": 79,
    "blind xss": 79,
    "self-xss": 79,
    "self xss": 79,
    "universal xss": 79,
    # --- authentication / authorisation variants ---
    "local privilege escalation": 269,
    "password reset": 640,
    "password reset poisoning": 640,
    "oauth": 287,
    "sso": 287,
    "2fa / mfa bypass": 287,
    "2fa bypass": 287,
    "mfa bypass": 287,
    "otp bypass": 287,
    "email verification bypass": 287,
    "missing authentication": 306,
    "bruteforce": 307,
    "brute force": 307,
    "authorization bypass": 285,
    "weak credentials": 521,
    "default credentials": 1392,
    "insecure deeplink": 939,
    "session management issue": 613,
    # --- protection-mechanism bypasses ---
    "waf bypass": 693,
    "csp bypass": 693,
    "sop bypass": 693,
    "filter bypass": 693,
    "lack of rate limiting": 770,
    "rate limiting bypass": 770,
    # --- file access ---
    "arbitrary file read": 22,
    "arbitrary file write": 73,
    "arbitrary file download": 22,
    "directory listing": 548,
    "file upload": 434,
    "unrestricted file upload": 434,
    # --- protocol / caching / transport ---
    "web cache poisoning": 524,
    "web cache deception": 524,
    "http response manipulation": 113,
    "http response splitting": 113,
    "http parameter pollution": 235,
    "mitm": 300,
    "postmessage": 346,
    "jwt": 347,
    # --- crypto & config ---
    "cryptographic issues": 327,
    # CWE-16 "Configuration" is likewise a category; CWE-1188 is the weakness.
    "security misconfiguration": 1188,
    "aws misconfiguration": 1188,
    "components with known vulnerabilities": 1104,
    "supply chain attack": 1357,
    "token leak": 200,
    # --- business logic ---
    "payment tampering": 472,
    "payment bypass": 472,
    "phishing": 451,
}

# Labels that are legitimately NOT vulnerability classes: platform tags,
# engagement types, research categories. They must not be force-mapped onto
# a CWE, and coverage metrics should exclude them rather than counting them
# as failures.
NON_VULNERABILITY_LABELS: frozenset[str] = frozenset(
    {
        "security code review",
        "internal pentest",
        "browser hacking",
        "reverse engineering",
        "privacy issue",
        "android",
        "ios",
        "windows",
        "macos",
        "linux",
        "cloud",
        "ci/cd",
        "ai",
        "llm",
        "iot",
        "hardware",
        "blockchain",
        "smart contract",
        "graphql",
        "api",
        "mobile",
        "web3",
    }
)

# CWE names hide the everyday term in a trailing parenthetical, in two
# flavours: quoted -- "...('Cross-site Scripting')" -- and bare --
# "Cross-Site Request Forgery (CSRF)". We want both the parenthetical and
# the name with it stripped off.
_PARENTHETICAL = re.compile(r"\('?([^')]+)'?\)")


def alias_map(weaknesses: list[Weakness]) -> dict[str, int]:
    """Lowercased alias/name -> CWE id, for normalising extracted labels.

    More specific names win: when two weaknesses claim the same alias we
    keep the lower abstraction level (a Variant beats a Class), because a
    concrete label like "Reflected XSS" should not collapse into "Injection".

    Three sources feed the map, in increasing priority: the official Name,
    the official Alternate_Terms, and `COMMUNITY_ALIASES`. The curated layer
    wins outright so that "IDOR" resolves even though MITRE never uses it.
    """
    rank = {"Variant": 0, "Base": 1, "Compound": 2, "Class": 3, "Pillar": 4}
    out: dict[str, tuple[int, int]] = {}

    def offer(label: str, score: int, cwe_id: int) -> None:
        k = " ".join(label.strip().lower().split())
        if not k:
            return
        if k not in out or score < out[k][0]:
            out[k] = (score, cwe_id)

    for w in weaknesses:
        score = rank.get(w.abstraction, 5)
        offer(w.name, score, w.cwe_id)
        # the short name inside the official name, e.g. 'SQL Injection', CSRF
        for m in _PARENTHETICAL.findall(w.name):
            offer(m, score, w.cwe_id)
        # ...and the official name with the parenthetical stripped off
        offer(_PARENTHETICAL.sub("", w.name), score, w.cwe_id)
        for label in w.aliases:
            offer(label, score, w.cwe_id)

    resolved = {k: v[1] for k, v in out.items()}
    resolved.update(COMMUNITY_ALIASES)  # curated layer always wins
    return resolved
