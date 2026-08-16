from __future__ import annotations

from typing import Literal

from pydantic import BaseModel

FindingType = Literal["subdomain", "url", "tech", "cve", "endpoint", "header", "other"]


class ReconFinding(BaseModel):
    """One fact a recon tool reported about a target.

    `target` is the registrable domain (`acme.example`) and is useful for
    grouping a whole engagement. `host` is the specific host the finding came
    from (`git.acme.example`).

    Both are kept because they answer different questions. Planning has to
    happen per host: `git.acme.example` running GitLab and `jira.acme.example`
    running Jira are entirely different attack surfaces, and merging their
    fingerprints produces a plan that cannot say which host to try anything on.
    """

    target: str
    type: FindingType
    value: str
    evidence: str | None = None
    source_tool: str
    host: str | None = None

    @property
    def asset(self) -> str:
        """The unit a plan is built for — the host when known."""
        return self.host or self.target
