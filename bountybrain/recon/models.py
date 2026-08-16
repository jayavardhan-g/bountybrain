from __future__ import annotations

from typing import Literal

from pydantic import BaseModel

FindingType = Literal["subdomain", "url", "tech", "cve", "endpoint", "header", "other"]


class ReconFinding(BaseModel):
    target: str
    type: FindingType
    value: str
    evidence: str | None = None
    source_tool: str
