"""SQLAlchemy models for the knowledge graph.

We use plain relational tables with foreign keys. No dedicated graph DB.
`reports` is the anchor; every other table is either an entity or a
relation table linking reports to entities (or entities to entities).
"""
from __future__ import annotations

from datetime import date, datetime

from sqlalchemy import (
    Date,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    pass


# --------- entity tables ---------


class Report(Base):
    __tablename__ = "reports"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    source: Mapped[str] = mapped_column(String(64))  # hackerone|pentesterland|portswigger|web|seed
    url: Mapped[str] = mapped_column(String(1024), unique=True)
    title: Mapped[str] = mapped_column(String(512))
    date: Mapped[date | None] = mapped_column(Date, nullable=True)
    program: Mapped[str | None] = mapped_column(String(256), nullable=True)
    bounty: Mapped[float | None] = mapped_column(nullable=True)
    severity: Mapped[str | None] = mapped_column(String(32), nullable=True)
    raw_markdown: Mapped[str] = mapped_column(Text)
    difficulty: Mapped[str | None] = mapped_column(String(32), nullable=True)
    key_takeaway: Mapped[str | None] = mapped_column(Text, nullable=True)
    root_cause: Mapped[str | None] = mapped_column(Text, nullable=True)
    payloads_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())


class Vulnerability(Base):
    __tablename__ = "vulnerabilities"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(128), unique=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)


class Technique(Base):
    __tablename__ = "techniques"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(256), unique=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)


class Tool(Base):
    __tablename__ = "tools"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(128), unique=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)


class Target(Base):
    __tablename__ = "targets"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(128), unique=True)
    category: Mapped[str | None] = mapped_column(String(64), nullable=True)


class Patch(Base):
    __tablename__ = "patches"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    description: Mapped[str] = mapped_column(Text)
    commit_url: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    report_id: Mapped[int | None] = mapped_column(
        ForeignKey("reports.id"), nullable=True
    )


class CVE(Base):
    __tablename__ = "cves"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    cve_id: Mapped[str] = mapped_column(String(32), unique=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    year: Mapped[int | None] = mapped_column(Integer, nullable=True)


# --------- relation tables ---------


class ReportExploitsVuln(Base):
    __tablename__ = "report_exploits_vuln"
    report_id: Mapped[int] = mapped_column(ForeignKey("reports.id"), primary_key=True)
    vuln_id: Mapped[int] = mapped_column(ForeignKey("vulnerabilities.id"), primary_key=True)


class ReportUsesTechnique(Base):
    __tablename__ = "report_uses_technique"
    report_id: Mapped[int] = mapped_column(ForeignKey("reports.id"), primary_key=True)
    technique_id: Mapped[int] = mapped_column(ForeignKey("techniques.id"), primary_key=True)


class ReportUsesTool(Base):
    __tablename__ = "report_uses_tool"
    report_id: Mapped[int] = mapped_column(ForeignKey("reports.id"), primary_key=True)
    tool_id: Mapped[int] = mapped_column(ForeignKey("tools.id"), primary_key=True)


class ReportTargetsTech(Base):
    __tablename__ = "report_targets_tech"
    report_id: Mapped[int] = mapped_column(ForeignKey("reports.id"), primary_key=True)
    target_id: Mapped[int] = mapped_column(ForeignKey("targets.id"), primary_key=True)


class ReportBypassesReport(Base):
    __tablename__ = "report_bypasses_report"
    report_id: Mapped[int] = mapped_column(ForeignKey("reports.id"), primary_key=True)
    bypassed_report_id: Mapped[int] = mapped_column(
        ForeignKey("reports.id"), primary_key=True
    )


class ReportReferencesCVE(Base):
    __tablename__ = "report_references_cve"
    report_id: Mapped[int] = mapped_column(ForeignKey("reports.id"), primary_key=True)
    cve_id: Mapped[int] = mapped_column(ForeignKey("cves.id"), primary_key=True)


class TechniqueVariantOf(Base):
    __tablename__ = "technique_variant_of"
    technique_id: Mapped[int] = mapped_column(ForeignKey("techniques.id"), primary_key=True)
    parent_technique_id: Mapped[int] = mapped_column(
        ForeignKey("techniques.id"), primary_key=True
    )
