"""SQLAlchemy models for the knowledge graph.

Plain relational tables with foreign keys — no dedicated graph database. The
schema is deliberately *typed*: rather than one generic `edges` table, each
relationship kind gets its own table with its own semantics, so a query like
"which attack patterns can follow this one" is a join rather than a string
filter.

Node types
    Vulnerability   a CWE weakness class            (~970)
    Technique       a CAPEC attack pattern          (~615)
    CVE             a specific disclosed flaw
    Product         a vendor/product/technology
    Signature       a nuclei detection template     (~13.5k)
    Exploit         an Exploit-DB entry             (~47k)
    Document        retrievable prose: article, writeup record, or signature
    Tool            an offensive tool named in prose

Edge types
    weakness_relations          CWE -> CWE   (ChildOf/PeerOf/CanPrecede/...)
    technique_relations         CAPEC -> CAPEC
    technique_targets_weakness  CAPEC -> CWE   (official MITRE mapping)
    weakness_observed_cve       CWE  -> CVE    (from CWE Observed_Examples)
    signature_detects_weakness  nuclei -> CWE
    signature_references_cve    nuclei -> CVE
    signature_targets_product   nuclei -> Product
    exploit_references_cve      EDB -> CVE
    document_covers_weakness    Document -> CWE (labelled | llm | rule)
    document_covers_technique   Document -> CAPEC
    document_references_cve     Document -> CVE
    document_targets_product    Document -> Product
    document_mentions_tool      Document -> Tool
"""
from __future__ import annotations

from datetime import date, datetime

from sqlalchemy import (
    Boolean,
    Date,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


# --------------------------------------------------------------------------
# entity tables
# --------------------------------------------------------------------------


class Vulnerability(Base):
    """A CWE weakness class — the canonical vocabulary of the whole graph."""

    __tablename__ = "vulnerabilities"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    cwe_id: Mapped[int] = mapped_column(Integer, unique=True, index=True)
    name: Mapped[str] = mapped_column(String(512))
    abstraction: Mapped[str | None] = mapped_column(String(32), nullable=True)
    status: Mapped[str | None] = mapped_column(String(32), nullable=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    extended_description: Mapped[str | None] = mapped_column(Text, nullable=True)
    likelihood: Mapped[str | None] = mapped_column(String(32), nullable=True)
    aliases_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    languages_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    technologies_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    consequences_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    detection_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    mitigations_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    # Bugcrowd VRT payout priority, 1 (critical) .. 5 (informational)
    vrt_priority: Mapped[int | None] = mapped_column(Integer, nullable=True)

    @property
    def key(self) -> str:
        return f"CWE-{self.cwe_id}"


class Technique(Base):
    """A CAPEC attack pattern — the 'how', linked to the weakness it exploits."""

    __tablename__ = "techniques"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    capec_id: Mapped[int] = mapped_column(Integer, unique=True, index=True)
    name: Mapped[str] = mapped_column(String(512))
    abstraction: Mapped[str | None] = mapped_column(String(32), nullable=True)
    status: Mapped[str | None] = mapped_column(String(32), nullable=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    extended_description: Mapped[str | None] = mapped_column(Text, nullable=True)
    likelihood: Mapped[str | None] = mapped_column(String(32), nullable=True)
    typical_severity: Mapped[str | None] = mapped_column(String(32), nullable=True)
    min_skill: Mapped[str | None] = mapped_column(String(32), nullable=True)
    prerequisites_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    skills_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    execution_flow_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    mitigations_json: Mapped[str | None] = mapped_column(Text, nullable=True)

    @property
    def key(self) -> str:
        return f"CAPEC-{self.capec_id}"


class CVE(Base):
    __tablename__ = "cves"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    cve_id: Mapped[str] = mapped_column(String(32), unique=True, index=True)
    year: Mapped[int | None] = mapped_column(Integer, nullable=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    cvss_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    cvss_vector: Mapped[str | None] = mapped_column(String(128), nullable=True)
    # FIRST's probability the CVE is exploited in the wild within 30 days
    epss_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    epss_percentile: Mapped[float | None] = mapped_column(Float, nullable=True)
    # denormalised from Exploit-DB: public weaponisation evidence
    exploit_count: Mapped[int] = mapped_column(Integer, default=0)


class Product(Base):
    """A vendor / product / framework — the join key for recon fingerprints."""

    __tablename__ = "products"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(256), unique=True, index=True)
    vendor: Mapped[str | None] = mapped_column(String(256), nullable=True)
    category: Mapped[str | None] = mapped_column(String(64), nullable=True)
    cpe: Mapped[str | None] = mapped_column(String(512), nullable=True)


class Signature(Base):
    """A nuclei detection template."""

    __tablename__ = "signatures"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    template_id: Mapped[str] = mapped_column(String(256), index=True)
    name: Mapped[str] = mapped_column(String(512))
    path: Mapped[str] = mapped_column(String(512), unique=True)
    severity: Mapped[str | None] = mapped_column(String(32), nullable=True)
    protocol: Mapped[str | None] = mapped_column(String(32), nullable=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    impact: Mapped[str | None] = mapped_column(Text, nullable=True)
    remediation: Mapped[str | None] = mapped_column(Text, nullable=True)
    cvss_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    epss_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    verified: Mapped[bool] = mapped_column(Boolean, default=False)
    tags_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    references_json: Mapped[str | None] = mapped_column(Text, nullable=True)


class Exploit(Base):
    __tablename__ = "exploits"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    edb_id: Mapped[int] = mapped_column(Integer, unique=True, index=True)
    description: Mapped[str] = mapped_column(Text)
    exploit_type: Mapped[str | None] = mapped_column(String(32), nullable=True)
    platform: Mapped[str | None] = mapped_column(String(64), nullable=True)
    verified: Mapped[bool] = mapped_column(Boolean, default=False)
    published: Mapped[date | None] = mapped_column(Date, nullable=True)
    url: Mapped[str | None] = mapped_column(String(512), nullable=True)


class Tool(Base):
    __tablename__ = "tools"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    category: Mapped[str | None] = mapped_column(String(64), nullable=True)


class Document(Base):
    """Anything retrievable: a prose article, a disclosed-writeup record, or a
    flattened detection signature. This is what the RAG layer indexes.

    `doc_type` distinguishes them so retrieval can be filtered, and so the
    evaluation can report per-corpus numbers instead of one blurred average.
    """

    __tablename__ = "documents"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    doc_type: Mapped[str] = mapped_column(String(32), index=True)  # article|writeup|weakness|technique|signature
    source: Mapped[str] = mapped_column(String(64), index=True)
    url: Mapped[str] = mapped_column(String(1024))
    title: Mapped[str] = mapped_column(String(512))
    section: Mapped[str | None] = mapped_column(String(512), nullable=True)
    body: Mapped[str] = mapped_column(Text)
    external_id: Mapped[str | None] = mapped_column(String(64), nullable=True)  # WSTG-INPV-05, CWE-89
    path: Mapped[str | None] = mapped_column(String(512), nullable=True)
    published: Mapped[date | None] = mapped_column(Date, nullable=True)
    # writeup-only fields
    program: Mapped[str | None] = mapped_column(String(256), nullable=True)
    bounty: Mapped[float | None] = mapped_column(Float, nullable=True)
    authors_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    severity: Mapped[str | None] = mapped_column(String(32), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())

    __table_args__ = (
        UniqueConstraint("url", "section", name="uq_document_url_section"),
        Index("ix_documents_type_source", "doc_type", "source"),
    )


# --------------------------------------------------------------------------
# edge tables
# --------------------------------------------------------------------------


class WeaknessRelation(Base):
    """CWE -> CWE, e.g. ChildOf / PeerOf / CanPrecede. The taxonomy backbone."""

    __tablename__ = "weakness_relations"
    src_id: Mapped[int] = mapped_column(ForeignKey("vulnerabilities.id"), primary_key=True)
    dst_id: Mapped[int] = mapped_column(ForeignKey("vulnerabilities.id"), primary_key=True)
    nature: Mapped[str] = mapped_column(String(32), primary_key=True)


class TechniqueRelation(Base):
    """CAPEC -> CAPEC. `CanPrecede` is what makes multi-step chains queryable."""

    __tablename__ = "technique_relations"
    src_id: Mapped[int] = mapped_column(ForeignKey("techniques.id"), primary_key=True)
    dst_id: Mapped[int] = mapped_column(ForeignKey("techniques.id"), primary_key=True)
    nature: Mapped[str] = mapped_column(String(32), primary_key=True)


class TechniqueTargetsWeakness(Base):
    """Official MITRE CAPEC -> CWE mapping: this attack exploits this weakness."""

    __tablename__ = "technique_targets_weakness"
    technique_id: Mapped[int] = mapped_column(ForeignKey("techniques.id"), primary_key=True)
    vuln_id: Mapped[int] = mapped_column(ForeignKey("vulnerabilities.id"), primary_key=True)


class WeaknessObservedCVE(Base):
    __tablename__ = "weakness_observed_cve"
    vuln_id: Mapped[int] = mapped_column(ForeignKey("vulnerabilities.id"), primary_key=True)
    cve_id: Mapped[int] = mapped_column(ForeignKey("cves.id"), primary_key=True)


class SignatureDetectsWeakness(Base):
    __tablename__ = "signature_detects_weakness"
    signature_id: Mapped[int] = mapped_column(ForeignKey("signatures.id"), primary_key=True)
    vuln_id: Mapped[int] = mapped_column(ForeignKey("vulnerabilities.id"), primary_key=True)


class SignatureReferencesCVE(Base):
    __tablename__ = "signature_references_cve"
    signature_id: Mapped[int] = mapped_column(ForeignKey("signatures.id"), primary_key=True)
    cve_id: Mapped[int] = mapped_column(ForeignKey("cves.id"), primary_key=True)


class SignatureTargetsProduct(Base):
    """The recon join: a fingerprinted product maps to templates that hit it."""

    __tablename__ = "signature_targets_product"
    signature_id: Mapped[int] = mapped_column(ForeignKey("signatures.id"), primary_key=True)
    product_id: Mapped[int] = mapped_column(ForeignKey("products.id"), primary_key=True)


class ExploitReferencesCVE(Base):
    __tablename__ = "exploit_references_cve"
    exploit_id: Mapped[int] = mapped_column(ForeignKey("exploits.id"), primary_key=True)
    cve_id: Mapped[int] = mapped_column(ForeignKey("cves.id"), primary_key=True)


class DocumentCoversWeakness(Base):
    """Document -> CWE.

    `provenance` records how the edge was derived — `labelled` for a curated
    source label, `llm` for model extraction, `rule` for the regex baseline.
    Keeping it means the evaluation can score the LLM edges against the
    labelled ones instead of grading its own homework.
    """

    __tablename__ = "document_covers_weakness"
    document_id: Mapped[int] = mapped_column(ForeignKey("documents.id"), primary_key=True)
    vuln_id: Mapped[int] = mapped_column(ForeignKey("vulnerabilities.id"), primary_key=True)
    provenance: Mapped[str] = mapped_column(String(16), primary_key=True, default="llm")
    confidence: Mapped[float | None] = mapped_column(Float, nullable=True)


class DocumentCoversTechnique(Base):
    __tablename__ = "document_covers_technique"
    document_id: Mapped[int] = mapped_column(ForeignKey("documents.id"), primary_key=True)
    technique_id: Mapped[int] = mapped_column(ForeignKey("techniques.id"), primary_key=True)
    provenance: Mapped[str] = mapped_column(String(16), primary_key=True, default="llm")
    confidence: Mapped[float | None] = mapped_column(Float, nullable=True)


class DocumentReferencesCVE(Base):
    __tablename__ = "document_references_cve"
    document_id: Mapped[int] = mapped_column(ForeignKey("documents.id"), primary_key=True)
    cve_id: Mapped[int] = mapped_column(ForeignKey("cves.id"), primary_key=True)


class DocumentTargetsProduct(Base):
    __tablename__ = "document_targets_product"
    document_id: Mapped[int] = mapped_column(ForeignKey("documents.id"), primary_key=True)
    product_id: Mapped[int] = mapped_column(ForeignKey("products.id"), primary_key=True)


class DocumentMentionsTool(Base):
    __tablename__ = "document_mentions_tool"
    document_id: Mapped[int] = mapped_column(ForeignKey("documents.id"), primary_key=True)
    tool_id: Mapped[int] = mapped_column(ForeignKey("tools.id"), primary_key=True)


# Convenience groupings used by the metrics module.
ENTITY_MODELS = [
    Vulnerability,
    Technique,
    CVE,
    Product,
    Signature,
    Exploit,
    Tool,
    Document,
]

EDGE_MODELS = [
    WeaknessRelation,
    TechniqueRelation,
    TechniqueTargetsWeakness,
    WeaknessObservedCVE,
    SignatureDetectsWeakness,
    SignatureReferencesCVE,
    SignatureTargetsProduct,
    ExploitReferencesCVE,
    DocumentCoversWeakness,
    DocumentCoversTechnique,
    DocumentReferencesCVE,
    DocumentTargetsProduct,
    DocumentMentionsTool,
]
