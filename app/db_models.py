from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Integer,
    Numeric,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import UUID, INET, JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    pass


# -------------------------
# RAW (append-only)
# -------------------------
class RawIngest(Base):
    __tablename__ = "raw_ingests"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    source: Mapped[str] = mapped_column(Text, nullable=False)  # e.g. "nessus_pro"
    nessus_scan_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    scan_name: Mapped[str] = mapped_column(Text, nullable=False)
    folder_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    exported_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    file_sha256: Mapped[str] = mapped_column(Text, nullable=False, unique=True)
    row_count: Mapped[int] = mapped_column(Integer, nullable=False)
    ingested_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=datetime.utcnow)

    rows = relationship("RawNessusRow", back_populates="ingest")


class RawNessusRow(Base):
    __tablename__ = "raw_nessus_rows"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    ingest_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("raw_ingests.id"), nullable=False)
    row_num: Mapped[int] = mapped_column(Integer, nullable=False)
    row_json: Mapped[dict] = mapped_column(JSONB, nullable=False)

    # convenience columns (optional but useful)
    severity: Mapped[int | None] = mapped_column(Integer, nullable=True)
    plugin_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    plugin_name: Mapped[str | None] = mapped_column(Text, nullable=True)
    cve_text: Mapped[str | None] = mapped_column(Text, nullable=True)
    host_ip: Mapped[str | None] = mapped_column(INET, nullable=True)
    host_fqdn: Mapped[str | None] = mapped_column(Text, nullable=True)
    port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    protocol: Mapped[str | None] = mapped_column(Text, nullable=True)

    ingest = relationship("RawIngest", back_populates="rows")


# -------------------------
# NORMALIZED
# -------------------------
class Scan(Base):
    __tablename__ = "scans"
    __table_args__ = (UniqueConstraint("nessus_scan_id", "exported_at", name="uq_scans_nessus_exported"),)

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    nessus_scan_id: Mapped[int] = mapped_column(Integer, nullable=False)
    scan_name: Mapped[str] = mapped_column(Text, nullable=False)
    folder_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    folder_name: Mapped[str | None] = mapped_column(Text, nullable=True)
    scanner_url: Mapped[str] = mapped_column(Text, nullable=False)
    scan_start: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    scan_end: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    exported_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class Asset(Base):
    __tablename__ = "assets"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    canonical_name: Mapped[str] = mapped_column(Text, nullable=False)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=datetime.utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=datetime.utcnow)


class AssetIdentity(Base):
    __tablename__ = "asset_identities"
    __table_args__ = (UniqueConstraint("identity_type", "identity_value", name="uq_asset_identity_type_value"),)

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    asset_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("assets.id"), nullable=False)

    identity_type: Mapped[str] = mapped_column(Text, nullable=False)  # ip|fqdn|hostname
    identity_value: Mapped[str] = mapped_column(Text, nullable=False)

    ip_value: Mapped[str | None] = mapped_column(INET, nullable=True)

    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=datetime.utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=datetime.utcnow)


class Plugin(Base):
    __tablename__ = "plugins"

    plugin_id: Mapped[int] = mapped_column(Integer, primary_key=True)
    plugin_name: Mapped[str] = mapped_column(Text, nullable=False)
    family: Mapped[str | None] = mapped_column(Text, nullable=True)
    synopsis: Mapped[str | None] = mapped_column(Text, nullable=True)
    solution: Mapped[str | None] = mapped_column(Text, nullable=True)
    cvss_base: Mapped[float | None] = mapped_column(Numeric, nullable=True)


class Finding(Base):
    __tablename__ = "findings"
    __table_args__ = (UniqueConstraint("asset_id", "plugin_id", name="uq_finding_asset_plugin"),)

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    asset_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("assets.id"), nullable=False)
    plugin_id: Mapped[int] = mapped_column(Integer, ForeignKey("plugins.plugin_id"), nullable=False)

    severity_label: Mapped[str] = mapped_column(Text, nullable=False)  # Critical|High|Medium|Low|Informational
    severity_nessus: Mapped[int] = mapped_column(Integer, nullable=False)

    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=datetime.utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=datetime.utcnow)

    status: Mapped[str] = mapped_column(Text, nullable=False, default="open")
    is_informational: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)


class FindingInstance(Base):
    __tablename__ = "finding_instances"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    finding_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("findings.id"), nullable=False)
    scan_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("scans.id"), nullable=False)

    port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    protocol: Mapped[str | None] = mapped_column(Text, nullable=True)
    plugin_output: Mapped[str | None] = mapped_column(Text, nullable=True)


# -------------------------
# CVE truth
# -------------------------
class Cve(Base):
    __tablename__ = "cves"
    cve: Mapped[str] = mapped_column(Text, primary_key=True)


class FindingCve(Base):
    __tablename__ = "finding_cves"
    __table_args__ = (UniqueConstraint("finding_id", "cve", name="uq_finding_cve"),)

    finding_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("findings.id"), primary_key=True)
    cve: Mapped[str] = mapped_column(Text, ForeignKey("cves.cve"), primary_key=True)
    source: Mapped[str] = mapped_column(Text, nullable=False)  # csv|parsed_text
