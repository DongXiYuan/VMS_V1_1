from __future__ import annotations

from datetime import UTC, datetime, timedelta

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .database import Base


def utc_now() -> datetime:
    return datetime.now(UTC)


def preview_expires_at() -> datetime:
    return utc_now() + timedelta(hours=24)


class Asset(Base):
    __tablename__ = "assets"

    id: Mapped[int] = mapped_column(primary_key=True)
    ip: Mapped[str] = mapped_column(String(45), unique=True, index=True)
    organization: Mapped[str] = mapped_column(String(200), default="")
    project: Mapped[str] = mapped_column(String(200), default="")
    workspace: Mapped[str] = mapped_column(String(200), default="")
    owner: Mapped[str] = mapped_column(String(100), default="")
    raw_data: Mapped[str] = mapped_column(Text, default="{}")
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, onupdate=utc_now)


class ImportBatch(Base):
    __tablename__ = "import_batches"

    id: Mapped[int] = mapped_column(primary_key=True)
    scanner_type: Mapped[str] = mapped_column(String(30), index=True)
    scan_month: Mapped[str] = mapped_column(String(7), index=True)
    source_file: Mapped[str] = mapped_column(String(255), default="")
    status: Mapped[str] = mapped_column(String(30), default="published")
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    standard_count: Mapped[int] = mapped_column(Integer, default=0)
    anomaly_count: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)


class VulnerabilityRecord(Base):
    __tablename__ = "vulnerability_records"
    __table_args__ = (
        UniqueConstraint("scanner_type", "scan_month", "ip", "port", "normalized_vuln_name", name="uq_vulnerability_business_key"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    scanner_type: Mapped[str] = mapped_column(String(30), index=True)
    scan_month: Mapped[str] = mapped_column(String(7), index=True)
    ip: Mapped[str] = mapped_column(String(45), index=True)
    port: Mapped[str] = mapped_column(String(20), default="")
    protocol: Mapped[str] = mapped_column(String(20), default="")
    service: Mapped[str] = mapped_column(String(100), default="")
    organization: Mapped[str] = mapped_column(String(200), default="")
    project: Mapped[str] = mapped_column(String(200), default="", index=True)
    workspace: Mapped[str] = mapped_column(String(200), default="")
    owner: Mapped[str] = mapped_column(String(100), default="")
    severity: Mapped[str] = mapped_column(String(20), default="", index=True)
    vuln_name: Mapped[str] = mapped_column(String(500))
    normalized_vuln_name: Mapped[str] = mapped_column(String(500), index=True)
    vuln_detail: Mapped[str] = mapped_column(Text, default="")
    verify_info: Mapped[str] = mapped_column(Text, default="")
    fix_method: Mapped[str] = mapped_column(Text, default="")
    cve: Mapped[str] = mapped_column(String(200), default="")
    handle_status: Mapped[str] = mapped_column(String(30), default="待修复", index=True)
    remark: Mapped[str] = mapped_column(Text, default="")
    previous_month_status: Mapped[str] = mapped_column(String(30), default="无")
    previous_month_remark: Mapped[str] = mapped_column(Text, default="无")
    asset_match_status: Mapped[str] = mapped_column(String(30), default="已匹配", index=True)
    is_deleted: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    deleted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    deleted_by: Mapped[str] = mapped_column(String(100), default="")
    deleted_reason: Mapped[str] = mapped_column(Text, default="")
    source_file: Mapped[str] = mapped_column(String(255), default="")
    batch_id: Mapped[int | None] = mapped_column(ForeignKey("import_batches.id"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, onupdate=utc_now)

    changes: Mapped[list["RecordChange"]] = relationship(back_populates="record", cascade="all, delete-orphan")


class RecordChange(Base):
    __tablename__ = "record_changes"

    id: Mapped[int] = mapped_column(primary_key=True)
    record_id: Mapped[int] = mapped_column(ForeignKey("vulnerability_records.id"), index=True)
    field_name: Mapped[str] = mapped_column(String(50))
    old_value: Mapped[str] = mapped_column(Text, default="")
    new_value: Mapped[str] = mapped_column(Text, default="")
    changed_by: Mapped[str] = mapped_column(String(100), default="prototype-admin")
    changed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)

    record: Mapped[VulnerabilityRecord] = relationship(back_populates="changes")


class ImportAnomaly(Base):
    __tablename__ = "import_anomalies"

    id: Mapped[int] = mapped_column(primary_key=True)
    batch_id: Mapped[int | None] = mapped_column(ForeignKey("import_batches.id"), index=True)
    scanner_type: Mapped[str] = mapped_column(String(30))
    source_file: Mapped[str] = mapped_column(String(255), default="")
    ip: Mapped[str] = mapped_column(String(45), default="")
    anomaly_type: Mapped[str] = mapped_column(String(100))
    detail: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)


class ImportPreview(Base):
    __tablename__ = "import_previews"

    id: Mapped[int] = mapped_column(primary_key=True)
    import_type: Mapped[str] = mapped_column(String(30), index=True)
    scanner_type: Mapped[str] = mapped_column(String(30), default="")
    scan_month: Mapped[str] = mapped_column(String(7), default="")
    original_filename: Mapped[str] = mapped_column(String(255))
    stored_path: Mapped[str] = mapped_column(String(500))
    sha256: Mapped[str] = mapped_column(String(64), index=True)
    status: Mapped[str] = mapped_column(String(30), default="preview", index=True)
    has_blocking_errors: Mapped[bool] = mapped_column(Boolean, default=False)
    summary_json: Mapped[str] = mapped_column(Text, default="{}")
    payload_json: Mapped[str] = mapped_column(Text, default="{}")
    issues_json: Mapped[str] = mapped_column(Text, default="[]")
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=preview_expires_at)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    published_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
