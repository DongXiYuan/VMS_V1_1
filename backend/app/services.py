from __future__ import annotations

import json
from pathlib import Path
from typing import Iterable

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from vms_stage1.core import (
    StandardRecord,
    attach_previous_month,
    load_config,
    normalize_vuln_name,
    parse_assets,
    parse_nsfocus,
    parse_simple_xlsx,
)

from .models import Asset, ImportAnomaly, ImportBatch, ImportPreview, RecordChange, VulnerabilityRecord, utc_now


PROJECT_ROOT = Path(__file__).parents[2]
SAMPLES_DIR = PROJECT_ROOT / "samples"
MAPPINGS_PATH = PROJECT_ROOT / "prototype" / "config" / "field_mappings.json"


def first_existing_path(*candidates: Path) -> Path:
    for candidate in candidates:
        if candidate.exists():
            return candidate
    raise FileNotFoundError(f"未找到样例文件: {[str(candidate) for candidate in candidates]}")


def resolve_nsfocus_source(samples_dir: Path) -> Path:
    return first_existing_path(
        samples_dir / "绿盟",
        samples_dir / "绿盟.zip",
        samples_dir,
    )


def import_assets_from_sample(db: Session) -> dict[str, int]:
    config = load_config(MAPPINGS_PATH)
    parsed = parse_assets(first_existing_path(SAMPLES_DIR / "资产表（样例）.xlsx"), config["assets"])
    created = updated = 0
    for ip, values in parsed.items():
        asset = db.scalar(select(Asset).where(Asset.ip == ip))
        if not asset:
            asset = Asset(ip=ip)
            db.add(asset)
            created += 1
        else:
            updated += 1
        asset.organization = values["organization"]
        asset.project = values["project"]
        asset.workspace = values["workspace"]
        asset.owner = values["owner"]
        asset.raw_data = json.dumps(values, ensure_ascii=False)
    db.commit()
    return {"created": created, "updated": updated, "total": len(parsed)}


def assets_for_parser(db: Session) -> dict[str, dict[str, str]]:
    assets = db.scalars(select(Asset)).all()
    return {
        asset.ip: {
            "organization": asset.organization,
            "project": asset.project,
            "workspace": asset.workspace,
            "owner": asset.owner,
        }
        for asset in assets
    }


def record_to_stage1(record: VulnerabilityRecord) -> StandardRecord:
    return StandardRecord(
        scan_month=record.scan_month,
        scanner_type=record.scanner_type,
        ip=record.ip,
        port=record.port,
        protocol=record.protocol,
        service=record.service,
        organization=record.organization,
        project=record.project,
        workspace=record.workspace,
        owner=record.owner,
        severity=record.severity,
        vuln_name=record.vuln_name,
        vuln_detail=record.vuln_detail,
        verify_info=record.verify_info,
        fix_method=record.fix_method,
        cve=record.cve,
        handle_status=record.handle_status,
        remark=record.remark,
        previous_month_status=record.previous_month_status,
        previous_month_remark=record.previous_month_remark,
        asset_match_status=record.asset_match_status,
        source_file=record.source_file,
    )


def previous_month(scan_month: str) -> str:
    year, month = map(int, scan_month.split("-"))
    if month == 1:
        return f"{year - 1}-12"
    return f"{year}-{month - 1:02d}"


def publish_scanner_records(
    db: Session,
    scanner_type: str,
    scan_month: str,
    source_file: str,
    records: list[StandardRecord],
    anomalies: list[Anomaly],
) -> ImportBatch:
    previous = [
        record_to_stage1(record)
        for record in db.scalars(
            select(VulnerabilityRecord).where(VulnerabilityRecord.scan_month == previous_month(scan_month))
        )
    ]
    attach_previous_month(records, previous)
    for previous_batch in db.scalars(select(ImportBatch).where(
        ImportBatch.scanner_type == scanner_type,
        ImportBatch.scan_month == scan_month,
        ImportBatch.is_active.is_(True),
    )):
        previous_batch.is_active = False
    batch = ImportBatch(
        scanner_type=scanner_type,
        scan_month=scan_month,
        source_file=source_file,
        standard_count=len(records),
        anomaly_count=len(anomalies),
    )
    db.add(batch)
    db.flush()
    for anomaly in anomalies:
        db.add(ImportAnomaly(
            batch_id=batch.id,
            scanner_type=anomaly.scanner_type,
            source_file=anomaly.source_file,
            ip=anomaly.ip,
            anomaly_type=anomaly.anomaly_type,
            detail=anomaly.detail,
        ))
    for record in records:
        existing = db.scalar(select(VulnerabilityRecord).where(
            VulnerabilityRecord.scanner_type == record.scanner_type,
            VulnerabilityRecord.scan_month == record.scan_month,
            VulnerabilityRecord.ip == record.ip,
            VulnerabilityRecord.port == record.port,
            VulnerabilityRecord.normalized_vuln_name == normalize_vuln_name(record.vuln_name),
        ))
        if not existing:
            existing = VulnerabilityRecord(
                scanner_type=record.scanner_type,
                scan_month=record.scan_month,
                ip=record.ip,
                port=record.port,
                normalized_vuln_name=normalize_vuln_name(record.vuln_name),
            )
            db.add(existing)
        existing.protocol = record.protocol
        existing.service = record.service
        existing.organization = record.organization
        existing.project = record.project
        existing.workspace = record.workspace
        existing.owner = record.owner
        existing.severity = record.severity
        existing.vuln_name = record.vuln_name
        existing.vuln_detail = record.vuln_detail
        existing.verify_info = record.verify_info
        existing.fix_method = record.fix_method
        existing.cve = record.cve
        existing.previous_month_status = record.previous_month_status
        existing.previous_month_remark = record.previous_month_remark
        existing.asset_match_status = record.asset_match_status
        existing.source_file = record.source_file
        existing.batch_id = batch.id
    db.commit()
    db.refresh(batch)
    return batch


def import_sample_batch(db: Session, scan_month: str) -> dict[str, object]:
    config = load_config(MAPPINGS_PATH)
    assets = assets_for_parser(db)
    previous = [
        record_to_stage1(record)
        for record in db.scalars(
            select(VulnerabilityRecord).where(VulnerabilityRecord.scan_month == previous_month(scan_month))
        )
    ]
    results = [
        parse_simple_xlsx(first_existing_path(SAMPLES_DIR / "青藤云漏洞（样例）.xlsx"), scan_month, "青藤云", config["qingteng"], assets),
        parse_simple_xlsx(first_existing_path(SAMPLES_DIR / "阿里云漏洞（样例）.xlsx"), scan_month, "阿里云", config["aliyun"], assets),
        parse_nsfocus(resolve_nsfocus_source(SAMPLES_DIR), scan_month, config["nsfocus_index"], config["nsfocus_host"], assets),
    ]
    all_records = [record for result in results for record in result.records]
    attach_previous_month(all_records, previous)

    scanner_summaries = []
    batch_by_scanner: dict[str, ImportBatch] = {}
    for result in results:
        for previous_batch in db.scalars(select(ImportBatch).where(
            ImportBatch.scanner_type == result.scanner_type,
            ImportBatch.scan_month == scan_month,
            ImportBatch.is_active.is_(True),
        )):
            previous_batch.is_active = False
        batch = ImportBatch(
            scanner_type=result.scanner_type,
            scan_month=scan_month,
            source_file="samples",
            standard_count=len(result.records),
            anomaly_count=len(result.anomalies),
        )
        db.add(batch)
        db.flush()
        batch_by_scanner[result.scanner_type] = batch
        for anomaly in result.anomalies:
            db.add(ImportAnomaly(
                batch_id=batch.id,
                scanner_type=anomaly.scanner_type,
                source_file=anomaly.source_file,
                ip=anomaly.ip,
                anomaly_type=anomaly.anomaly_type,
                detail=anomaly.detail,
            ))
        scanner_summaries.append({
            "scanner_type": result.scanner_type,
            "batch_id": batch.id,
            "records": len(result.records),
            "anomalies": len(result.anomalies),
            "filtered_low": result.filtered_low,
        })

    for record in all_records:
        existing = db.scalar(select(VulnerabilityRecord).where(
            VulnerabilityRecord.scanner_type == record.scanner_type,
            VulnerabilityRecord.scan_month == record.scan_month,
            VulnerabilityRecord.ip == record.ip,
            VulnerabilityRecord.port == record.port,
            VulnerabilityRecord.normalized_vuln_name == normalize_vuln_name(record.vuln_name),
        ))
        if not existing:
            existing = VulnerabilityRecord(
                scanner_type=record.scanner_type,
                scan_month=record.scan_month,
                ip=record.ip,
                port=record.port,
                normalized_vuln_name=normalize_vuln_name(record.vuln_name),
            )
            db.add(existing)
        existing.protocol = record.protocol
        existing.service = record.service
        existing.organization = record.organization
        existing.project = record.project
        existing.workspace = record.workspace
        existing.owner = record.owner
        existing.severity = record.severity
        existing.vuln_name = record.vuln_name
        existing.vuln_detail = record.vuln_detail
        existing.verify_info = record.verify_info
        existing.fix_method = record.fix_method
        existing.cve = record.cve
        existing.previous_month_status = record.previous_month_status
        existing.previous_month_remark = record.previous_month_remark
        existing.asset_match_status = record.asset_match_status
        existing.source_file = record.source_file
        existing.batch_id = batch_by_scanner[record.scanner_type].id
    db.commit()
    return {"scan_month": scan_month, "total_records": len(all_records), "scanners": scanner_summaries}


def update_record(db: Session, record: VulnerabilityRecord, handle_status: str | None, remark: str | None, changed_by: str) -> VulnerabilityRecord:
    changes = {"handle_status": handle_status, "remark": remark}
    for field_name, new_value in changes.items():
        if new_value is None:
            continue
        old_value = getattr(record, field_name)
        if old_value == new_value:
            continue
        setattr(record, field_name, new_value)
        db.add(RecordChange(record_id=record.id, field_name=field_name, old_value=old_value, new_value=new_value, changed_by=changed_by))
    db.commit()
    db.refresh(record)
    return record


def batch_update_records(
    db: Session,
    records: Iterable[VulnerabilityRecord],
    handle_status: str | None,
    remark: str | None,
    changed_by: str,
) -> int:
    updated_count = 0
    for record in records:
        if record.is_deleted:
            continue
        before = (record.handle_status, record.remark)
        update_record(db, record, handle_status, remark, changed_by)
        after = (record.handle_status, record.remark)
        if before != after:
            updated_count += 1
    return updated_count


def soft_delete_records(
    db: Session,
    records: Iterable[VulnerabilityRecord],
    delete_reason: str,
    changed_by: str,
) -> int:
    deleted_count = 0
    deleted_at = utc_now()
    for record in records:
        if record.is_deleted:
            continue
        old_is_deleted = str(record.is_deleted)
        old_deleted_reason = record.deleted_reason
        old_deleted_by = record.deleted_by
        record.is_deleted = True
        record.deleted_at = deleted_at
        record.deleted_by = changed_by
        record.deleted_reason = delete_reason
        db.add(RecordChange(record_id=record.id, field_name="is_deleted", old_value=old_is_deleted, new_value="True", changed_by=changed_by))
        db.add(RecordChange(record_id=record.id, field_name="deleted_reason", old_value=old_deleted_reason, new_value=delete_reason, changed_by=changed_by))
        if old_deleted_by != changed_by:
            db.add(RecordChange(record_id=record.id, field_name="deleted_by", old_value=old_deleted_by, new_value=changed_by, changed_by=changed_by))
        deleted_count += 1
    db.commit()
    return deleted_count


def rematch_unmatched_records(db: Session, records: Iterable[VulnerabilityRecord], changed_by: str) -> dict[str, int]:
    matched_count = 0
    unmatched_count = 0
    assets = {asset.ip: asset for asset in db.scalars(select(Asset)).all()}
    for record in records:
        if record.is_deleted or record.asset_match_status != "待补充资产":
            continue
        asset = assets.get(record.ip)
        if not asset:
            unmatched_count += 1
            continue
        old_match_status = record.asset_match_status
        record.organization = asset.organization
        record.project = asset.project
        record.workspace = asset.workspace
        record.owner = asset.owner
        record.asset_match_status = "已匹配"
        db.add(
            RecordChange(
                record_id=record.id,
                field_name="asset_match_status",
                old_value=old_match_status,
                new_value="已匹配",
                changed_by=changed_by,
            )
        )
        matched_count += 1
    db.commit()
    return {"matched_count": matched_count, "unmatched_count": unmatched_count}


def reset_database(db: Session) -> None:
    for model in (RecordChange, ImportAnomaly, VulnerabilityRecord, ImportBatch, ImportPreview, Asset):
        db.execute(delete(model))
    db.commit()
