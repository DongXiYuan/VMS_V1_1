from __future__ import annotations

import hashlib
import json
import re
import shutil
from dataclasses import asdict
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.orm import Session

from vms_stage1.core import Anomaly, StandardRecord, load_config, parse_assets, parse_nsfocus, parse_simple_xlsx

from .models import Asset, ImportBatch, ImportPreview
from .services import MAPPINGS_PATH, assets_for_parser, publish_scanner_records


UPLOAD_ROOT = Path(__file__).parents[1] / "data" / "uploads"
PREVIEW_DIR = UPLOAD_ROOT / "previews"
PUBLISHED_DIR = UPLOAD_ROOT / "published"
SCANNER_EXTENSIONS = {"青藤云": {".xls", ".xlsx"}, "阿里云": {".xls", ".xlsx"}, "绿盟": {".zip"}}
BLOCKING_TYPES = {"文件结构异常", "缺少索引", "索引结构异常", "ZIP 路径越界", "文件格式异常"}


def utc_now() -> datetime:
    return datetime.now(UTC)


def json_dump(value: object) -> str:
    return json.dumps(value, ensure_ascii=False)


def save_preview_file(original_filename: str, content: bytes) -> tuple[Path, str]:
    PREVIEW_DIR.mkdir(parents=True, exist_ok=True)
    suffix = Path(original_filename).suffix.lower()
    path = PREVIEW_DIR / f"{uuid4().hex}{suffix}"
    path.write_bytes(content)
    return path, hashlib.sha256(content).hexdigest()


def preview_to_dict(preview: ImportPreview) -> dict[str, object]:
    summary = json.loads(preview.summary_json)
    return {
        "id": preview.id,
        "import_type": preview.import_type,
        "scanner_type": preview.scanner_type,
        "scan_month": preview.scan_month,
        "original_filename": preview.original_filename,
        "status": preview.status,
        "has_blocking_errors": preview.has_blocking_errors,
        "summary": summary,
        "issues": json.loads(preview.issues_json),
        "expires_at": preview.expires_at,
        "replacement_warning": bool(summary.get("replacement_warning", False)),
    }


def create_blocking_preview(
    db: Session,
    *,
    import_type: str,
    original_filename: str,
    stored_path: Path,
    sha256: str,
    issue_type: str,
    detail: str,
    scanner_type: str = "",
    scan_month: str = "",
    summary: dict[str, object] | None = None,
) -> ImportPreview:
    preview = ImportPreview(
        import_type=import_type,
        scanner_type=scanner_type,
        scan_month=scan_month,
        original_filename=original_filename,
        stored_path=str(stored_path),
        sha256=sha256,
        has_blocking_errors=True,
        summary_json=json_dump(summary or {}),
        issues_json=json_dump([{
            "level": "blocking",
            "issue_type": issue_type,
            "detail": detail,
            "ip": "",
            "source_file": original_filename,
        }]),
    )
    db.add(preview)
    db.commit()
    db.refresh(preview)
    return preview


def create_asset_preview(db: Session, original_filename: str, content: bytes) -> ImportPreview:
    expire_old_previews(db)
    if Path(original_filename).suffix.lower() not in {".xls", ".xlsx"}:
        raise ValueError("资产表仅支持 .xls 或 .xlsx 文件")
    stored_path, sha256 = save_preview_file(original_filename, content)
    try:
        config = load_config(MAPPINGS_PATH)
        parsed = parse_assets(stored_path, config["assets"])
    except Exception as error:
        return create_blocking_preview(
            db,
            import_type="assets",
            original_filename=original_filename,
            stored_path=stored_path,
            sha256=sha256,
            issue_type="文件结构异常",
            detail=f"无法读取资产表: {error}",
            summary={"created": 0, "updated": 0, "unchanged": 0, "invalid": 0},
        )
    current = assets_for_parser(db)
    created = updated = unchanged = 0
    for ip, values in parsed.items():
        if ip not in current:
            created += 1
        elif current[ip] == values:
            unchanged += 1
        else:
            updated += 1
    preview = ImportPreview(
        import_type="assets",
        original_filename=original_filename,
        stored_path=str(stored_path),
        sha256=sha256,
        summary_json=json_dump({"created": created, "updated": updated, "unchanged": unchanged, "invalid": 0}),
        payload_json=json_dump(parsed),
    )
    db.add(preview)
    db.commit()
    db.refresh(preview)
    return preview


def anomaly_to_issue(anomaly: Anomaly) -> dict[str, str]:
    return {
        "level": "blocking" if anomaly.anomaly_type in BLOCKING_TYPES else "warning",
        "issue_type": anomaly.anomaly_type,
        "detail": anomaly.detail,
        "ip": anomaly.ip,
        "source_file": anomaly.source_file,
    }


def create_vulnerability_preview(
    db: Session, scanner_type: str, scan_month: str, original_filename: str, content: bytes
) -> ImportPreview:
    expire_old_previews(db)
    if scanner_type not in SCANNER_EXTENSIONS:
        raise ValueError("扫描器类型必须为青藤云、阿里云或绿盟")
    if not re.fullmatch(r"\d{4}-\d{2}", scan_month):
        raise ValueError("扫描月份格式必须为 YYYY-MM")
    expected_extensions = SCANNER_EXTENSIONS[scanner_type]
    if Path(original_filename).suffix.lower() not in expected_extensions:
        allowed = "、".join(sorted(expected_extensions))
        raise ValueError(f"{scanner_type}仅支持 {allowed} 文件")
    stored_path, sha256 = save_preview_file(original_filename, content)
    config = load_config(MAPPINGS_PATH)
    assets = assets_for_parser(db)
    try:
        if scanner_type == "青藤云":
            result = parse_simple_xlsx(stored_path, scan_month, scanner_type, config["qingteng"], assets)
        elif scanner_type == "阿里云":
            result = parse_simple_xlsx(stored_path, scan_month, scanner_type, config["aliyun"], assets)
        else:
            result = parse_nsfocus(stored_path, scan_month, config["nsfocus_index"], config["nsfocus_host"], assets)
    except Exception as error:
        return create_blocking_preview(
            db,
            import_type="vulnerabilities",
            scanner_type=scanner_type,
            scan_month=scan_month,
            original_filename=original_filename,
            stored_path=stored_path,
            sha256=sha256,
            issue_type="文件结构异常",
            detail=f"无法读取扫描文件: {error}",
            summary={
                "records": 0,
                "filtered_low": 0,
                "merged_duplicates": 0,
                "anomalies": 1,
                "indexed_hosts": 0,
                "parsed_host_reports": 0,
                "skipped_hosts": 0,
                "replacement_warning": False,
            },
        )
    issues = [anomaly_to_issue(anomaly) for anomaly in result.anomalies]
    replacement_warning = db.scalar(select(ImportBatch.id).where(
        ImportBatch.scanner_type == scanner_type,
        ImportBatch.scan_month == scan_month,
        ImportBatch.is_active.is_(True),
    )) is not None
    if replacement_warning:
        issues.append({
            "level": "warning",
            "issue_type": "替换当前有效批次",
            "detail": f"{scanner_type} {scan_month} 已有有效批次，发布后将替换当前版本",
            "ip": "",
            "source_file": original_filename,
        })
    summary = {
        "records": len(result.records),
        "filtered_low": result.filtered_low,
        "merged_duplicates": result.merged_duplicates,
        "anomalies": len(result.anomalies),
        "indexed_hosts": result.indexed_hosts,
        "parsed_host_reports": result.parsed_host_reports,
        "skipped_hosts": result.skipped_hosts,
        "replacement_warning": replacement_warning,
    }
    preview = ImportPreview(
        import_type="vulnerabilities",
        scanner_type=scanner_type,
        scan_month=scan_month,
        original_filename=original_filename,
        stored_path=str(stored_path),
        sha256=sha256,
        has_blocking_errors=any(issue["level"] == "blocking" for issue in issues),
        summary_json=json_dump(summary),
        payload_json=json_dump([asdict(record) for record in result.records]),
        issues_json=json_dump(issues),
    )
    db.add(preview)
    db.commit()
    db.refresh(preview)
    return preview


def get_preview(db: Session, preview_id: int) -> ImportPreview:
    preview = db.scalar(select(ImportPreview).where(ImportPreview.id == preview_id))
    if not preview:
        raise ValueError("预览批次不存在")
    return preview


def ensure_publishable(preview: ImportPreview, confirm_warnings: bool = False) -> None:
    if preview.status != "preview":
        raise ValueError("预览批次不是待发布状态")
    expires_at = preview.expires_at
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=UTC)
    if expires_at <= utc_now():
        raise ValueError("预览批次已过期，请重新上传")
    if preview.has_blocking_errors:
        raise ValueError("预览存在阻止发布的错误")
    issues = json.loads(preview.issues_json)
    if any(issue["level"] == "warning" for issue in issues) and not confirm_warnings:
        raise ValueError("预览存在警告，请确认后发布")


def move_to_published(preview: ImportPreview, category: str, folder: str) -> Path:
    destination_dir = PUBLISHED_DIR / category / folder
    destination_dir.mkdir(parents=True, exist_ok=True)
    source = Path(preview.stored_path)
    destination = destination_dir / f"{uuid4().hex}_{preview.original_filename}"
    shutil.move(str(source), destination)
    preview.stored_path = str(destination)
    return destination


def publish_asset_preview(db: Session, preview_id: int) -> dict[str, object]:
    preview = get_preview(db, preview_id)
    if preview.import_type != "assets":
        raise ValueError("该预览批次不是资产表")
    ensure_publishable(preview)
    parsed: dict[str, dict[str, str]] = json.loads(preview.payload_json)
    for ip, values in parsed.items():
        asset = db.scalar(select(Asset).where(Asset.ip == ip))
        if not asset:
            asset = Asset(ip=ip)
            db.add(asset)
        asset.organization = values["organization"]
        asset.project = values["project"]
        asset.workspace = values["workspace"]
        asset.owner = values["owner"]
        asset.raw_data = json_dump(values)
    destination = move_to_published(preview, "assets", utc_now().date().isoformat())
    preview.status = "published"
    preview.published_at = utc_now()
    db.commit()
    return {"id": preview.id, "status": preview.status, "stored_path": str(destination), **json.loads(preview.summary_json)}


def publish_vulnerability_preview(db: Session, preview_id: int, confirm_warnings: bool) -> dict[str, object]:
    preview = get_preview(db, preview_id)
    if preview.import_type != "vulnerabilities":
        raise ValueError("该预览批次不是漏洞扫描文件")
    ensure_publishable(preview, confirm_warnings)
    records = [StandardRecord(**values) for values in json.loads(preview.payload_json)]
    issues = json.loads(preview.issues_json)
    anomalies = [
        Anomaly(
            scanner_type=preview.scanner_type,
            source_file=issue["source_file"],
            ip=issue["ip"],
            anomaly_type=issue["issue_type"],
            detail=issue["detail"],
        )
        for issue in issues
        if issue["issue_type"] != "替换当前有效批次"
    ]
    category = {"青藤云": "qingteng", "阿里云": "aliyun", "绿盟": "nsfocus"}[preview.scanner_type]
    destination = move_to_published(preview, category, preview.scan_month)
    batch = publish_scanner_records(
        db,
        scanner_type=preview.scanner_type,
        scan_month=preview.scan_month,
        source_file=preview.original_filename,
        records=records,
        anomalies=anomalies,
    )
    preview.status = "published"
    preview.published_at = utc_now()
    db.commit()
    return {
        "id": preview.id,
        "status": preview.status,
        "batch_id": batch.id,
        "stored_path": str(destination),
        **json.loads(preview.summary_json),
    }


def expire_old_previews(db: Session) -> dict[str, int]:
    expired = deleted_files = 0
    for preview in db.scalars(select(ImportPreview).where(ImportPreview.status == "preview")):
        expires_at = preview.expires_at
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=UTC)
        if expires_at > utc_now():
            continue
        path = Path(preview.stored_path)
        if path.exists():
            path.unlink()
            deleted_files += 1
        preview.status = "expired"
        expired += 1
    db.commit()
    return {"expired": expired, "deleted_files": deleted_files}
