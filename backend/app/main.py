from __future__ import annotations

from pathlib import Path

from fastapi import Depends, FastAPI, File, Form, HTTPException, Path as ApiPath, Query, UploadFile
from fastapi.responses import FileResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .database import Base, engine, ensure_sqlite_schema, get_db
from .export_services import export_unmatched_assets_xlsx, export_zip_bytes
from .models import Asset, ImportAnomaly, ImportBatch, ImportPreview, RecordChange, VulnerabilityRecord
from .schemas import (
    BatchActionResult,
    ChangeOut,
    ListResponse,
    PreviewOut,
    PublishRequest,
    RecordBatchDelete,
    RecordBatchUpdate,
    RecordOut,
    RecordUpdate,
    RematchRequest,
    SampleImportRequest,
)
from .services import (
    batch_update_records,
    import_assets_from_sample,
    import_sample_batch,
    previous_month,
    rematch_unmatched_records,
    soft_delete_records,
    update_record,
)
from .upload_services import (
    create_asset_preview,
    create_vulnerability_preview,
    expire_old_previews,
    get_preview,
    preview_to_dict,
    publish_asset_preview,
    publish_vulnerability_preview,
)


Base.metadata.create_all(bind=engine)
ensure_sqlite_schema()

app = FastAPI(
    title="VMS API",
    description="漏洞管理系统后端接口",
    version="1.1.0",
)

STATIC_DIR = Path(__file__).parent / "static"
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

REOPENED_SOURCE_STATUSES = {"已修复", "主机已关机", "采用缓解措施"}
DISPOSED_STATUSES = {"已修复", "采用缓解措施", "主机已关机", "项目已下线"}
UNRESOLVED_STATUSES = {"待修复", "已通知", "当前无法修复"}


def apply_month_filters(query, column, scan_month: str | None, scan_month_from: str | None, scan_month_to: str | None):
    if scan_month:
        return query.where(column == scan_month)
    if scan_month_from:
        query = query.where(column >= scan_month_from)
    if scan_month_to:
        query = query.where(column <= scan_month_to)
    return query


def apply_deleted_filter(query, include_deleted: bool = False):
    if include_deleted:
        return query
    return query.where(VulnerabilityRecord.is_deleted.is_(False))


def uses_month_window(scan_month: str | None, scan_month_from: str | None, scan_month_to: str | None) -> bool:
    return bool(scan_month or scan_month_from or scan_month_to)


def previous_lookup_key(
    scanner_type: str,
    scan_month: str,
    ip: str,
    port: str,
    normalized_vuln_name: str,
) -> tuple[str, str, str, str, str]:
    return (scanner_type, scan_month, ip, port, normalized_vuln_name)


def business_lookup_key(
    scanner_type: str,
    ip: str,
    port: str,
    normalized_vuln_name: str,
) -> tuple[str, str, str, str]:
    return (scanner_type, ip, port, normalized_vuln_name)


def compute_reopened_fields(record: VulnerabilityRecord, previous: VulnerabilityRecord | None) -> tuple[bool, str]:
    previous_status = previous.handle_status if previous else record.previous_month_status
    if previous_status in REOPENED_SOURCE_STATUSES:
        return True, previous_status
    return False, ""


def load_previous_map(db: Session, records: list[VulnerabilityRecord]) -> dict[tuple[str, str, str, str, str], VulnerabilityRecord]:
    previous_months = {previous_month(item.scan_month) for item in records}
    if not previous_months:
        return {}
    previous_records = db.scalars(
        select(VulnerabilityRecord).where(
            VulnerabilityRecord.scan_month.in_(previous_months),
            VulnerabilityRecord.is_deleted.is_(False),
        )
    ).all()
    return {
        previous_lookup_key(
            previous_record.scanner_type,
            previous_record.scan_month,
            previous_record.ip,
            previous_record.port,
            previous_record.normalized_vuln_name,
        ): previous_record
        for previous_record in previous_records
    }


def load_first_detected_map(db: Session, records: list[VulnerabilityRecord]) -> dict[tuple[str, str, str, str], object]:
    if not records:
        return {}
    historical_records = db.scalars(
        select(VulnerabilityRecord).where(
            VulnerabilityRecord.is_deleted.is_(False),
            VulnerabilityRecord.scanner_type.in_(sorted({item.scanner_type for item in records})),
            VulnerabilityRecord.ip.in_(sorted({item.ip for item in records})),
            VulnerabilityRecord.port.in_(sorted({item.port for item in records})),
            VulnerabilityRecord.normalized_vuln_name.in_(sorted({item.normalized_vuln_name for item in records})),
        )
    ).all()
    first_detected_map: dict[tuple[str, str, str, str], object] = {}
    for historical_record in historical_records:
        key = business_lookup_key(
            historical_record.scanner_type,
            historical_record.ip,
            historical_record.port,
            historical_record.normalized_vuln_name,
        )
        earliest = first_detected_map.get(key)
        if earliest is None or historical_record.created_at < earliest:
            first_detected_map[key] = historical_record.created_at
    return first_detected_map


def record_to_response_item(
    record: VulnerabilityRecord,
    live_previous_map: dict[tuple[str, str, str, str, str], VulnerabilityRecord],
    first_detected_map: dict[tuple[str, str, str, str], object],
) -> dict[str, object]:
    previous = live_previous_map.get(
        previous_lookup_key(
            record.scanner_type,
            previous_month(record.scan_month),
            record.ip,
            record.port,
            record.normalized_vuln_name,
        )
    )
    first_detected_at = first_detected_map.get(
        business_lookup_key(record.scanner_type, record.ip, record.port, record.normalized_vuln_name),
        record.created_at,
    )
    previous_status = previous.handle_status if previous else record.previous_month_status
    previous_remark = previous.remark if previous else record.previous_month_remark
    is_reopened, reopened_from_status = compute_reopened_fields(record, previous)
    return {
        "id": record.id,
        "scan_month": record.scan_month,
        "scanner_type": record.scanner_type,
        "ip": record.ip,
        "port": record.port,
        "protocol": record.protocol,
        "service": record.service,
        "organization": record.organization,
        "project": record.project,
        "workspace": record.workspace,
        "owner": record.owner,
        "severity": record.severity,
        "vuln_name": record.vuln_name,
        "vuln_detail": record.vuln_detail,
        "verify_info": record.verify_info,
        "fix_method": record.fix_method,
        "first_detected_at": first_detected_at,
        "handle_status": record.handle_status,
        "remark": record.remark,
        "previous_month_status": previous_status or "无",
        "previous_month_remark": previous_remark or "无",
        "is_reopened": is_reopened,
        "reopened_from_status": reopened_from_status,
        "asset_match_status": record.asset_match_status,
        "is_deleted": record.is_deleted,
        "deleted_at": record.deleted_at,
        "deleted_by": record.deleted_by,
        "deleted_reason": record.deleted_reason,
        "source_file": record.source_file,
    }


def months_for_statistics(db: Session, scan_month: str | None, scan_month_from: str | None, scan_month_to: str | None) -> list[str]:
    query = select(VulnerabilityRecord.scan_month).where(VulnerabilityRecord.is_deleted.is_(False))
    query = apply_month_filters(query, VulnerabilityRecord.scan_month, scan_month, scan_month_from, scan_month_to)
    months = sorted({value for value in db.scalars(query).all() if value})
    if uses_month_window(scan_month, scan_month_from, scan_month_to):
        return months
    return months[-6:]


def unmatched_records_query(scan_month: str | None, scan_month_from: str | None, scan_month_to: str | None, scanner_type: str | None):
    query = select(VulnerabilityRecord).where(
        VulnerabilityRecord.is_deleted.is_(False),
        VulnerabilityRecord.asset_match_status == "待补充资产",
    )
    query = apply_month_filters(query, VulnerabilityRecord.scan_month, scan_month, scan_month_from, scan_month_to)
    if scanner_type:
        query = query.where(VulnerabilityRecord.scanner_type == scanner_type)
    return query


def load_filtered_records(
    db: Session,
    scan_month: str | None = None,
    scan_month_from: str | None = None,
    scan_month_to: str | None = None,
    scanner_type: str | None = None,
    project: str | None = None,
    vuln_name: str | None = None,
) -> list[VulnerabilityRecord]:
    query = apply_deleted_filter(select(VulnerabilityRecord))
    query = apply_month_filters(query, VulnerabilityRecord.scan_month, scan_month, scan_month_from, scan_month_to)
    if scanner_type:
        query = query.where(VulnerabilityRecord.scanner_type == scanner_type)
    if project:
        query = query.where(VulnerabilityRecord.project == project)
    if vuln_name:
        query = query.where(VulnerabilityRecord.vuln_name == vuln_name)
    return db.scalars(
        query.order_by(
            VulnerabilityRecord.scan_month,
            VulnerabilityRecord.project,
            VulnerabilityRecord.scanner_type,
            VulnerabilityRecord.ip,
            VulnerabilityRecord.port,
            VulnerabilityRecord.vuln_name,
        )
    ).all()


def build_record_items(db: Session, records: list[VulnerabilityRecord]) -> list[dict[str, object]]:
    previous_map = load_previous_map(db, records)
    first_detected_map = load_first_detected_map(db, records)
    return [record_to_response_item(item, previous_map, first_detected_map) for item in records]


@app.get("/", include_in_schema=False)
def root() -> FileResponse:
    return FileResponse(STATIC_DIR / "index.html", headers={"Cache-Control": "no-store"})


@app.get("/favicon.ico", include_in_schema=False)
def favicon() -> Response:
    return Response(status_code=204)


@app.get("/api/health", summary="健康检查")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/api/dev/import-assets-sample", summary="导入资产表示例")
def import_assets_sample(db: Session = Depends(get_db)) -> dict[str, int]:
    return import_assets_from_sample(db)


@app.post("/api/imports/assets/preview", response_model=PreviewOut, summary="上传资产表并预览")
async def preview_assets(file: UploadFile = File(...), db: Session = Depends(get_db)) -> dict[str, object]:
    try:
        return preview_to_dict(create_asset_preview(db, file.filename or "", await file.read()))
    except ValueError as error:
        raise HTTPException(status_code=400, detail=str(error)) from error


@app.post("/api/imports/assets/{preview_id}/publish", summary="发布资产表预览")
def publish_assets(preview_id: int, db: Session = Depends(get_db)) -> dict[str, object]:
    try:
        return publish_asset_preview(db, preview_id)
    except ValueError as error:
        raise HTTPException(status_code=409, detail=str(error)) from error


@app.post("/api/imports/vulnerabilities/preview", response_model=PreviewOut, summary="上传漏洞文件并预览")
async def preview_vulnerabilities(
    scanner_type: str = Form(...),
    scan_month: str = Form(...),
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
) -> dict[str, object]:
    try:
        preview = create_vulnerability_preview(db, scanner_type, scan_month, file.filename or "", await file.read())
        return preview_to_dict(preview)
    except ValueError as error:
        raise HTTPException(status_code=400, detail=str(error)) from error


@app.post("/api/imports/vulnerabilities/{preview_id}/publish", summary="发布漏洞预览")
def publish_vulnerabilities(preview_id: int, request: PublishRequest, db: Session = Depends(get_db)) -> dict[str, object]:
    try:
        return publish_vulnerability_preview(db, preview_id, request.confirm_warnings)
    except ValueError as error:
        raise HTTPException(status_code=409, detail=str(error)) from error


@app.get("/api/imports/previews/{preview_id}", summary="查看预览详情")
def preview_detail(preview_id: int, db: Session = Depends(get_db)) -> dict[str, object]:
    try:
        return preview_to_dict(get_preview(db, preview_id))
    except ValueError as error:
        raise HTTPException(status_code=404, detail=str(error)) from error


@app.post("/api/imports/previews/cleanup", summary="清理过期预览")
def cleanup_previews(db: Session = Depends(get_db)) -> dict[str, int]:
    return expire_old_previews(db)


@app.post("/api/dev/import-vulnerabilities-sample", summary="导入三类漏洞示例")
def import_vulnerabilities_sample(request: SampleImportRequest, db: Session = Depends(get_db)) -> dict[str, object]:
    if db.scalar(select(func.count()).select_from(Asset)) == 0:
        raise HTTPException(status_code=400, detail="请先导入资产表示例")
    return import_sample_batch(db, request.scan_month)


@app.get("/api/assets", summary="查看资产列表")
def list_assets(db: Session = Depends(get_db)) -> dict[str, object]:
    items = db.scalars(select(Asset).order_by(Asset.ip)).all()
    return {
        "total": len(items),
        "items": [
            {
                "id": item.id,
                "ip": item.ip,
                "organization": item.organization,
                "project": item.project,
                "workspace": item.workspace,
                "owner": item.owner,
            }
            for item in items
        ],
    }


@app.get("/api/records", response_model=ListResponse, summary="查询标准漏洞清单")
def list_records(
    scan_month: str | None = Query(default=None, description="单个月份，例如 2026-05"),
    scan_month_from: str | None = Query(default=None, description="起始月份，例如 2026-05"),
    scan_month_to: str | None = Query(default=None, description="结束月份，例如 2026-07"),
    scanner_type: str | None = Query(default=None, description="扫描器类型"),
    project: str | None = Query(default=None, description="项目名称"),
    vuln_name: str | None = Query(default=None, description="漏洞名称"),
    handle_status: str | None = Query(default=None, description="处置状态"),
    reopened_only: bool = Query(default=False, description="是否只看复发漏洞"),
    include_deleted: bool = Query(default=False, description="是否包含已软删除记录"),
    db: Session = Depends(get_db),
) -> ListResponse:
    query = select(VulnerabilityRecord)
    query = apply_deleted_filter(query, include_deleted)
    query = apply_month_filters(query, VulnerabilityRecord.scan_month, scan_month, scan_month_from, scan_month_to)
    if scanner_type:
        query = query.where(VulnerabilityRecord.scanner_type == scanner_type)
    if project:
        query = query.where(VulnerabilityRecord.project == project)
    if vuln_name:
        query = query.where(VulnerabilityRecord.vuln_name == vuln_name)
    if handle_status:
        query = query.where(VulnerabilityRecord.handle_status == handle_status)
    items = db.scalars(
        query.order_by(
            VulnerabilityRecord.scan_month,
            VulnerabilityRecord.scanner_type,
            VulnerabilityRecord.ip,
            VulnerabilityRecord.port,
        )
    ).all()
    previous_map = load_previous_map(db, items)
    first_detected_map = load_first_detected_map(db, items)
    response_items = [record_to_response_item(item, previous_map, first_detected_map) for item in items]
    if reopened_only:
        response_items = [item for item in response_items if item["is_reopened"]]
    return ListResponse(total=len(response_items), items=response_items)


@app.patch("/api/records/{record_id}", response_model=RecordOut, summary="修改处置状态和备注")
def patch_record(
    record_id: int = ApiPath(description="漏洞记录 ID"),
    request: RecordUpdate = ...,
    db: Session = Depends(get_db),
) -> dict[str, object]:
    record = db.get(VulnerabilityRecord, record_id)
    if not record or record.is_deleted:
        raise HTTPException(status_code=404, detail="漏洞记录不存在")
    updated = update_record(db, record, request.handle_status, request.remark, request.changed_by)
    previous_map = load_previous_map(db, [updated])
    first_detected_map = load_first_detected_map(db, [updated])
    return record_to_response_item(updated, previous_map, first_detected_map)


@app.get("/api/records/{record_id}/changes", response_model=list[ChangeOut], summary="查看变更历史")
def list_record_changes(record_id: int = ApiPath(description="漏洞记录 ID"), db: Session = Depends(get_db)) -> list[RecordChange]:
    if not db.get(VulnerabilityRecord, record_id):
        raise HTTPException(status_code=404, detail="漏洞记录不存在")
    return list(db.scalars(select(RecordChange).where(RecordChange.record_id == record_id).order_by(RecordChange.changed_at)))


@app.get("/api/anomalies", summary="查看导入异常")
def list_anomalies(
    scan_month: str | None = Query(default=None, description="单个月份，例如 2026-05"),
    scan_month_from: str | None = Query(default=None, description="起始月份，例如 2026-05"),
    scan_month_to: str | None = Query(default=None, description="结束月份，例如 2026-07"),
    db: Session = Depends(get_db),
) -> dict[str, object]:
    query = (
        select(ImportAnomaly)
        .join(ImportBatch, ImportAnomaly.batch_id == ImportBatch.id)
        .where(ImportBatch.is_active.is_(True))
        .order_by(ImportBatch.scan_month, ImportAnomaly.id)
    )
    effective_month = None
    if uses_month_window(scan_month, scan_month_from, scan_month_to):
        query = apply_month_filters(query, ImportBatch.scan_month, scan_month, scan_month_from, scan_month_to)
    else:
        effective_month = db.scalar(select(func.max(ImportBatch.scan_month)).where(ImportBatch.is_active.is_(True)))
        if effective_month:
            query = query.where(ImportBatch.scan_month == effective_month)
    items = db.scalars(query).all()
    return {
        "scan_month": effective_month,
        "scan_month_from": scan_month_from or scan_month,
        "scan_month_to": scan_month_to or scan_month,
        "total": len(items),
        "items": [
            {
                "scanner_type": item.scanner_type,
                "source_file": item.source_file,
                "ip": item.ip,
                "anomaly_type": item.anomaly_type,
                "detail": item.detail,
            }
            for item in items
        ],
    }


@app.get("/api/anomalies/unmatched-assets/export", summary="导出未匹配资产 IP")
def export_unmatched_assets(
    scan_month: str | None = Query(default=None),
    scan_month_from: str | None = Query(default=None),
    scan_month_to: str | None = Query(default=None),
    scanner_type: str | None = Query(default=None),
    dedup_by_ip: bool = Query(default=True),
    db: Session = Depends(get_db),
):
    records = db.scalars(
        unmatched_records_query(scan_month, scan_month_from, scan_month_to, scanner_type).order_by(
            VulnerabilityRecord.scan_month,
            VulnerabilityRecord.scanner_type,
            VulnerabilityRecord.ip,
            VulnerabilityRecord.vuln_name,
        )
    ).all()
    if not records:
        raise HTTPException(status_code=404, detail="当前筛选条件下没有未匹配资产记录")
    content = export_unmatched_assets_xlsx(records, dedup_by_ip)
    filename = "unmatched_assets_dedup.xlsx" if dedup_by_ip else "unmatched_assets_raw.xlsx"
    headers = {"Content-Disposition": f'attachment; filename="{filename}"'}
    return StreamingResponse(iter([content]), media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", headers=headers)


@app.post("/api/anomalies/unmatched-assets/rematch", summary="批量重匹配未匹配资产")
def rematch_unmatched_assets(request: RematchRequest, db: Session = Depends(get_db)) -> dict[str, int]:
    records = db.scalars(
        unmatched_records_query(request.scan_month, request.scan_month_from, request.scan_month_to, request.scanner_type)
    ).all()
    result = rematch_unmatched_records(db, records, request.changed_by)
    return {"total": len(records), **result}


@app.get("/api/exports/vulnerabilities", summary="导出漏洞报告")
def export_vulnerabilities(
    scan_month: str | None = Query(default=None, description="单个月份，例如 2026-05"),
    scan_month_from: str | None = Query(default=None, description="起始月份，例如 2026-05"),
    scan_month_to: str | None = Query(default=None, description="结束月份，例如 2026-07"),
    handle_status: str | None = Query(default=None, description="处置状态"),
    project: str | None = Query(default=None, description="项目名称"),
    mode: str = Query(default="project-merged", description="project-merged 或 project-scanner-split"),
    db: Session = Depends(get_db),
):
    if mode not in {"project-merged", "project-scanner-split"}:
        raise HTTPException(status_code=400, detail="导出模式必须为 project-merged 或 project-scanner-split")
    query = apply_deleted_filter(select(VulnerabilityRecord))
    query = apply_month_filters(query, VulnerabilityRecord.scan_month, scan_month, scan_month_from, scan_month_to)
    if handle_status:
        query = query.where(VulnerabilityRecord.handle_status == handle_status)
    if project:
        query = query.where(VulnerabilityRecord.project == project)
    records = db.scalars(
        query.order_by(
            VulnerabilityRecord.project,
            VulnerabilityRecord.scanner_type,
            VulnerabilityRecord.ip,
            VulnerabilityRecord.port,
            VulnerabilityRecord.vuln_name,
        )
    ).all()
    if not records:
        raise HTTPException(status_code=404, detail="当前筛选条件下没有可导出的漏洞记录")
    content, filename = export_zip_bytes(records, mode, scan_month, scan_month_from, scan_month_to)
    headers = {"Content-Disposition": f'attachment; filename="{filename}"'}
    return StreamingResponse(iter([content]), media_type="application/zip", headers=headers)


@app.get("/api/statistics/overview", summary="查看工作台统计")
def statistics_overview(
    scan_month: str | None = Query(default=None, description="单个月份，例如 2026-05"),
    scan_month_from: str | None = Query(default=None, description="起始月份，例如 2026-05"),
    scan_month_to: str | None = Query(default=None, description="结束月份，例如 2026-07"),
    db: Session = Depends(get_db),
) -> dict[str, object]:
    query = apply_deleted_filter(select(VulnerabilityRecord))
    anomaly_query = (
        select(func.count())
        .select_from(ImportAnomaly)
        .join(ImportBatch, ImportAnomaly.batch_id == ImportBatch.id)
        .where(ImportBatch.is_active.is_(True))
    )
    effective_month = None
    if uses_month_window(scan_month, scan_month_from, scan_month_to):
        query = apply_month_filters(query, VulnerabilityRecord.scan_month, scan_month, scan_month_from, scan_month_to)
        anomaly_query = apply_month_filters(anomaly_query, ImportBatch.scan_month, scan_month, scan_month_from, scan_month_to)
    else:
        effective_month = db.scalar(
            select(func.max(VulnerabilityRecord.scan_month)).where(VulnerabilityRecord.is_deleted.is_(False))
        )
        if effective_month:
            query = query.where(VulnerabilityRecord.scan_month == effective_month)
            anomaly_query = anomaly_query.where(ImportBatch.scan_month == effective_month)
    records = list(db.scalars(query))
    previous_map = load_previous_map(db, records)
    scanner_counts = {"青藤云": 0, "阿里云": 0, "绿盟": 0}
    status_counts: dict[str, int] = {}
    reopened_count = 0
    for record in records:
        scanner_counts[record.scanner_type] = scanner_counts.get(record.scanner_type, 0) + 1
        status_counts[record.handle_status] = status_counts.get(record.handle_status, 0) + 1
        previous = previous_map.get(
            previous_lookup_key(
                record.scanner_type,
                previous_month(record.scan_month),
                record.ip,
                record.port,
                record.normalized_vuln_name,
            )
        )
        if compute_reopened_fields(record, previous)[0]:
            reopened_count += 1
    return {
        "scan_month": effective_month,
        "scan_month_from": scan_month_from or scan_month,
        "scan_month_to": scan_month_to or scan_month,
        "total": len(records),
        "scanner_counts": scanner_counts,
        "disposed_count": sum(status_counts.get(status, 0) for status in DISPOSED_STATUSES),
        "unresolved_count": sum(status_counts.get(status, 0) for status in UNRESOLVED_STATUSES),
        "pending_offline_count": status_counts.get("项目待下线", 0),
        "offline_count": status_counts.get("项目已下线", 0),
        "project_count": len({record.project for record in records if record.project}),
        "anomaly_count": db.scalar(anomaly_query) or 0,
        "status_counts": status_counts,
        "reopened_count": reopened_count,
    }


@app.get("/api/statistics/top-projects", summary="系统漏洞总数 Top10")
def statistics_top_projects(
    scan_month: str | None = Query(default=None),
    scan_month_from: str | None = Query(default=None),
    scan_month_to: str | None = Query(default=None),
    db: Session = Depends(get_db),
) -> dict[str, object]:
    query = apply_deleted_filter(select(VulnerabilityRecord))
    query = apply_month_filters(query, VulnerabilityRecord.scan_month, scan_month, scan_month_from, scan_month_to)
    records = db.scalars(query).all()
    counts: dict[str, int] = {}
    for record in records:
        key = record.project or "未匹配项目"
        counts[key] = counts.get(key, 0) + 1
    items = [{"project": name, "count": count} for name, count in sorted(counts.items(), key=lambda item: (-item[1], item[0]))[:10]]
    return {"items": items}


@app.get("/api/statistics/top-vulnerabilities", summary="漏洞名称出现次数 Top10")
def statistics_top_vulnerabilities(
    scan_month: str | None = Query(default=None),
    scan_month_from: str | None = Query(default=None),
    scan_month_to: str | None = Query(default=None),
    db: Session = Depends(get_db),
) -> dict[str, object]:
    query = apply_deleted_filter(select(VulnerabilityRecord))
    query = apply_month_filters(query, VulnerabilityRecord.scan_month, scan_month, scan_month_from, scan_month_to)
    records = db.scalars(query).all()
    counts: dict[str, int] = {}
    for record in records:
        key = record.vuln_name
        counts[key] = counts.get(key, 0) + 1
    items = [{"vuln_name": name, "count": count} for name, count in sorted(counts.items(), key=lambda item: (-item[1], item[0]))[:10]]
    return {"items": items}


@app.get("/api/statistics/top-projects/details", summary="系统漏洞总数 Top10 明细")
def statistics_top_projects_details(
    project: str = Query(..., description="项目名称"),
    scan_month: str | None = Query(default=None),
    scan_month_from: str | None = Query(default=None),
    scan_month_to: str | None = Query(default=None),
    scanner_type: str | None = Query(default=None),
    db: Session = Depends(get_db),
) -> dict[str, object]:
    records = load_filtered_records(db, scan_month, scan_month_from, scan_month_to, scanner_type, project=project)
    items = build_record_items(db, records)
    return {"dimension": "project", "value": project, "total": len(items), "items": items}


@app.get("/api/statistics/top-vulnerabilities/details", summary="漏洞名称 Top10 明细")
def statistics_top_vulnerabilities_details(
    vuln_name: str = Query(..., description="漏洞名称"),
    scan_month: str | None = Query(default=None),
    scan_month_from: str | None = Query(default=None),
    scan_month_to: str | None = Query(default=None),
    scanner_type: str | None = Query(default=None),
    db: Session = Depends(get_db),
) -> dict[str, object]:
    records = load_filtered_records(db, scan_month, scan_month_from, scan_month_to, scanner_type, vuln_name=vuln_name)
    items = build_record_items(db, records)
    return {"dimension": "vuln_name", "value": vuln_name, "total": len(items), "items": items}


@app.get("/api/statistics/reopened/details", summary="复发漏洞明细")
def statistics_reopened_details(
    scan_month: str | None = Query(default=None),
    scan_month_from: str | None = Query(default=None),
    scan_month_to: str | None = Query(default=None),
    scanner_type: str | None = Query(default=None),
    db: Session = Depends(get_db),
) -> dict[str, object]:
    records = load_filtered_records(db, scan_month, scan_month_from, scan_month_to, scanner_type)
    items = [item for item in build_record_items(db, records) if item["is_reopened"]]
    value = scan_month or f"{scan_month_from or ''}~{scan_month_to or ''}".strip("~")
    return {"dimension": "reopened", "value": value or "current", "total": len(items), "items": items}


@app.get("/api/statistics/monthly-trend", summary="近六个月趋势")
def statistics_monthly_trend(
    scan_month: str | None = Query(default=None),
    scan_month_from: str | None = Query(default=None),
    scan_month_to: str | None = Query(default=None),
    db: Session = Depends(get_db),
) -> dict[str, object]:
    months = months_for_statistics(db, scan_month, scan_month_from, scan_month_to)
    items = []
    for month in months:
        records = db.scalars(
            select(VulnerabilityRecord).where(
                VulnerabilityRecord.is_deleted.is_(False),
                VulnerabilityRecord.scan_month == month,
            )
        ).all()
        total = len(records)
        disposed_count = sum(1 for record in records if record.handle_status in DISPOSED_STATUSES)
        scanner_counts = {"青藤云": 0, "阿里云": 0, "绿盟": 0}
        for record in records:
            scanner_counts[record.scanner_type] = scanner_counts.get(record.scanner_type, 0) + 1
        items.append(
            {
                "scan_month": month,
                "total": total,
                "disposed_count": disposed_count,
                "fixed_rate": round(disposed_count / total, 4) if total else 0,
                "scanner_counts": scanner_counts,
            }
        )
    return {"items": items}


@app.get("/api/statistics/reopened-trend", summary="复发漏洞趋势")
def statistics_reopened_trend(
    scan_month: str | None = Query(default=None),
    scan_month_from: str | None = Query(default=None),
    scan_month_to: str | None = Query(default=None),
    db: Session = Depends(get_db),
) -> dict[str, object]:
    months = months_for_statistics(db, scan_month, scan_month_from, scan_month_to)
    items = []
    for month in months:
        records = db.scalars(
            select(VulnerabilityRecord).where(
                VulnerabilityRecord.is_deleted.is_(False),
                VulnerabilityRecord.scan_month == month,
            )
        ).all()
        previous_map = load_previous_map(db, records)
        reopened_count = 0
        for record in records:
            previous = previous_map.get(
                previous_lookup_key(
                    record.scanner_type,
                    previous_month(record.scan_month),
                    record.ip,
                    record.port,
                    record.normalized_vuln_name,
                )
            )
            if compute_reopened_fields(record, previous)[0]:
                reopened_count += 1
        items.append({"scan_month": month, "reopened_count": reopened_count})
    return {"items": items}


@app.post("/api/records/batch-update", response_model=BatchActionResult, summary="批量修改漏洞处置状态和备注")
def batch_patch_records(request: RecordBatchUpdate, db: Session = Depends(get_db)) -> BatchActionResult:
    records = db.scalars(select(VulnerabilityRecord).where(VulnerabilityRecord.id.in_(request.record_ids))).all()
    updated_count = batch_update_records(db, records, request.handle_status, request.remark, request.changed_by)
    return BatchActionResult(total=len(request.record_ids), updated_count=updated_count, deleted_count=0)


@app.post("/api/records/batch-delete", response_model=BatchActionResult, summary="批量软删除漏洞记录")
def batch_delete_records(request: RecordBatchDelete, db: Session = Depends(get_db)) -> BatchActionResult:
    records = db.scalars(select(VulnerabilityRecord).where(VulnerabilityRecord.id.in_(request.record_ids))).all()
    deleted_count = soft_delete_records(db, records, request.delete_reason, request.changed_by)
    return BatchActionResult(total=len(request.record_ids), updated_count=0, deleted_count=deleted_count)
