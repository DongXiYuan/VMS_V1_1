from datetime import UTC, datetime, timedelta
from pathlib import Path
import zipfile

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.database import Base, get_db
from app.main import app
from app.models import ImportPreview
from app.services import reset_database


SAMPLES_DIR = Path(__file__).parents[2] / "samples"
XLSX_MIME = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"


engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
TestingSessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
Base.metadata.create_all(bind=engine)


def override_get_db():
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()


app.dependency_overrides[get_db] = override_get_db
client = TestClient(app)


def setup_function() -> None:
    Base.metadata.create_all(bind=engine)
    with TestingSessionLocal() as db:
        reset_database(db)


def sample_path(*candidates: str) -> Path:
    for candidate in candidates:
        path = SAMPLES_DIR / candidate
        if path.exists():
            return path
    raise FileNotFoundError(f"未找到样例文件: {candidates}")


def test_health() -> None:
    assert client.get("/api/health").json() == {"status": "ok"}


def test_root_serves_web_app() -> None:
    response = client.get("/")
    assert response.status_code == 200
    assert "VMS 漏洞管理系统" in response.text
    assert response.headers["cache-control"] == "no-store"


def test_static_web_assets_are_served() -> None:
    assert client.get("/static/styles.css").status_code == 200
    script = client.get("/static/app.js")
    assert script.status_code == 200
    assert "loadDashboard" in script.text


def test_web_app_versions_static_assets_to_avoid_stale_browser_cache() -> None:
    page = client.get("/").text
    assert 'href="/static/styles.css?v=stage4.7"' in page
    assert 'src="/static/app.js?v=stage4.7"' in page


def test_web_app_contains_real_upload_controls() -> None:
    page = client.get("/").text
    assert "文件导入" in page
    assert 'id="asset-upload-form"' in page
    assert 'id="vulnerability-upload-form"' in page


def test_frontend_formats_backend_timestamps_in_shanghai_timezone() -> None:
    script = client.get("/static/app.js").text
    assert 'timeZone: "Asia/Shanghai"' in script
    assert '`${value}Z`' in script


def test_sample_import_and_record_edit_flow() -> None:
    assets = client.post("/api/dev/import-assets-sample")
    assert assets.status_code == 200
    assert assets.json()["total"] == 7

    batch = client.post("/api/dev/import-vulnerabilities-sample", json={"scan_month": "2026-05"})
    assert batch.status_code == 200
    imported_total = batch.json()["total_records"]
    imported_anomalies = sum(item["anomalies"] for item in batch.json()["scanners"])
    assert imported_total > 0

    records = client.get("/api/records", params={"scan_month": "2026-05"})
    assert records.status_code == 200
    assert records.json()["total"] == imported_total
    first = records.json()["items"][0]
    assert first["previous_month_status"] == "无"

    updated = client.patch(f"/api/records/{first['id']}", json={"handle_status": "已通知", "remark": "等待反馈", "changed_by": "admin"})
    assert updated.status_code == 200
    assert updated.json()["handle_status"] == "已通知"
    assert updated.json()["remark"] == "等待反馈"

    changes = client.get(f"/api/records/{first['id']}/changes")
    assert changes.status_code == 200
    assert len(changes.json()) == 2

    anomalies = client.get("/api/anomalies")
    assert anomalies.status_code == 200
    assert anomalies.json()["total"] == imported_anomalies


def test_same_month_reimport_is_idempotent() -> None:
    client.post("/api/dev/import-assets-sample")
    first = client.post("/api/dev/import-vulnerabilities-sample", json={"scan_month": "2026-05"})
    second = client.post("/api/dev/import-vulnerabilities-sample", json={"scan_month": "2026-05"})
    assert second.status_code == 200
    records = client.get("/api/records", params={"scan_month": "2026-05"}).json()
    assert records["total"] == first.json()["total_records"]
    anomalies = client.get("/api/anomalies").json()
    assert anomalies["total"] == sum(item["anomalies"] for item in first.json()["scanners"])


def test_next_month_import_attaches_previous_status_and_remark() -> None:
    client.post("/api/dev/import-assets-sample")
    client.post("/api/dev/import-vulnerabilities-sample", json={"scan_month": "2026-05"})
    may_records = client.get("/api/records", params={"scan_month": "2026-05", "scanner_type": "青藤云"}).json()["items"]
    target = may_records[0]
    client.patch(
        f"/api/records/{target['id']}",
        json={"handle_status": "已通知", "remark": "上月等待反馈", "changed_by": "admin"},
    )
    june = client.post("/api/dev/import-vulnerabilities-sample", json={"scan_month": "2026-06"})
    assert june.status_code == 200
    june_records = client.get("/api/records", params={"scan_month": "2026-06", "scanner_type": "青藤云"}).json()["items"]
    inherited = next(record for record in june_records if record["ip"] == target["ip"] and record["vuln_name"] == target["vuln_name"])
    assert inherited["previous_month_status"] == "已通知"
    assert inherited["previous_month_remark"] == "上月等待反馈"


def test_statistics_overview() -> None:
    client.post("/api/dev/import-assets-sample")
    batch = client.post("/api/dev/import-vulnerabilities-sample", json={"scan_month": "2026-05"})
    response = client.get("/api/statistics/overview", params={"scan_month": "2026-05"})
    assert response.status_code == 200
    data = response.json()
    expected_counts = {item["scanner_type"]: item["records"] for item in batch.json()["scanners"]}
    assert data["total"] == batch.json()["total_records"]
    assert data["scanner_counts"] == expected_counts
    assert data["unresolved_count"] == batch.json()["total_records"]
    assert data["anomaly_count"] == sum(item["anomalies"] for item in batch.json()["scanners"])


def test_import_preview_defaults_to_preview_status() -> None:
    with TestingSessionLocal() as db:
        preview = ImportPreview(import_type="assets", original_filename="资产.xlsx", stored_path="x", sha256="abc")
        db.add(preview)
        db.commit()
        db.refresh(preview)
        assert preview.status == "preview"
        assert preview.has_blocking_errors is False
        assert preview.expires_at is not None


def test_asset_preview_does_not_modify_database() -> None:
    with open(sample_path("资产表（样例）.xlsx"), "rb") as source:
        response = client.post("/api/imports/assets/preview", files={"file": ("资产.xlsx", source, XLSX_MIME)})
    assert response.status_code == 200
    assert response.json()["summary"] == {"created": 7, "updated": 0, "unchanged": 0, "invalid": 0}
    assert client.get("/api/assets").json()["total"] == 0


def test_asset_preview_rejects_non_xlsx() -> None:
    response = client.post("/api/imports/assets/preview", files={"file": ("资产.txt", b"x", "text/plain")})
    assert response.status_code == 400


def test_asset_preview_accepts_legacy_xls_extension() -> None:
    response = client.post("/api/imports/assets/preview", files={"file": ("资产.xls", b"broken", "application/vnd.ms-excel")})
    assert response.status_code == 200
    assert response.json()["has_blocking_errors"] is True


def test_broken_asset_xlsx_creates_blocking_preview() -> None:
    response = client.post("/api/imports/assets/preview", files={"file": ("资产.xlsx", b"broken", XLSX_MIME)})
    assert response.status_code == 200
    assert response.json()["has_blocking_errors"] is True


def test_asset_publish_applies_preview_and_moves_original_file() -> None:
    with open(sample_path("资产表（样例）.xlsx"), "rb") as source:
        preview = client.post("/api/imports/assets/preview", files={"file": ("资产.xlsx", source, XLSX_MIME)}).json()
    response = client.post(f"/api/imports/assets/{preview['id']}/publish")
    assert response.status_code == 200
    assert response.json()["status"] == "published"
    assert client.get("/api/assets").json()["total"] == 7
    stored_path = Path(response.json()["stored_path"])
    assert stored_path.exists()
    assert "published" in stored_path.parts


def upload_vulnerability(scanner_type: str, scan_month: str, path: Path):
    with open(path, "rb") as source:
        return client.post(
            "/api/imports/vulnerabilities/preview",
            data={"scanner_type": scanner_type, "scan_month": scan_month},
            files={"file": (path.name, source, "application/octet-stream")},
        )


def build_nsfocus_zip(tmp_path: Path) -> Path:
    path = tmp_path / "绿盟扫描.zip"
    with zipfile.ZipFile(path, "w") as archive:
        archive.write(sample_path("index（样例）.xls", "绿盟/index.xls"), "index.xls")
        archive.write(sample_path("10.1.1.1（样例）.xls", "绿盟/10.1.1.1.xls"), "10.1.1.1.xls")
    return path


def build_zip_without_index(tmp_path: Path) -> Path:
    path = tmp_path / "缺少索引.zip"
    with zipfile.ZipFile(path, "w") as archive:
        archive.write(sample_path("10.1.1.1（样例）.xls", "绿盟/10.1.1.1.xls"), "10.1.1.1.xls")
    return path


def test_qingteng_preview_returns_five_records_without_publishing() -> None:
    response = upload_vulnerability("青藤云", "2026-05", sample_path("青藤云漏洞（样例）.xlsx"))
    assert response.status_code == 200
    assert response.json()["summary"]["records"] == 5
    assert client.get("/api/records", params={"scan_month": "2026-05"}).json()["total"] == 0


def test_aliyun_preview_returns_seven_records() -> None:
    response = upload_vulnerability("阿里云", "2026-05", sample_path("阿里云漏洞（样例）.xlsx"))
    assert response.status_code == 200
    assert response.json()["summary"]["records"] == 7


def test_qingteng_preview_accepts_legacy_xls_extension() -> None:
    response = client.post(
        "/api/imports/vulnerabilities/preview",
        data={"scanner_type": "青藤云", "scan_month": "2026-05"},
        files={"file": ("青藤云.xls", b"broken", "application/vnd.ms-excel")},
    )
    assert response.status_code == 200
    assert response.json()["has_blocking_errors"] is True


def test_nsfocus_zip_preview_uses_index_before_host_reports(tmp_path: Path) -> None:
    response = upload_vulnerability("绿盟", "2026-05", build_nsfocus_zip(tmp_path))
    assert response.status_code == 200
    summary = response.json()["summary"]
    assert summary["records"] == 1
    assert summary["indexed_hosts"] == 7
    assert summary["parsed_host_reports"] == 1


def test_nsfocus_zip_without_index_blocks_publish(tmp_path: Path) -> None:
    preview = upload_vulnerability("绿盟", "2026-05", build_zip_without_index(tmp_path)).json()
    assert preview["has_blocking_errors"] is True
    response = client.post(
        f"/api/imports/vulnerabilities/{preview['id']}/publish",
        json={"confirm_warnings": True},
    )
    assert response.status_code == 409


def test_broken_nsfocus_zip_creates_blocking_preview(tmp_path: Path) -> None:
    path = tmp_path / "损坏.zip"
    path.write_bytes(b"broken")
    response = upload_vulnerability("绿盟", "2026-05", path)
    assert response.status_code == 200
    assert response.json()["has_blocking_errors"] is True


def test_warning_requires_confirmation_before_publish() -> None:
    preview = upload_vulnerability("青藤云", "2026-05", sample_path("青藤云漏洞（样例）.xlsx")).json()
    assert any(issue["level"] == "warning" for issue in preview["issues"])
    rejected = client.post(
        f"/api/imports/vulnerabilities/{preview['id']}/publish",
        json={"confirm_warnings": False},
    )
    assert rejected.status_code == 409
    published = client.post(
        f"/api/imports/vulnerabilities/{preview['id']}/publish",
        json={"confirm_warnings": True},
    )
    assert published.status_code == 200
    assert client.get("/api/records", params={"scan_month": "2026-05"}).json()["total"] == 5


def test_same_month_republish_warns_and_preserves_manual_fields() -> None:
    preview = upload_vulnerability("青藤云", "2026-05", sample_path("青藤云漏洞（样例）.xlsx")).json()
    client.post(f"/api/imports/vulnerabilities/{preview['id']}/publish", json={"confirm_warnings": True})
    record = client.get("/api/records", params={"scan_month": "2026-05", "scanner_type": "青藤云"}).json()["items"][0]
    client.patch(
        f"/api/records/{record['id']}",
        json={"handle_status": "已通知", "remark": "等待项目反馈", "changed_by": "admin"},
    )
    replacement = upload_vulnerability("青藤云", "2026-05", sample_path("青藤云漏洞（样例）.xlsx")).json()
    assert replacement["replacement_warning"] is True
    client.post(f"/api/imports/vulnerabilities/{replacement['id']}/publish", json={"confirm_warnings": True})
    refreshed = client.get("/api/records", params={"scan_month": "2026-05", "scanner_type": "青藤云"}).json()["items"][0]
    assert refreshed["handle_status"] == "已通知"
    assert refreshed["remark"] == "等待项目反馈"


def test_expired_preview_cannot_publish_and_cleanup_removes_file() -> None:
    with open(sample_path("资产表（样例）.xlsx"), "rb") as source:
        preview = client.post("/api/imports/assets/preview", files={"file": ("资产.xlsx", source, XLSX_MIME)}).json()
    with TestingSessionLocal() as db:
        stored = db.get(ImportPreview, preview["id"])
        assert stored is not None
        preview_path = Path(stored.stored_path)
        stored.expires_at = datetime.now(UTC) - timedelta(minutes=1)
        db.commit()
    assert client.post(f"/api/imports/assets/{preview['id']}/publish").status_code == 409
    cleanup = client.post("/api/imports/previews/cleanup")
    assert cleanup.status_code == 200
    assert cleanup.json()["expired"] == 1
    assert cleanup.json()["deleted_files"] == 1
    assert not preview_path.exists()


def test_preview_detail_returns_saved_summary() -> None:
    with open(sample_path("资产表（样例）.xlsx"), "rb") as source:
        preview = client.post("/api/imports/assets/preview", files={"file": ("资产.xlsx", source, XLSX_MIME)}).json()
    response = client.get(f"/api/imports/previews/{preview['id']}")
    assert response.status_code == 200
    assert response.json()["summary"]["created"] == 7
