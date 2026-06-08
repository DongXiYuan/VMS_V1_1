import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "backend" / "tests"))

from test_api import client, setup_function as base_setup_function  # noqa: E402


def setup_function() -> None:
    base_setup_function()


def import_sample_records() -> dict[str, object]:
    assert client.post("/api/dev/import-assets-sample").status_code == 200
    response = client.post("/api/dev/import-vulnerabilities-sample", json={"scan_month": "2026-05"})
    assert response.status_code == 200
    return response.json()


def test_batch_delete_hides_records_from_default_views() -> None:
    imported = import_sample_records()
    records = client.get("/api/records", params={"scan_month": "2026-05"}).json()
    target_ids = [item["id"] for item in records["items"][:2]]

    deleted = client.post(
        "/api/records/batch-delete",
        json={"record_ids": target_ids, "delete_reason": "误导入", "changed_by": "admin"},
    )
    assert deleted.status_code == 200
    assert deleted.json()["deleted_count"] == 2

    refreshed = client.get("/api/records", params={"scan_month": "2026-05"}).json()
    assert refreshed["total"] == imported["total_records"] - 2
    assert {item["id"] for item in refreshed["items"]}.isdisjoint(target_ids)

    with_deleted = client.get(
        "/api/records",
        params={"scan_month": "2026-05", "include_deleted": "true"},
    ).json()
    deleted_items = [item for item in with_deleted["items"] if item["id"] in target_ids]
    assert len(deleted_items) == 2
    assert all(item["is_deleted"] is True for item in deleted_items)
    assert all(item["deleted_reason"] == "误导入" for item in deleted_items)

    overview = client.get("/api/statistics/overview", params={"scan_month": "2026-05"}).json()
    assert overview["total"] == imported["total_records"] - 2


def test_batch_update_changes_status_for_multiple_records() -> None:
    import_sample_records()
    records = client.get("/api/records", params={"scan_month": "2026-05"}).json()["items"]
    target_ids = [item["id"] for item in records[:3]]

    updated = client.post(
        "/api/records/batch-update",
        json={
            "record_ids": target_ids,
            "handle_status": "已通知",
            "remark": "批量通知",
            "changed_by": "admin",
        },
    )
    assert updated.status_code == 200
    assert updated.json()["updated_count"] == 3

    refreshed = client.get("/api/records", params={"scan_month": "2026-05"}).json()["items"]
    changed = [item for item in refreshed if item["id"] in target_ids]
    assert len(changed) == 3
    assert all(item["handle_status"] == "已通知" for item in changed)
    assert all(item["remark"] == "批量通知" for item in changed)


def test_export_returns_not_found_when_all_filtered_records_are_soft_deleted() -> None:
    import_sample_records()
    records = client.get("/api/records", params={"scan_month": "2026-05"}).json()["items"]
    target_ids = [item["id"] for item in records if item["handle_status"] == "待修复"]

    deleted = client.post(
        "/api/records/batch-delete",
        json={"record_ids": target_ids, "delete_reason": "无需修复", "changed_by": "admin"},
    )
    assert deleted.status_code == 200
    assert deleted.json()["deleted_count"] == len(target_ids)

    exported = client.get(
        "/api/exports/vulnerabilities",
        params={"scan_month": "2026-05", "handle_status": "待修复"},
    )
    assert exported.status_code == 404
