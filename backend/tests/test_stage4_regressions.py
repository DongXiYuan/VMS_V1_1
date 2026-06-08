from pathlib import Path
import sys


TESTS_DIR = Path(__file__).resolve().parent
BACKEND_DIR = TESTS_DIR.parent
ROOT_DIR = BACKEND_DIR.parent
PROTOTYPE_SRC_DIR = ROOT_DIR / "prototype" / "src"
if str(TESTS_DIR) not in sys.path:
    sys.path.insert(0, str(TESTS_DIR))
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))
if str(PROTOTYPE_SRC_DIR) not in sys.path:
    sys.path.insert(0, str(PROTOTYPE_SRC_DIR))

from test_api import client, setup_function as base_setup_function


SCANNER_QINGTENG = "\u9752\u85e4\u4e91"
STATUS_NOTIFIED = "\u5df2\u901a\u77e5"
STATUS_FIXED = "\u5df2\u4fee\u590d"


def setup_function() -> None:
    base_setup_function()


def test_web_app_contains_month_range_and_detail_dialogs() -> None:
    page = client.get("/").text
    assert 'id="global-month-from"' in page
    assert 'id="global-month-to"' in page
    assert 'id="detail-dialog"' in page
    assert 'id="previous-dialog"' in page
    assert 'id="drilldown-dialog"' in page
    assert 'id="batch-apply"' in page
    assert 'id="batch-delete"' in page
    assert 'id="select-all-records"' in page
    assert 'id="anomaly-filter-month"' in page
    assert 'id="filter-reopened"' in page
    assert 'id="filter-vuln-name"' in page
    assert 'id="export-unmatched-raw"' in page
    assert 'id="export-unmatched-dedup"' in page
    assert 'id="rematch-unmatched"' in page
    assert 'id="top-projects-list"' in page
    assert 'id="top-vulns-list"' in page
    assert 'id="monthly-trend-table"' in page
    assert 'id="reopened-trend-table"' in page


def test_next_month_import_uses_latest_saved_status_and_remark() -> None:
    client.post("/api/dev/import-assets-sample")
    client.post("/api/dev/import-vulnerabilities-sample", json={"scan_month": "2026-05"})
    may_records = client.get(
        "/api/records",
        params={"scan_month": "2026-05", "scanner_type": SCANNER_QINGTENG},
    ).json()["items"]
    target = may_records[0]
    client.patch(
        f"/api/records/{target['id']}",
        json={"handle_status": STATUS_NOTIFIED, "remark": "first note", "changed_by": "admin"},
    )
    client.patch(
        f"/api/records/{target['id']}",
        json={"handle_status": STATUS_FIXED, "remark": "latest note", "changed_by": "admin"},
    )
    june = client.post("/api/dev/import-vulnerabilities-sample", json={"scan_month": "2026-06"})
    assert june.status_code == 200
    june_records = client.get(
        "/api/records",
        params={"scan_month": "2026-06", "scanner_type": SCANNER_QINGTENG},
    ).json()["items"]
    inherited = next(
        record
        for record in june_records
        if record["ip"] == target["ip"] and record["vuln_name"] == target["vuln_name"]
    )
    assert inherited["previous_month_status"] == STATUS_FIXED
    assert inherited["previous_month_remark"] == "latest note"


def test_current_month_list_reflects_latest_previous_month_updates() -> None:
    client.post("/api/dev/import-assets-sample")
    client.post("/api/dev/import-vulnerabilities-sample", json={"scan_month": "2026-05"})
    client.post("/api/dev/import-vulnerabilities-sample", json={"scan_month": "2026-06"})

    may_records = client.get(
        "/api/records",
        params={"scan_month": "2026-05", "scanner_type": SCANNER_QINGTENG},
    ).json()["items"]
    may_target = may_records[0]
    june_before = client.get(
        "/api/records",
        params={"scan_month": "2026-06", "scanner_type": SCANNER_QINGTENG},
    ).json()["items"]
    linked_before = next(
        record
        for record in june_before
        if record["ip"] == may_target["ip"] and record["vuln_name"] == may_target["vuln_name"]
    )
    assert linked_before["previous_month_status"] in {STATUS_NOTIFIED, STATUS_FIXED, "待修复"}

    client.patch(
        f"/api/records/{may_target['id']}",
        json={"handle_status": STATUS_NOTIFIED, "remark": "follow up remark", "changed_by": "admin"},
    )
    client.patch(
        f"/api/records/{may_target['id']}",
        json={"handle_status": STATUS_FIXED, "remark": "final previous remark", "changed_by": "admin"},
    )

    june_after = client.get(
        "/api/records",
        params={"scan_month": "2026-06", "scanner_type": SCANNER_QINGTENG},
    ).json()["items"]
    linked_after = next(
        record
        for record in june_after
        if record["ip"] == may_target["ip"] and record["vuln_name"] == may_target["vuln_name"]
    )
    assert linked_after["previous_month_status"] == STATUS_FIXED
    assert linked_after["previous_month_remark"] == "final previous remark"


def test_statistics_overview_supports_month_range() -> None:
    client.post("/api/dev/import-assets-sample")
    may = client.post("/api/dev/import-vulnerabilities-sample", json={"scan_month": "2026-05"})
    june = client.post("/api/dev/import-vulnerabilities-sample", json={"scan_month": "2026-06"})
    response = client.get(
        "/api/statistics/overview",
        params={"scan_month_from": "2026-05", "scan_month_to": "2026-06"},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["scan_month_from"] == "2026-05"
    assert data["scan_month_to"] == "2026-06"
    assert data["total"] == may.json()["total_records"] + june.json()["total_records"]


def test_records_support_month_range_filter() -> None:
    client.post("/api/dev/import-assets-sample")
    may = client.post("/api/dev/import-vulnerabilities-sample", json={"scan_month": "2026-05"})
    june = client.post("/api/dev/import-vulnerabilities-sample", json={"scan_month": "2026-06"})
    response = client.get(
        "/api/records",
        params={"scan_month_from": "2026-05", "scan_month_to": "2026-06"},
    )
    assert response.status_code == 200
    assert response.json()["total"] == may.json()["total_records"] + june.json()["total_records"]


def test_same_month_republish_keeps_first_detected_time_and_single_record() -> None:
    client.post("/api/dev/import-assets-sample")
    client.post("/api/dev/import-vulnerabilities-sample", json={"scan_month": "2026-05"})
    first_records = client.get(
        "/api/records",
        params={"scan_month": "2026-05", "scanner_type": SCANNER_QINGTENG},
    ).json()["items"]
    target = first_records[0]
    first_detected_at = target["first_detected_at"]

    client.patch(
        f"/api/records/{target['id']}",
        json={"handle_status": STATUS_NOTIFIED, "remark": "carry forward remark", "changed_by": "admin"},
    )

    client.post("/api/dev/import-vulnerabilities-sample", json={"scan_month": "2026-05"})
    second_records = client.get(
        "/api/records",
        params={"scan_month": "2026-05", "scanner_type": SCANNER_QINGTENG},
    ).json()["items"]
    linked = next(
        record
        for record in second_records
        if record["ip"] == target["ip"] and record["vuln_name"] == target["vuln_name"]
    )
    assert linked["first_detected_at"] == first_detected_at
    assert linked["handle_status"] == STATUS_NOTIFIED
    assert linked["remark"] == "carry forward remark"
    assert len(
        [record for record in second_records if record["ip"] == target["ip"] and record["vuln_name"] == target["vuln_name"]]
    ) == 1


def test_next_month_reuses_original_first_detected_time() -> None:
    client.post("/api/dev/import-assets-sample")
    client.post("/api/dev/import-vulnerabilities-sample", json={"scan_month": "2026-05"})
    may_records = client.get(
        "/api/records",
        params={"scan_month": "2026-05", "scanner_type": SCANNER_QINGTENG},
    ).json()["items"]
    may_target = may_records[0]
    may_first_detected_at = may_target["first_detected_at"]

    client.post("/api/dev/import-vulnerabilities-sample", json={"scan_month": "2026-06"})
    june_records = client.get(
        "/api/records",
        params={"scan_month": "2026-06", "scanner_type": SCANNER_QINGTENG},
    ).json()["items"]
    june_target = next(
        record
        for record in june_records
        if record["ip"] == may_target["ip"]
        and record["port"] == may_target["port"]
        and record["vuln_name"] == may_target["vuln_name"]
    )
    assert june_target["first_detected_at"] == may_first_detected_at
