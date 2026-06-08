from pathlib import Path
import zipfile

import pytest

from vms_stage1.core import (
    StandardRecord,
    attach_previous_month,
    dedupe,
    normalize_severity,
    normalize_vuln_name,
    parse_assets,
    parse_nsfocus_host,
    parse_simple_xlsx,
    resolve_fields,
    run_pipeline,
    safe_extract,
)


ROOT = Path(__file__).parents[2]
SAMPLES = ROOT / "samples"
CONFIG = ROOT / "prototype" / "config" / "field_mappings.json"


def test_normalize_severity() -> None:
    assert normalize_severity("[中]") == "中危"
    assert normalize_severity("高") == "高危"
    assert normalize_severity("危急") == "危急"
    assert normalize_severity("unknown") is None


def test_dedupe_includes_port() -> None:
    records = [
        StandardRecord("2026-05", "绿盟", "10.1.1.1", port="80", vuln_name="漏洞 A"),
        StandardRecord("2026-05", "绿盟", "10.1.1.1", port="8080", vuln_name="漏洞 A"),
        StandardRecord("2026-05", "绿盟", "10.1.1.1", port="80", vuln_name="  漏洞   A "),
    ]
    unique, merged = dedupe(records)
    assert len(unique) == 2
    assert merged == 1
    assert normalize_vuln_name(unique[0].vuln_name)


def test_sample_pipeline(tmp_path: Path) -> None:
    result = run_pipeline(SAMPLES, tmp_path, "2026-05", CONFIG)
    assert len(result["assets"]) == 7
    assert any(record.scanner_type == "青藤云" for record in result["records"])
    assert any(record.scanner_type == "阿里云" for record in result["records"])
    assert any(record.scanner_type == "绿盟" for record in result["records"])
    assert (tmp_path / "阶段1_标准漏洞清单.xlsx").exists()
    assert (tmp_path / "阶段1_导入统计.json").exists()


def test_nsfocus_merged_port_cells_are_filled_down(monkeypatch) -> None:
    rows = [
        ["8080", "TCP", "http", "漏洞 A", "", "[中]", "", "", "", "", "", "", "", "", "", "", "", "详情 A", "方案 A", "验证 A"],
        ["", "", "", "漏洞 B", "", "[高]", "", "", "", "", "", "", "", "", "", "", "", "详情 B", "方案 B", "验证 B"],
    ]
    fields = {
        "port": 0,
        "protocol": 1,
        "service": 2,
        "vuln_name": 3,
        "severity": 5,
        "vuln_detail": 17,
        "fix_method": 18,
        "verify_info": 19,
    }
    monkeypatch.setattr("vms_stage1.core.xls_rows", lambda path, config: (rows, fields))
    assets = {"10.1.1.1": {"organization": "组织", "project": "项目", "workspace": "空间", "owner": "负责人"}}
    result = parse_nsfocus_host(Path("10.1.1.1.xls"), "2026-05", {}, assets)
    assert len(result.records) == 2
    assert result.records[1].port == "8080"
    assert result.records[1].protocol == "TCP"
    assert result.records[1].service == "http"


def test_parse_assets_uses_xls_reader_for_legacy_excel(monkeypatch) -> None:
    rows = [["10.1.1.1", "组织", "项目", "空间", "负责人"]]
    fields = {"ip": 0, "organization": 1, "project": 2, "workspace": 3, "owner": 4}
    monkeypatch.setattr("vms_stage1.core.xls_rows", lambda path, config: (rows, fields))
    assets = parse_assets(Path("资产.xls"), {})
    assert assets["10.1.1.1"]["project"] == "项目"


def test_parse_simple_scanner_uses_xls_reader_for_legacy_excel(monkeypatch) -> None:
    rows = [["10.1.1.1", "高危", "漏洞 A"]]
    fields = {"ip": 0, "severity": 1, "vuln_name": 2}
    monkeypatch.setattr("vms_stage1.core.xls_rows", lambda path, config: (rows, fields))
    result = parse_simple_xlsx(Path("扫描.xls"), "2026-05", "青藤云", {}, {})
    assert len(result.records) == 1
    assert result.records[0].vuln_name == "漏洞 A"


def test_field_mapping_does_not_depend_on_column_order() -> None:
    config = {"fields": {"ip": "IP地址", "owner": "项目负责人"}, "required": ["ip", "owner"]}
    fields = resolve_fields(["项目负责人", "其他字段", "IP地址"], config)
    assert fields == {"ip": 2, "owner": 0}


def test_safe_extract_rejects_path_traversal(tmp_path: Path) -> None:
    archive_path = tmp_path / "unsafe.zip"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("../escape.txt", "blocked")
    with pytest.raises(ValueError, match="ZIP 路径越界"):
        safe_extract(archive_path, tmp_path / "extract")


def test_previous_month_status_and_remark_are_attached_by_port() -> None:
    previous = [
        StandardRecord(
            "2026-04",
            "绿盟",
            "10.1.1.1",
            port="2070",
            vuln_name="Dubbo 未授权访问漏洞",
            handle_status="已通知",
            remark="等待项目反馈",
        )
    ]
    current = [
        StandardRecord("2026-05", "绿盟", "10.1.1.1", port="2070", vuln_name="Dubbo 未授权访问漏洞"),
        StandardRecord("2026-05", "绿盟", "10.1.1.1", port="8080", vuln_name="Dubbo 未授权访问漏洞"),
    ]
    attach_previous_month(current, previous)
    assert current[0].previous_month_status == "已通知"
    assert current[0].previous_month_remark == "等待项目反馈"
    assert current[1].previous_month_status == "无"
    assert current[1].previous_month_remark == "无"
