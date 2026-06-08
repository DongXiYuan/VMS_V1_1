from __future__ import annotations

from collections import defaultdict
from io import BytesIO
import re
import zipfile

from openpyxl import Workbook
from openpyxl.styles import Font

from .models import VulnerabilityRecord


MERGED_HEADERS = [
    "序号",
    "扫描器类型",
    "IP",
    "端口",
    "协议",
    "服务",
    "组织",
    "项目",
    "工作空间",
    "负责人",
    "危险等级",
    "漏洞名称",
    "漏洞详情",
    "漏洞验证",
    "漏洞修复方案",
    "处置状态",
    "备注",
]

SPLIT_HEADERS = [
    "序号",
    "IP",
    "端口",
    "协议",
    "服务",
    "组织",
    "项目",
    "工作空间",
    "负责人",
    "危险等级",
    "漏洞名称",
    "漏洞详情",
    "漏洞验证",
    "漏洞修复方案",
    "处置状态",
    "备注",
]

UNMATCHED_HEADERS = [
    "IP",
    "扫描器类型",
    "月份",
    "项目",
    "漏洞名称",
    "出现次数",
    "来源文件",
]


def safe_name(value: str) -> str:
    cleaned = re.sub(r'[\\/:*?"<>|]+', "_", (value or "").strip())
    return cleaned or "未匹配项目"


def month_label(scan_month: str | None, scan_month_from: str | None, scan_month_to: str | None) -> str:
    if scan_month:
        return scan_month
    if scan_month_from and scan_month_to:
        return f"{scan_month_from}_to_{scan_month_to}"
    return scan_month_from or scan_month_to or "all"


def workbook_bytes(records: list[VulnerabilityRecord], mode: str) -> bytes:
    workbook = Workbook()
    sheet = workbook.active
    sheet.title = "漏洞清单"
    headers = MERGED_HEADERS if mode == "project-merged" else SPLIT_HEADERS
    sheet.append(headers)
    for cell in sheet[1]:
        cell.font = Font(bold=True)

    for index, record in enumerate(records, start=1):
        base = [
            index,
            record.ip,
            record.port,
            record.protocol,
            record.service,
            record.organization,
            record.project,
            record.workspace,
            record.owner,
            record.severity,
            record.vuln_name,
            record.vuln_detail,
            record.verify_info,
            record.fix_method,
            record.handle_status,
            record.remark,
        ]
        row = [index, record.scanner_type, *base[1:]] if mode == "project-merged" else base
        sheet.append(row)

    stream = BytesIO()
    workbook.save(stream)
    return stream.getvalue()


def group_records(records: list[VulnerabilityRecord], mode: str) -> dict[tuple[str, str | None], list[VulnerabilityRecord]]:
    grouped: dict[tuple[str, str | None], list[VulnerabilityRecord]] = defaultdict(list)
    for record in records:
        project = safe_name(record.project)
        key = (project, None) if mode == "project-merged" else (project, record.scanner_type)
        grouped[key].append(record)
    return grouped


def export_zip_bytes(
    records: list[VulnerabilityRecord],
    mode: str,
    scan_month: str | None,
    scan_month_from: str | None,
    scan_month_to: str | None,
) -> tuple[bytes, str]:
    label = month_label(scan_month, scan_month_from, scan_month_to)
    stream = BytesIO()
    with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        grouped = group_records(records, mode)
        for key in sorted(grouped.keys()):
            project, scanner_type = key
            filename = (
                f"{project}_{label}_漏洞.xlsx"
                if mode == "project-merged"
                else f"{project}_{safe_name(scanner_type or '')}_{label}_漏洞.xlsx"
            )
            archive.writestr(filename, workbook_bytes(grouped[key], mode))
    return stream.getvalue(), f"vms_export_{mode}_{label}.zip"


def export_unmatched_assets_xlsx(records: list[VulnerabilityRecord], dedup_by_ip: bool) -> bytes:
    workbook = Workbook()
    sheet = workbook.active
    sheet.title = "未匹配资产"
    sheet.append(UNMATCHED_HEADERS)
    for cell in sheet[1]:
        cell.font = Font(bold=True)

    if dedup_by_ip:
        grouped: dict[str, list[VulnerabilityRecord]] = defaultdict(list)
        for record in records:
            grouped[record.ip].append(record)
        for ip in sorted(grouped):
            group = grouped[ip]
            first = group[0]
            sheet.append([
                ip,
                first.scanner_type,
                first.scan_month,
                first.project,
                first.vuln_name,
                len(group),
                "；".join(sorted({item.source_file for item in group if item.source_file})),
            ])
    else:
        for record in records:
            sheet.append([
                record.ip,
                record.scanner_type,
                record.scan_month,
                record.project,
                record.vuln_name,
                1,
                record.source_file,
            ])

    stream = BytesIO()
    workbook.save(stream)
    return stream.getvalue()
