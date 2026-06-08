from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class RecordUpdate(BaseModel):
    handle_status: str | None = Field(default=None, description="新的处置状态")
    remark: str | None = Field(default=None, description="新的备注内容")
    changed_by: str = Field(default="prototype-admin", description="操作人")


class RecordBatchUpdate(BaseModel):
    record_ids: list[int] = Field(min_length=1, description="需要批量更新的漏洞记录 ID 列表")
    handle_status: str | None = Field(default=None, description="批量设置的新处置状态")
    remark: str | None = Field(default=None, description="批量设置的新备注")
    changed_by: str = Field(default="prototype-admin", description="执行批量更新的用户")


class RecordBatchDelete(BaseModel):
    record_ids: list[int] = Field(min_length=1, description="需要批量软删除的漏洞记录 ID 列表")
    delete_reason: str = Field(description="软删除原因，例如误导入、重复导入、无需修复")
    changed_by: str = Field(default="prototype-admin", description="执行批量删除的用户")


class BatchActionResult(BaseModel):
    total: int = Field(description="本次请求中包含的记录数量")
    updated_count: int = Field(default=0, description="本次成功批量更新的记录数量")
    deleted_count: int = Field(default=0, description="本次成功软删除的记录数量")


class RematchRequest(BaseModel):
    scan_month: str | None = Field(default=None, description="单个月份，格式 YYYY-MM")
    scan_month_from: str | None = Field(default=None, description="起始月份，格式 YYYY-MM")
    scan_month_to: str | None = Field(default=None, description="结束月份，格式 YYYY-MM")
    scanner_type: str | None = Field(default=None, description="扫描器类型")
    changed_by: str = Field(default="prototype-admin", description="执行重匹配的用户")


class RecordOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int = Field(description="漏洞记录 ID")
    scan_month: str = Field(description="扫描月份，格式为 YYYY-MM")
    scanner_type: str = Field(description="扫描器类型")
    ip: str = Field(description="资产 IP")
    port: str = Field(description="端口")
    protocol: str = Field(description="协议")
    service: str = Field(description="服务")
    organization: str = Field(description="资产所属组织")
    project: str = Field(description="项目名，也就是系统名")
    workspace: str = Field(description="工作空间")
    owner: str = Field(description="项目负责人")
    severity: str = Field(description="漏洞等级")
    vuln_name: str = Field(description="漏洞名称")
    vuln_detail: str = Field(description="漏洞详情")
    verify_info: str = Field(description="验证内容")
    fix_method: str = Field(description="修复方案")
    first_detected_at: datetime = Field(description="该漏洞首次进入标准清单的时间")
    handle_status: str = Field(description="当前处置状态")
    remark: str = Field(description="当前备注")
    previous_month_status: str = Field(description="上月同漏洞的处置状态")
    previous_month_remark: str = Field(description="上月同漏洞的备注")
    is_reopened: bool = Field(description="是否为上月已处置但本月复发的漏洞")
    reopened_from_status: str = Field(description="复发时继承的上月处置状态")
    asset_match_status: str = Field(description="资产匹配状态")
    is_deleted: bool = Field(description="是否已被软删除")
    deleted_at: datetime | None = Field(description="软删除时间")
    deleted_by: str = Field(description="软删除执行人")
    deleted_reason: str = Field(description="软删除原因")
    source_file: str = Field(description="来源文件")


class ChangeOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int = Field(description="变更记录 ID")
    record_id: int = Field(description="被修改的漏洞记录 ID")
    field_name: str = Field(description="被修改字段")
    old_value: str = Field(description="修改前内容")
    new_value: str = Field(description="修改后内容")
    changed_by: str = Field(description="操作人")
    changed_at: datetime = Field(description="修改时间")


class ListResponse(BaseModel):
    total: int = Field(description="符合筛选条件的漏洞总数")
    items: list[RecordOut] = Field(description="漏洞记录列表")


class SampleImportRequest(BaseModel):
    scan_month: str = Field(description="导入月份，例如 2026-05", pattern=r"^\d{4}-\d{2}$", examples=["2026-05"])


class PreviewIssue(BaseModel):
    level: str = Field(description="问题级别：blocking 或 warning")
    issue_type: str = Field(description="问题类型")
    detail: str = Field(description="问题详情")
    ip: str = Field(default="", description="相关 IP")
    source_file: str = Field(default="", description="相关来源文件")


class PreviewOut(BaseModel):
    id: int = Field(description="预览批次 ID")
    import_type: str = Field(description="导入类型：assets 或 vulnerabilities")
    scanner_type: str = Field(description="扫描器类型")
    scan_month: str = Field(description="扫描月份")
    original_filename: str = Field(description="上传时的原始文件名")
    status: str = Field(description="预览状态：preview、published 或 expired")
    has_blocking_errors: bool = Field(description="是否存在阻止发布的错误")
    summary: dict[str, object] = Field(description="预览统计摘要")
    issues: list[PreviewIssue] = Field(description="预览问题明细")
    expires_at: datetime = Field(description="未发布预览的过期时间")
    replacement_warning: bool = Field(default=False, description="发布后是否会替换同月当前有效批次")


class PublishRequest(BaseModel):
    confirm_warnings: bool = Field(default=False, description="存在普通警告时，确认仍然发布")
