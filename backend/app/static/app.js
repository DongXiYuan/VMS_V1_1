const state = {
  records: [],
  activePage: "dashboard",
  selectedRecordIds: new Set(),
  drilldown: null,
};

const pageMeta = {
  dashboard: ["工作台", "查看当前漏洞数据和处理进度"],
  imports: ["文件导入", "上传真实文件，预览确认后发布"],
  assets: ["资产管理", "查看 IP 与项目、负责人映射"],
  records: ["漏洞清单", "筛选、批量处理并识别复发漏洞"],
  anomalies: ["异常处理", "导出未匹配资产并执行重匹配"],
};

const previewLabels = {
  assets: { created: "新增资产", updated: "更新资产", unchanged: "未变化", invalid: "异常记录" },
  vulnerabilities: {
    records: "有效漏洞",
    filtered_low: "低危过滤",
    indexed_hosts: "索引主机数",
    skipped_hosts: "跳过主机数",
    parsed_host_reports: "解析主机报告数",
    missing_host_reports: "缺失主机报告",
    scanner_total: "扫描器漏洞总数",
  },
};

const issueLabels = { blocking: "阻止发布", warning: "提醒确认" };
const $ = (id) => document.getElementById(id);

const escapeHtml = (value) =>
  String(value ?? "").replace(/[&<>"']/g, (char) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#039;",
  }[char]));

function currentMonths() {
  return { from: $("global-month-from").value.trim(), to: $("global-month-to").value.trim() };
}

function currentEffectiveMonthLabel() {
  const { from, to } = currentMonths();
  if (from && to && from === to) return from;
  if (from || to) return `${from || "开始"} - ${to || "结束"}`;
  return "最新月份";
}

function setGlobalMonths(month) {
  if (!month) return;
  $("global-month-from").value = month;
  $("global-month-to").value = month;
}

function applyMonthParams(params) {
  const { from, to } = currentMonths();
  if (from && to && from === to) {
    params.set("scan_month", from);
    return params;
  }
  if (from) params.set("scan_month_from", from);
  if (to) params.set("scan_month_to", to);
  return params;
}

function buildRecordParams() {
  const params = applyMonthParams(new URLSearchParams());
  if ($("filter-scanner").value) params.set("scanner_type", $("filter-scanner").value);
  if ($("filter-status").value) params.set("handle_status", $("filter-status").value);
  if ($("filter-project").value.trim()) params.set("project", $("filter-project").value.trim());
  if ($("filter-vuln-name").value.trim()) params.set("vuln_name", $("filter-vuln-name").value.trim());
  if ($("filter-reopened").checked) params.set("reopened_only", "true");
  return params;
}

async function api(path, options = {}) {
  const isFormData = options.body instanceof FormData;
  const headers = isFormData ? { ...(options.headers || {}) } : { "Content-Type": "application/json", ...(options.headers || {}) };
  const response = await fetch(path, { ...options, headers });
  if (!response.ok) {
    const detail = await response.json().catch(() => ({}));
    throw new Error(detail.detail || `请求失败：${response.status}`);
  }
  return response.json();
}

function notify(message, isError = false) {
  const box = $("notice");
  box.textContent = message;
  box.className = `notice${isError ? " error" : ""}`;
  box.classList.remove("hidden");
  setTimeout(() => box.classList.add("hidden"), 4200);
}

function emptyRow(columns, message = "暂无数据") {
  return `<tr><td colspan="${columns}" class="muted">${message}</td></tr>`;
}

function renderBars(target, values) {
  const entries = Object.entries(values || {});
  const max = Math.max(1, ...entries.map(([, value]) => Number(value || 0)));
  $(target).innerHTML = entries.length
    ? entries
        .map(
          ([label, value]) => `
            <div class="bar-row">
              <span>${escapeHtml(label)}</span>
              <div class="bar-track"><div class="bar-fill" style="width:${(Number(value) / max) * 100}%"></div></div>
              <strong>${escapeHtml(value)}</strong>
            </div>
          `,
        )
        .join("")
    : `<p class="muted">暂无数据</p>`;
}

function renderRankList(target, items, labelKey, drilldownKind = "") {
  $(target).innerHTML = items.length
    ? items
        .map(
          (item, index) => `
            <div class="rank-row ${drilldownKind ? "clickable drilldown-trigger" : ""}" ${drilldownKind ? `data-drilldown-kind="${drilldownKind}" data-drilldown-value="${escapeHtml(item[labelKey])}"` : ""}>
              <span class="rank-index">${index + 1}</span>
              <span class="rank-label">${escapeHtml(item[labelKey])}</span>
              <strong>${escapeHtml(item.count)}</strong>
            </div>
          `,
        )
        .join("")
    : `<p class="muted">暂无数据</p>`;
}

function drilldownTitle(kind, value) {
  if (kind === "project") return `系统漏洞明细：${value}`;
  if (kind === "vuln_name") return `漏洞名称明细：${value}`;
  return `复发漏洞明细：${value}`;
}

function drilldownSummary(kind, total, value) {
  if (kind === "project") return `当前筛选条件下，系统 ${value} 共命中 ${total} 条漏洞记录。`;
  if (kind === "vuln_name") return `当前筛选条件下，漏洞 ${value} 共命中 ${total} 条漏洞记录。`;
  return `当前筛选条件下，共命中 ${total} 条复发漏洞记录。`;
}

function renderPreview(target, data, kind) {
  const labels = previewLabels[kind] || {};
  const summary = Object.entries(data.summary || {})
    .map(
      ([key, value]) => `
        <div class="mini-card">
          <span>${escapeHtml(labels[key] || key)}</span>
          <strong>${escapeHtml(value)}</strong>
        </div>
      `,
    )
    .join("");
  const issues = (data.issues || [])
    .map(
      (issue) => `
        <tr class="${issue.level === "blocking" ? "issue-blocking" : "issue-warning"}">
          <td>${escapeHtml(issueLabels[issue.level] || issue.level)}</td>
          <td>${escapeHtml(issue.issue_type)}</td>
          <td>${escapeHtml(issue.ip || "-")}</td>
          <td>${escapeHtml(issue.detail)}</td>
        </tr>
      `,
    )
    .join("");
  const hasWarnings = (data.issues || []).some((issue) => issue.level === "warning");
  const disabled = data.has_blocking_errors ? "disabled" : "";

  $(target).classList.remove("muted");
  $(target).innerHTML = `
    <div class="preview-title">
      <strong>${escapeHtml(data.original_filename)}</strong>
      <span class="count-pill">${escapeHtml(data.status)}</span>
    </div>
    ${data.replacement_warning ? '<p class="warning-text">同月已有有效批次，发布后将替换当前版本。</p>' : ""}
    <div class="mini-cards">${summary}</div>
    <div class="table-wrap">
      <table class="issue-table">
        <thead><tr><th>级别</th><th>类型</th><th>IP</th><th>详情</th></tr></thead>
        <tbody>${issues || emptyRow(4, "无异常或警告")}</tbody>
      </table>
    </div>
    <button ${disabled} onclick="publishPreview('${kind}', ${data.id}, ${hasWarnings})">确认发布</button>
    ${data.has_blocking_errors ? '<p class="error-text">存在关键错误，无法发布。请修正文件后重新上传。</p>' : ""}
  `;
}

window.publishPreview = async (kind, id, hasWarnings) => {
  if (hasWarnings && !window.confirm("当前预览存在警告，确认仍然发布吗？")) return;
  try {
    const path = kind === "assets" ? `/api/imports/assets/${id}/publish` : `/api/imports/vulnerabilities/${id}/publish`;
    const options = kind === "assets" ? { method: "POST" } : { method: "POST", body: JSON.stringify({ confirm_warnings: hasWarnings }) };
    const result = await api(path, options);
    notify("发布成功");
    if (kind === "assets") {
      await loadAssets();
      return;
    }
    setGlobalMonths($("upload-month").value.trim() || result.scan_month);
    await loadDashboard();
    await loadRecords();
    await loadAnomalies();
  } catch (error) {
    notify(error.message, true);
  }
};

function formatDateTime(value) {
  if (!value) return "-";
  const normalized = typeof value === "string" && !/[zZ]|[+-]\d{2}:\d{2}$/.test(value) ? `${value}Z` : value;
  const date = new Date(normalized);
  if (Number.isNaN(date.getTime())) return escapeHtml(value);
  const parts = new Intl.DateTimeFormat("zh-CN", {
    timeZone: "Asia/Shanghai",
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    hour12: false,
  }).formatToParts(date);
  const get = (type) => parts.find((part) => part.type === type)?.value || "";
  return `${get("year")}-${get("month")}-${get("day")} ${get("hour")}:${get("minute")}`;
}

function textButton(label, onClick) {
  return `<button type="button" class="small-button secondary" onclick="${onClick}">${escapeHtml(label)}</button>`;
}

function detailButton(item) {
  return textButton(item.vuln_name, `openDetail(${item.id})`);
}

function previousButton(item) {
  if (!item.previous_month_status || item.previous_month_status === "无") return "无";
  return textButton(item.previous_month_status, `openPrevious(${item.id})`);
}

function reopenedBadge(item) {
  return item.is_reopened ? `<span class="reopened-badge">复发待复查</span>` : "-";
}

function updateSelectedCount() {
  $("selected-count").textContent = `已选 ${state.selectedRecordIds.size} 条`;
}

function syncSelectAllCheckbox() {
  $("select-all-records").checked = state.records.length > 0 && state.records.every((item) => state.selectedRecordIds.has(item.id));
}

async function loadDashboard() {
  const params = applyMonthParams(new URLSearchParams());
  const [overview, topProjects, topVulns, monthlyTrend, reopenedTrend] = await Promise.all([
    api(`/api/statistics/overview?${params}`),
    api(`/api/statistics/top-projects?${params}`),
    api(`/api/statistics/top-vulnerabilities?${params}`),
    api(`/api/statistics/monthly-trend?${params}`),
    api(`/api/statistics/reopened-trend?${params}`),
  ]);

  const cards = [
    ["漏洞总数", overview.total],
    ["未修复", overview.unresolved_count],
    ["已处置", overview.disposed_count],
    ["涉及项目", overview.project_count],
    ["项目待下线", overview.pending_offline_count],
    ["导入异常", overview.anomaly_count],
    ["复发漏洞", overview.reopened_count],
  ];
  $("dashboard-cards").innerHTML = cards
    .map(([label, value]) => {
      const isDrilldown = label === "复发漏洞" && Number(value) > 0;
      return `<div class="card ${isDrilldown ? "clickable drilldown-trigger" : ""}" ${
        isDrilldown ? 'data-drilldown-kind="reopened" data-drilldown-value="current"' : ""
      }><p>${escapeHtml(label)}</p><strong>${escapeHtml(value)}</strong></div>`;
    })
    .join("");
  renderBars("scanner-bars", overview.scanner_counts);
  renderBars("status-bars", overview.status_counts);
  renderRankList("top-projects-list", topProjects.items || [], "project", "project");
  renderRankList("top-vulns-list", topVulns.items || [], "vuln_name", "vuln_name");
  $("monthly-trend-table").innerHTML = (monthlyTrend.items || []).length
    ? monthlyTrend.items
        .map(
          (item) => `
            <tr>
              <td>${escapeHtml(item.scan_month)}</td>
              <td>${escapeHtml(item.total)}</td>
              <td>${escapeHtml(item.disposed_count)}</td>
              <td>${escapeHtml((item.fixed_rate * 100).toFixed(1))}%</td>
              <td>${escapeHtml(item.scanner_counts["青藤云"] ?? 0)}</td>
              <td>${escapeHtml(item.scanner_counts["阿里云"] ?? 0)}</td>
              <td>${escapeHtml(item.scanner_counts["绿盟"] ?? 0)}</td>
            </tr>
          `,
        )
        .join("")
    : emptyRow(7);
  $("reopened-trend-table").innerHTML = (reopenedTrend.items || []).length
    ? reopenedTrend.items
        .map(
          (item) => `
            <tr class="${item.reopened_count ? "drilldown-trigger" : ""}" ${item.reopened_count ? `data-drilldown-kind="reopened" data-drilldown-value="${escapeHtml(item.scan_month)}"` : ""}>
              <td>${escapeHtml(item.scan_month)}</td>
              <td>${escapeHtml(item.reopened_count)}</td>
            </tr>
          `,
        )
        .join("")
    : emptyRow(2);
}

async function loadAssets() {
  const data = await api("/api/assets");
  $("asset-count").textContent = `${data.total} 条`;
  $("asset-table").innerHTML = data.items.length
    ? data.items
        .map(
          (item) => `
            <tr>
              <td>${escapeHtml(item.ip)}</td>
              <td>${escapeHtml(item.organization)}</td>
              <td>${escapeHtml(item.project)}</td>
              <td>${escapeHtml(item.workspace)}</td>
              <td>${escapeHtml(item.owner)}</td>
            </tr>
          `,
        )
        .join("")
    : emptyRow(5, "尚未导入资产数据");
}

async function loadRecords() {
  const params = buildRecordParams();
  const data = await api(`/api/records?${params}`);
  state.records = data.items;
  state.selectedRecordIds = new Set([...state.selectedRecordIds].filter((id) => data.items.some((item) => item.id === id)));
  updateSelectedCount();
  syncSelectAllCheckbox();
  $("record-count").textContent = `${data.total} 条`;
  $("record-table").innerHTML = data.items.length
    ? data.items
        .map(
          (item) => `
            <tr class="${item.is_reopened ? "reopened-row" : ""}">
              <td><input class="row-checkbox" type="checkbox" data-record-id="${item.id}" ${state.selectedRecordIds.has(item.id) ? "checked" : ""} /></td>
              <td>${item.id}</td>
              <td>${escapeHtml(item.scan_month)}</td>
              <td>${formatDateTime(item.first_detected_at)}</td>
              <td>${escapeHtml(item.scanner_type)}</td>
              <td>${escapeHtml(item.ip)}</td>
              <td>${escapeHtml(item.port || "-")}</td>
              <td>${escapeHtml(item.project || "-")}</td>
              <td>${escapeHtml(item.severity)}</td>
              <td>${detailButton(item)}</td>
              <td>${escapeHtml(item.handle_status)}</td>
              <td>${escapeHtml(item.remark || "-")}</td>
              <td>${previousButton(item)}</td>
              <td>${reopenedBadge(item)}</td>
              <td>${textButton("编辑", `openEdit(${item.id})`)}</td>
            </tr>
          `,
        )
        .join("")
    : emptyRow(15);
}

async function loadAnomalies() {
  const params = applyMonthParams(new URLSearchParams());
  const data = await api(`/api/anomalies?${params}`);
  $("anomaly-filter-month").textContent = `当前筛选月份：${currentEffectiveMonthLabel()}`;
  $("anomaly-count").textContent = `${data.total} 条`;
  $("anomaly-table").innerHTML = data.items.length
    ? data.items
        .map(
          (item) => `
            <tr>
              <td>${escapeHtml(item.scanner_type)}</td>
              <td>${escapeHtml(item.source_file)}</td>
              <td>${escapeHtml(item.ip || "-")}</td>
              <td>${escapeHtml(item.anomaly_type)}</td>
              <td>${escapeHtml(item.detail)}</td>
            </tr>
          `,
        )
        .join("")
    : emptyRow(5, `当前筛选条件 ${currentEffectiveMonthLabel()} 下暂无异常记录`);
}

async function loadActivePage() {
  try {
    if (state.activePage === "dashboard") await loadDashboard();
    if (state.activePage === "assets") await loadAssets();
    if (state.activePage === "records") await loadRecords();
    if (state.activePage === "anomalies") await loadAnomalies();
  } catch (error) {
    notify(error.message, true);
  }
}

function switchPage(page) {
  state.activePage = page;
  document.querySelectorAll(".nav-item").forEach((button) => button.classList.toggle("active", button.dataset.page === page));
  document.querySelectorAll(".page").forEach((section) => section.classList.toggle("active", section.id === `page-${page}`));
  [$("page-title").textContent, $("page-description").textContent] = pageMeta[page];
  loadActivePage();
}

window.openEdit = (id) => {
  const record = state.records.find((item) => item.id === id);
  if (!record) return;
  $("edit-id").value = id;
  $("edit-record-name").textContent = `${record.scan_month} | ${record.ip}${record.port ? `:${record.port}` : ""} | ${record.vuln_name}`;
  $("edit-status").value = record.handle_status;
  $("edit-remark").value = record.remark || "";
  $("edit-dialog").showModal();
};

window.openDetail = (id) => {
  const record = state.records.find((item) => item.id === id) || state.drilldown?.items?.find((item) => item.id === id);
  if (!record) return;
  $("detail-record-name").textContent = `${record.scanner_type} | ${record.ip}${record.port ? `:${record.port}` : ""}`;
  $("detail-first-detected-at").value = formatDateTime(record.first_detected_at);
  $("detail-vuln-detail").value = record.vuln_detail || "暂无漏洞详情";
  $("detail-verify-info").value = record.verify_info || "暂无验证内容";
  $("detail-fix-method").value = record.fix_method || "暂无修复方案";
  $("detail-dialog").showModal();
};

window.openPrevious = (id) => {
  const record = state.records.find((item) => item.id === id);
  if (!record) return;
  $("previous-record-name").textContent = `${record.scan_month} | ${record.ip}${record.port ? `:${record.port}` : ""} | ${record.vuln_name}`;
  $("previous-status").value = record.previous_month_status || "无";
  $("previous-remark").value = record.previous_month_remark || "无";
  $("previous-dialog").showModal();
};

async function openDrilldown(kind, value) {
  const params = applyMonthParams(new URLSearchParams());
  let path = "";
  if (kind === "project") {
    params.set("project", value);
    path = `/api/statistics/top-projects/details?${params.toString()}`;
  } else if (kind === "vuln_name") {
    params.set("vuln_name", value);
    path = `/api/statistics/top-vulnerabilities/details?${params.toString()}`;
  } else {
    if (value && value !== "current") {
      params.delete("scan_month_from");
      params.delete("scan_month_to");
      params.set("scan_month", value);
    }
    path = `/api/statistics/reopened/details?${params.toString()}`;
  }

  const data = await api(path);
  state.drilldown = { kind, value, items: data.items || [] };
  $("drilldown-title").textContent = drilldownTitle(kind, value === "current" ? currentEffectiveMonthLabel() : value);
  $("drilldown-summary").textContent = drilldownSummary(kind, data.total || 0, value === "current" ? currentEffectiveMonthLabel() : value);
  $("drilldown-table").innerHTML = (data.items || []).length
    ? data.items
        .map(
          (item) => `
            <tr>
              <td>${escapeHtml(item.scan_month)}</td>
              <td>${escapeHtml(item.scanner_type)}</td>
              <td>${escapeHtml(item.ip)}${item.port ? `:${escapeHtml(item.port)}` : ""}</td>
              <td>${escapeHtml(item.project || "-")}</td>
              <td>${escapeHtml(item.severity || "-")}</td>
              <td>${detailButton(item)}</td>
              <td>${escapeHtml(item.handle_status || "-")}</td>
              <td>${escapeHtml(formatDateTime(item.first_detected_at))}</td>
            </tr>
          `,
        )
        .join("")
    : emptyRow(8, "当前条件下暂无明细");
  $("drilldown-dialog").showModal();
}

function applyDrilldownToRecords() {
  const drilldown = state.drilldown;
  if (!drilldown) return;
  $("filter-project").value = drilldown.kind === "project" ? drilldown.value : "";
  $("filter-vuln-name").value = drilldown.kind === "vuln_name" ? drilldown.value : "";
  $("filter-reopened").checked = drilldown.kind === "reopened";
  if (drilldown.kind === "reopened" && drilldown.value && drilldown.value !== "current") {
    setGlobalMonths(drilldown.value);
  }
}

$("edit-form").addEventListener("submit", async (event) => {
  if (event.submitter?.value !== "default") return;
  event.preventDefault();
  try {
    await api(`/api/records/${$("edit-id").value}`, {
      method: "PATCH",
      body: JSON.stringify({
        handle_status: $("edit-status").value,
        remark: $("edit-remark").value,
        changed_by: "admin",
      }),
    });
    $("edit-dialog").close();
    notify("状态和备注已保存");
    await loadRecords();
    await loadDashboard();
  } catch (error) {
    notify(error.message, true);
  }
});

$("nav").addEventListener("click", (event) => {
  const button = event.target.closest(".nav-item");
  if (button) switchPage(button.dataset.page);
});

$("page-dashboard").addEventListener("click", async (event) => {
  const trigger = event.target.closest("[data-drilldown-kind]");
  if (!trigger) return;
  try {
    await openDrilldown(trigger.dataset.drilldownKind, trigger.dataset.drilldownValue || "");
  } catch (error) {
    notify(error.message, true);
  }
});

$("drilldown-open-records").addEventListener("click", (event) => {
  event.preventDefault();
  applyDrilldownToRecords();
  $("drilldown-dialog").close();
  switchPage("records");
});

$("record-table").addEventListener("change", (event) => {
  const checkbox = event.target.closest("input[type='checkbox'][data-record-id]");
  if (!checkbox) return;
  const recordId = Number(checkbox.dataset.recordId);
  if (checkbox.checked) state.selectedRecordIds.add(recordId);
  else state.selectedRecordIds.delete(recordId);
  updateSelectedCount();
  syncSelectAllCheckbox();
});

$("select-all-records").addEventListener("change", (event) => {
  if (event.target.checked) state.records.forEach((item) => state.selectedRecordIds.add(item.id));
  else state.records.forEach((item) => state.selectedRecordIds.delete(item.id));
  document.querySelectorAll("#record-table input[type='checkbox'][data-record-id]").forEach((element) => {
    element.checked = event.target.checked;
  });
  updateSelectedCount();
});

$("refresh-page").addEventListener("click", loadActivePage);
$("search-records").addEventListener("click", loadRecords);
$("export-records").addEventListener("click", () => {
  const params = buildRecordParams();
  params.set("mode", $("export-mode").value);
  window.location.href = `/api/exports/vulnerabilities?${params.toString()}`;
});

$("batch-apply").addEventListener("click", async () => {
  const recordIds = Array.from(state.selectedRecordIds);
  if (!recordIds.length) return notify("请先选择要批量修改的漏洞记录", true);
  const handleStatus = $("batch-status").value || null;
  const remark = $("batch-remark").value.trim() || null;
  if (!handleStatus && !remark) return notify("请至少填写批量状态或批量备注之一", true);
  try {
    await api("/api/records/batch-update", {
      method: "POST",
      body: JSON.stringify({ record_ids: recordIds, handle_status: handleStatus, remark, changed_by: "admin" }),
    });
    notify(`已批量修改 ${recordIds.length} 条记录`);
    await loadRecords();
    await loadDashboard();
  } catch (error) {
    notify(error.message, true);
  }
});

$("batch-delete").addEventListener("click", async () => {
  const recordIds = Array.from(state.selectedRecordIds);
  if (!recordIds.length) return notify("请先选择要批量删除的漏洞记录", true);
  const reason = $("batch-delete-reason").value;
  if (!window.confirm(`确认软删除这 ${recordIds.length} 条记录吗？删除原因：${reason}`)) return;
  try {
    await api("/api/records/batch-delete", {
      method: "POST",
      body: JSON.stringify({ record_ids: recordIds, delete_reason: reason, changed_by: "admin" }),
    });
    state.selectedRecordIds.clear();
    updateSelectedCount();
    syncSelectAllCheckbox();
    notify(`已软删除 ${recordIds.length} 条记录`);
    await loadRecords();
    await loadDashboard();
  } catch (error) {
    notify(error.message, true);
  }
});

$("export-unmatched-raw").addEventListener("click", () => {
  const params = applyMonthParams(new URLSearchParams());
  params.set("dedup_by_ip", "false");
  window.location.href = `/api/anomalies/unmatched-assets/export?${params.toString()}`;
});

$("export-unmatched-dedup").addEventListener("click", () => {
  const params = applyMonthParams(new URLSearchParams());
  params.set("dedup_by_ip", "true");
  window.location.href = `/api/anomalies/unmatched-assets/export?${params.toString()}`;
});

$("rematch-unmatched").addEventListener("click", async () => {
  try {
    const { from, to } = currentMonths();
    const payload = from && to && from === to ? { scan_month: from, changed_by: "admin" } : { scan_month_from: from || null, scan_month_to: to || null, changed_by: "admin" };
    const result = await api("/api/anomalies/unmatched-assets/rematch", { method: "POST", body: JSON.stringify(payload) });
    notify(`重匹配完成：成功 ${result.matched_count} 条，仍未匹配 ${result.unmatched_count} 条`);
    await loadRecords();
    await loadAnomalies();
    await loadDashboard();
  } catch (error) {
    notify(error.message, true);
  }
});

$("asset-upload-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  try {
    const data = await api("/api/imports/assets/preview", { method: "POST", body: new FormData(event.target) });
    renderPreview("asset-preview", data, "assets");
    notify("资产表解析完成，请检查预览");
  } catch (error) {
    notify(error.message, true);
  }
});

$("vulnerability-upload-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  try {
    const data = await api("/api/imports/vulnerabilities/preview", { method: "POST", body: new FormData(event.target) });
    renderPreview("vulnerability-preview", data, "vulnerabilities");
    notify("扫描文件解析完成，请检查预览");
  } catch (error) {
    notify(error.message, true);
  }
});

$("upload-scanner").addEventListener("change", (event) => {
  $("vulnerability-file").accept = event.target.value === "绿盟" ? ".zip" : ".xls,.xlsx";
});

$("import-assets").addEventListener("click", async () => {
  try {
    const data = await api("/api/dev/import-assets-sample", { method: "POST" });
    $("import-result").textContent = JSON.stringify(data, null, 2);
    notify("资产表示例导入完成");
  } catch (error) {
    notify(error.message, true);
  }
});

$("import-vulns").addEventListener("click", async () => {
  try {
    const { from } = currentMonths();
    const data = await api("/api/dev/import-vulnerabilities-sample", { method: "POST", body: JSON.stringify({ scan_month: from || "2026-05" }) });
    $("import-result").textContent = JSON.stringify(data, null, 2);
    notify("漏洞样例导入完成");
  } catch (error) {
    notify(error.message, true);
  }
});

updateSelectedCount();
loadDashboard().catch((error) => notify(error.message, true));
