const refs = {
  healthPill: document.getElementById("healthPill"),
  healthText: document.getElementById("healthText"),
  refreshJobsBtn: document.getElementById("refreshJobsBtn"),
  heroTarget: document.getElementById("heroTarget"),
  heroSummary: document.getElementById("heroSummary"),
  heroStatus: document.getElementById("heroStatus"),
  heroModules: document.getElementById("heroModules"),
  heroPorts: document.getElementById("heroPorts"),
  heroRisks: document.getElementById("heroRisks"),
  scanForm: document.getElementById("scanForm"),
  targetInput: document.getElementById("targetInput"),
  apiUrlInput: document.getElementById("apiUrlInput"),
  timeoutInput: document.getElementById("timeoutInput"),
  portTimeoutInput: document.getElementById("portTimeoutInput"),
  scanModeInput: document.getElementById("scanModeInput"),
  portScannerInput: document.getElementById("portScannerInput"),
  customPortsField: document.getElementById("customPortsField"),
  customPortsInput: document.getElementById("customPortsInput"),
  tcpScanInput: document.getElementById("tcpScanInput"),
  udpScanInput: document.getElementById("udpScanInput"),
  allowPrivateIpInput: document.getElementById("allowPrivateIpInput"),
  vtScanInput: document.getElementById("vtScanInput"),
  cidrTargetsInput: document.getElementById("cidrTargetsInput"),
  vtApiKeyInput: document.getElementById("vtApiKeyInput"),
  nvdApiKeyInput: document.getElementById("nvdApiKeyInput"),
  ctScanInput: document.getElementById("ctScanInput"),
  passiveDnsInput: document.getElementById("passiveDnsInput"),
  asnScanInput: document.getElementById("asnScanInput"),
  asnExpandInput: document.getElementById("asnExpandInput"),
  webAssetScanInput: document.getElementById("webAssetScanInput"),
  webCrawlerInput: document.getElementById("webCrawlerInput"),
  webJsExtractInput: document.getElementById("webJsExtractInput"),
  webSensitiveInput: document.getElementById("webSensitiveInput"),
  webDirScanInput: document.getElementById("webDirScanInput"),
  webDirFfufInput: document.getElementById("webDirFfufInput"),
  serviceRiskInput: document.getElementById("serviceRiskInput"),
  cveLookupInput: document.getElementById("cveLookupInput"),
  weakChecksInput: document.getElementById("weakChecksInput"),
  moduleCount: document.getElementById("moduleCount"),
  startScanBtn: document.getElementById("startScanBtn"),
  stopScanBtn: document.getElementById("stopScanBtn"),
  reportFileInput: document.getElementById("reportFileInput"),
  loadSampleBtn: document.getElementById("loadSampleBtn"),
  importHint: document.getElementById("importHint"),
  jobsList: document.getElementById("jobsList"),
  statusChip: document.getElementById("statusChip"),
  jobIdChip: document.getElementById("jobIdChip"),
  currentTargetValue: document.getElementById("currentTargetValue"),
  createdAtValue: document.getElementById("createdAtValue"),
  runtimeValue: document.getElementById("runtimeValue"),
  sourceValue: document.getElementById("sourceValue"),
  progressLabel: document.getElementById("progressLabel"),
  progressValue: document.getElementById("progressValue"),
  progressBar: document.getElementById("progressBar"),
  statusMessage: document.getElementById("statusMessage"),
  overviewPanel: document.getElementById("overviewPanel"),
  identityPanel: document.getElementById("identityPanel"),
  infrastructurePanel: document.getElementById("infrastructurePanel"),
  webPanel: document.getElementById("webPanel"),
  riskPanel: document.getElementById("riskPanel"),
  rawJsonView: document.getElementById("rawJsonView"),
  tabs: Array.from(document.querySelectorAll(".tab")),
  panels: Array.from(document.querySelectorAll(".tab-panel")),
};

const state = {
  currentJob: null,
  currentReport: null,
  currentSource: "idle",
  currentStatus: "idle",
  pollTimer: null,
  jobsTimer: null,
  healthTimer: null,
  activeTab: "overview",
};

function inferDefaultApiUrl() {
  const { protocol, hostname, origin } = window.location;
  if (protocol === "file:") {
    return "http://127.0.0.1:8000/api/scan";
  }
  if (hostname === "localhost" || hostname === "127.0.0.1") {
    return "http://127.0.0.1:8000/api/scan";
  }
  return `${origin}/api/scan`;
}

function getApiScanUrl() {
  return String(refs.apiUrlInput.value || "").trim() || inferDefaultApiUrl();
}

function getApiRootUrl() {
  return getApiScanUrl().replace(/\/+$/, "").replace(/\/scan$/, "");
}

function getHealthUrl() {
  const root = getApiRootUrl();
  return root.endsWith("/api") ? `${root.slice(0, -4)}/health` : `${root}/health`;
}

function getJobsUrl() {
  return `${getApiRootUrl()}/jobs`;
}

function formatDateTime(value) {
  if (!value) return "-";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return String(value);
  return new Intl.DateTimeFormat("zh-CN", {
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  }).format(date);
}

function formatRuntime(job) {
  if (!job) return "-";
  const start = job.started_at || job.created_at;
  if (!start) return "-";
  const end = job.finished_at || new Date().toISOString();
  const seconds = Math.max(0, Math.round((new Date(end) - new Date(start)) / 1000));
  const h = Math.floor(seconds / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  const s = seconds % 60;
  if (h > 0) return `${h}h ${m}m ${s}s`;
  if (m > 0) return `${m}m ${s}s`;
  return `${s}s`;
}

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function safeArray(value) {
  return Array.isArray(value) ? value : [];
}

function countEnabledModules() {
  const inputs = [
    refs.tcpScanInput,
    refs.udpScanInput,
    refs.vtScanInput,
    refs.ctScanInput,
    refs.passiveDnsInput,
    refs.asnScanInput,
    refs.asnExpandInput,
    refs.webAssetScanInput,
    refs.webCrawlerInput,
    refs.webJsExtractInput,
    refs.webSensitiveInput,
    refs.webDirScanInput,
    refs.webDirFfufInput,
    refs.serviceRiskInput,
    refs.cveLookupInput,
    refs.weakChecksInput,
    refs.allowPrivateIpInput,
  ];
  return inputs.filter((input) => input.checked).length;
}

function collectPayload() {
  return {
    target: refs.targetInput.value.trim(),
    timeout: Number(refs.timeoutInput.value || 10),
    port_timeout: Number(refs.portTimeoutInput.value || 0.8),
    port_scanner: refs.portScannerInput.value,
    scan_mode: refs.scanModeInput.value,
    custom_ports: refs.customPortsInput.value.trim() || null,
    tcp_scan: refs.tcpScanInput.checked,
    udp_scan: refs.udpScanInput.checked,
    allow_private_ip: refs.allowPrivateIpInput.checked,
    vt_scan: refs.vtScanInput.checked,
    vt_api_key: refs.vtApiKeyInput.value.trim() || null,
    nvd_api_key: refs.nvdApiKeyInput.value.trim() || null,
    cidr_targets: refs.cidrTargetsInput.value.trim(),
    ct_scan: refs.ctScanInput.checked,
    passive_dns_scan: refs.passiveDnsInput.checked,
    asn_scan: refs.asnScanInput.checked,
    asn_expand_c_segment: refs.asnExpandInput.checked,
    web_asset_scan: refs.webAssetScanInput.checked,
    web_crawler: refs.webCrawlerInput.checked,
    web_js_extract: refs.webJsExtractInput.checked,
    web_sensitive_path_extract: refs.webSensitiveInput.checked,
    web_dir_scan: refs.webDirScanInput.checked,
    web_dir_use_ffuf: refs.webDirFfufInput.checked,
    service_risk_scan: refs.serviceRiskInput.checked,
    cve_lookup: refs.cveLookupInput.checked,
    weak_nmap_checks: refs.weakChecksInput.checked,
  };
}

function getProgressPercent(status, report) {
  const map = {
    queued: 10,
    running: 62,
    stopping: 78,
    completed: 100,
    failed: 100,
    canceled: 100,
    idle: 0,
  };
  if (status !== "completed" || !report) return map[status] ?? 0;
  const modules = [
    report.dns,
    report.whois,
    report.tech_stack,
    report.virustotal,
    report.certificate_transparency,
    report.passive_dns,
    report.asn_network,
    report.web_assets,
    report.ip_scan,
    report.service_risk,
  ];
  const filled = modules.filter(Boolean).length;
  return Math.max(map.completed, Math.round((filled / modules.length) * 100));
}

function getStatusTone(status) {
  if (status === "completed") return "success";
  if (status === "failed" || status === "canceled") return "danger";
  if (status === "running" || status === "stopping") return "running";
  if (status === "queued") return "warning";
  return "neutral";
}

function getModuleState(module) {
  if (!module) return { tone: "neutral", label: "无数据", detail: "模块尚未返回结果。" };
  if (module.error) return { tone: "danger", label: "失败", detail: module.error };
  if (module.canceled) return { tone: "warning", label: "已取消", detail: module.message || "任务已取消。" };
  if (module.enabled === false) return { tone: "neutral", label: "未启用", detail: module.message || "该模块未启用。" };
  if (module.scan_performed === false) return { tone: "warning", label: "已跳过", detail: module.message || module.skip_reason || "本阶段未执行。" };
  if (module.message && !module.count && !module.total_records && !module.page_count && !module.service_count) {
    return { tone: "neutral", label: "提示", detail: module.message };
  }
  return { tone: "success", label: "完成", detail: "已返回模块结果。" };
}

function fetchJson(url, options) {
  return fetch(url, options).then(async (response) => {
    let payload = null;
    try {
      payload = await response.json();
    } catch (_error) {
      payload = null;
    }

    if (!response.ok) {
      const detail = payload?.detail || payload?.message || `HTTP ${response.status}`;
      throw new Error(detail);
    }
    return payload;
  });
}

function setHealth(text, tone) {
  refs.healthText.textContent = text;
  refs.healthPill.dataset.tone = tone;
}

async function refreshHealth() {
  try {
    const payload = await fetchJson(getHealthUrl());
    setHealth(payload.status === "ok" ? "API 正常" : "API 未知状态", payload.status === "ok" ? "success" : "warning");
  } catch (error) {
    setHealth(`API 不可达: ${error.message}`, "danger");
  }
}

function setCurrentJob(job, source = state.currentSource) {
  state.currentJob = job;
  state.currentStatus = job?.status || "idle";
  state.currentReport = job?.result || null;
  state.currentSource = source;
  syncView();
}

function setCurrentReport(report, source = "imported", status = "completed") {
  state.currentReport = report;
  state.currentSource = source;
  state.currentStatus = report?.canceled ? "canceled" : status;
  state.currentJob = null;
  syncView();
}

async function refreshJobs() {
  try {
    const payload = await fetchJson(getJobsUrl());
    renderJobs(payload.jobs || []);
  } catch (error) {
    refs.jobsList.innerHTML = `<div class="notice" data-tone="danger">${escapeHtml(`无法读取任务列表：${error.message}`)}</div>`;
  }
}

function stopPolling() {
  if (state.pollTimer) {
    window.clearInterval(state.pollTimer);
    state.pollTimer = null;
  }
}

function startPolling(jobId) {
  stopPolling();
  state.pollTimer = window.setInterval(async () => {
    try {
      const payload = await fetchJson(`${getApiScanUrl().replace(/\/+$/, "")}/${jobId}`);
      setCurrentJob(payload, "live");
      if (!["queued", "running", "stopping"].includes(payload.status)) {
        stopPolling();
        refreshJobs();
      }
    } catch (error) {
      refs.statusMessage.textContent = `轮询任务失败：${error.message}`;
      stopPolling();
    }
  }, 2000);
}

async function createScan(event) {
  event.preventDefault();
  const payload = collectPayload();

  if (!payload.target) {
    refs.statusMessage.textContent = "请输入目标后再创建任务。";
    refs.targetInput.focus();
    return;
  }

  if (payload.scan_mode === "custom" && !payload.custom_ports) {
    refs.statusMessage.textContent = "端口模式为自定义时，必须填写自定义端口。";
    refs.customPortsInput.focus();
    return;
  }

  if (payload.vt_scan && !payload.vt_api_key) {
    refs.statusMessage.textContent = "启用 VirusTotal 时必须提供 API Key。";
    refs.vtApiKeyInput.focus();
    return;
  }

  refs.startScanBtn.disabled = true;
  refs.statusMessage.textContent = "正在创建扫描任务...";

  try {
    const response = await fetchJson(getApiScanUrl(), {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    setCurrentJob(
      {
        job_id: response.job_id,
        status: response.status,
        created_at: response.created_at,
        result: null,
      },
      "live"
    );
    refs.stopScanBtn.disabled = false;
    refs.statusMessage.textContent = "任务已创建，正在等待后端执行。";
    await refreshJobs();
    startPolling(response.job_id);
  } catch (error) {
    refs.statusMessage.textContent = `创建任务失败：${error.message}`;
  } finally {
    refs.startScanBtn.disabled = false;
  }
}

async function stopCurrentScan() {
  if (!state.currentJob?.job_id) return;
  refs.stopScanBtn.disabled = true;
  try {
    const payload = await fetchJson(`${getApiScanUrl().replace(/\/+$/, "")}/${state.currentJob.job_id}/stop`, {
      method: "POST",
    });
    refs.statusMessage.textContent = payload.message || "已发送停止请求。";
    state.currentStatus = payload.status || "stopping";
    syncView();
    startPolling(state.currentJob.job_id);
  } catch (error) {
    refs.statusMessage.textContent = `停止任务失败：${error.message}`;
    refs.stopScanBtn.disabled = false;
  }
}

function renderJobs(jobs) {
  if (!jobs.length) {
    refs.jobsList.className = "job-list empty-state";
    refs.jobsList.textContent = "还没有可展示的任务。";
    return;
  }

  refs.jobsList.className = "job-list";
  refs.jobsList.innerHTML = jobs
    .slice(0, 12)
    .map((job) => {
      const target = job.result?.target?.input || job.result?.meta?.target_input || "-";
      return `
        <article class="job-item">
          <div class="job-item__meta">
            <strong>${escapeHtml(target)}</strong>
            <span class="badge" data-tone="${escapeHtml(getStatusTone(job.status))}">${escapeHtml(job.status)}</span>
          </div>
          <div class="job-item__meta">
            <span class="muted">${escapeHtml(formatDateTime(job.created_at))}</span>
            <button type="button" data-job-id="${escapeHtml(job.job_id)}">查看详情</button>
          </div>
        </article>
      `;
    })
    .join("");

  refs.jobsList.querySelectorAll("[data-job-id]").forEach((button) => {
    button.addEventListener("click", async () => {
      try {
        const payload = await fetchJson(`${getApiScanUrl().replace(/\/+$/, "")}/${button.dataset.jobId}`);
        setCurrentJob(payload, "history");
        if (["queued", "running", "stopping"].includes(payload.status)) {
          startPolling(payload.job_id);
        } else {
          stopPolling();
        }
      } catch (error) {
        refs.statusMessage.textContent = `读取任务详情失败：${error.message}`;
      }
    });
  });
}

function renderNotice(message, tone = "neutral") {
  return `<div class="notice" data-tone="${escapeHtml(tone)}">${escapeHtml(message)}</div>`;
}

function renderChips(items) {
  const values = safeArray(items);
  if (!values.length) return renderNotice("暂无可展示条目。");
  return `<div class="pill-row">${values.map((item) => `<span class="chip">${escapeHtml(item)}</span>`).join("")}</div>`;
}

function renderKVTable(rows) {
  const filtered = rows.filter(([, value]) => value !== undefined && value !== null && value !== "");
  if (!filtered.length) return renderNotice("暂无字段可展示。");
  return `
    <table class="kv-table">
      <tbody>
        ${filtered
          .map(
            ([label, value]) => `
              <tr>
                <td>${escapeHtml(label)}</td>
                <td>${Array.isArray(value) ? escapeHtml(value.join(", ")) : escapeHtml(value)}</td>
              </tr>
            `
          )
          .join("")}
      </tbody>
    </table>
  `;
}

function renderTable(headers, rows) {
  if (!rows.length) return renderNotice("暂无数据。");
  return `
    <table class="data-table">
      <thead>
        <tr>${headers.map((item) => `<th>${escapeHtml(item)}</th>`).join("")}</tr>
      </thead>
      <tbody>
        ${rows
          .map(
            (row) => `
              <tr>${row.map((cell) => `<td>${escapeHtml(cell ?? "-")}</td>`).join("")}</tr>
            `
          )
          .join("")}
      </tbody>
    </table>
  `;
}

function card(title, eyebrow, badge, body, tone = "neutral") {
  return `
    <article class="data-card">
      <div class="data-card__head">
        <div>
          <p class="eyebrow">${escapeHtml(eyebrow)}</p>
          <h3>${escapeHtml(title)}</h3>
        </div>
        <span class="badge" data-tone="${escapeHtml(tone)}">${escapeHtml(badge)}</span>
      </div>
      <div class="data-card__body">${body}</div>
    </article>
  `;
}

function computeOpenPorts(report) {
  const ipScan = report?.ip_scan;
  if (!ipScan?.results) return 0;
  return Object.values(ipScan.results).reduce((sum, record) => {
    const tcp = Number(record?.tcp?.open_port_count || 0);
    const udp = Number(record?.udp?.open_port_count || 0);
    return sum + tcp + udp;
  }, 0);
}

function computeRiskCount(report) {
  const risk = report?.service_risk;
  const cveMatches = safeArray(risk?.cve_lookup?.matches);
  const cves = cveMatches.reduce((sum, row) => sum + safeArray(row?.cves).length, 0);
  const weak = Object.values(risk?.weak_checks?.per_ip || {}).reduce((sum, row) => {
    return sum + Number(row?.ftp_anonymous_check?.finding_count || 0) + Number(row?.tls_cipher_check?.finding_count || 0);
  }, 0);
  return cves + weak;
}

function updateHero() {
  const report = state.currentReport;
  const target =
    state.currentJob?.result?.target?.input ||
    report?.target?.input ||
    state.currentJob?.job_id ||
    refs.targetInput.value.trim() ||
    "尚未选择目标";

  refs.heroTarget.textContent = target;
  refs.heroStatus.textContent = state.currentStatus || "idle";
  refs.heroModules.textContent = String(countEnabledModules());
  refs.heroPorts.textContent = report ? String(computeOpenPorts(report)) : "-";
  refs.heroRisks.textContent = report ? String(computeRiskCount(report)) : "-";

  if (!report) {
    refs.heroSummary.textContent = "扫描尚未完成。该工作台会根据真实模块结果自动生成基础情报、网络资产、Web 枚举与风险视图。";
    return;
  }

  const techCount = safeArray(report.tech_stack?.detected_technologies).length;
  const endpointCount = safeArray(report.web_assets?.combined_endpoints).length;
  refs.heroSummary.textContent = `当前报告包含 ${techCount} 个技术指纹、${computeOpenPorts(report)} 个开放端口、${endpointCount} 个接口或路径线索。`;
}

function renderOverview(report) {
  if (!report) {
    refs.overviewPanel.innerHTML = renderNotice("还没有可展示的报告。可以创建任务，或导入本地 JSON 报告。");
    return;
  }

  const summaryRows = [
    ["目标输入", report.target?.input],
    ["规范化 URL", report.target?.normalized_url],
    ["扫描模式", report.meta?.scan_mode],
    ["端口引擎", report.meta?.requested_port_scanner],
    ["启用 VirusTotal", report.meta?.vt_scan_enabled ? "是" : "否"],
    ["启用 Web 枚举", report.meta?.web_asset_scan_enabled ? "是" : "否"],
    ["启用服务风险", report.meta?.service_risk_scan_enabled ? "是" : "否"],
  ];

  const moduleCards = [
    ["DNS", report.dns],
    ["WHOIS", report.whois],
    ["Tech Stack", report.tech_stack],
    ["VirusTotal", report.virustotal],
    ["Certificate Transparency", report.certificate_transparency],
    ["Passive DNS", report.passive_dns],
    ["ASN", report.asn_network],
    ["Web Assets", report.web_assets],
    ["IP Scan", report.ip_scan],
    ["Service Risk", report.service_risk],
  ]
    .map(([label, data]) => {
      const moduleState = getModuleState(data);
      return `
        <div class="metric-row">
          <span>${escapeHtml(label)}</span>
          <strong>${escapeHtml(moduleState.label)}</strong>
        </div>
      `;
    })
    .join("");

  refs.overviewPanel.innerHTML = `
    <div class="overview-grid">
      ${card(
        "报告摘要",
        "Report Summary",
        state.currentSource,
        `
          ${renderKVTable(summaryRows)}
          <div class="metric-list" style="margin-top:16px">
            <div class="metric-row"><span>开放端口总数</span><strong>${computeOpenPorts(report)}</strong></div>
            <div class="metric-row"><span>风险条目总数</span><strong>${computeRiskCount(report)}</strong></div>
            <div class="metric-row"><span>技术指纹</span><strong>${safeArray(report.tech_stack?.detected_technologies).length}</strong></div>
            <div class="metric-row"><span>Web 端点线索</span><strong>${safeArray(report.web_assets?.combined_endpoints).length}</strong></div>
          </div>
        `,
        "概览"
      )}
      ${card("模块执行情况", "Module State", "后端返回", moduleCards, "success")}
    </div>
  `;
}

function renderIdentity(report) {
  if (!report) {
    refs.identityPanel.innerHTML = renderNotice("暂无基础情报数据。");
    return;
  }

  const dnsRows = Object.entries(report.dns || {}).map(([type, value]) => [
    type,
    Array.isArray(value) ? value.join(", ") : value?.error || "-",
  ]);

  refs.identityPanel.innerHTML = `
    <div class="info-grid">
      ${card("目标解析", "Target", "核心实体", renderKVTable([
        ["输入", report.target?.input],
        ["域名", report.target?.domain],
        ["协议", report.target?.scheme],
        ["端口", report.target?.port],
        ["路径", report.target?.path],
        ["查询参数", report.target?.query],
        ["规范化 URL", report.target?.normalized_url],
      ]), "success")}
      ${card("WHOIS", "Ownership", getModuleState(report.whois).label, renderKVTable([
        ["域名", report.whois?.domain_name],
        ["注册商", report.whois?.registrar],
        ["WHOIS 服务器", report.whois?.whois_server],
        ["创建时间", report.whois?.creation_date],
        ["过期时间", report.whois?.expiration_date],
        ["更新时间", report.whois?.updated_date],
        ["DNSSEC", report.whois?.dnssec],
      ]), getModuleState(report.whois).tone)}
      ${card("DNS 记录", "DNS", "基础情报", renderTable(["类型", "值 / 状态"], dnsRows), "success")}
      ${card("技术指纹", "Tech Detection", getModuleState(report.tech_stack).label, `
        ${renderKVTable([
          ["请求 URL", report.tech_stack?.url],
          ["状态码", report.tech_stack?.status_code],
        ])}
        <div style="margin-top:16px">${renderChips(report.tech_stack?.detected_technologies)}</div>
      `, getModuleState(report.tech_stack).tone)}
      ${card("VirusTotal", "Threat Intel", getModuleState(report.virustotal).label, renderVirusTotal(report.virustotal), getModuleState(report.virustotal).tone)}
    </div>
  `;
}

function renderVirusTotal(vt) {
  if (!vt) return renderNotice("未返回 VirusTotal 结果。");
  const stateInfo = getModuleState(vt);
  if (stateInfo.label !== "完成") return renderNotice(stateInfo.detail, stateInfo.tone);

  const domainStats = vt.domain?.last_analysis_stats || {};
  const urlStats = vt.url?.last_analysis_stats || {};
  return `
    ${renderKVTable([
      ["Domain reputation", vt.domain?.reputation],
      ["URL reputation", vt.url?.reputation],
      ["Domain malicious", domainStats.malicious ?? 0],
      ["URL malicious", urlStats.malicious ?? 0],
    ])}
    <div style="margin-top:16px">
      ${renderChips(Object.entries(vt.domain?.categories || {}).map(([vendor, category]) => `${vendor}: ${category}`))}
    </div>
  `;
}

function renderInfrastructure(report) {
  if (!report) {
    refs.infrastructurePanel.innerHTML = renderNotice("暂无网络与资产数据。");
    return;
  }

  refs.infrastructurePanel.innerHTML = `
    <div class="panel-grid panel-grid--two">
      ${card("证书透明度", "CT Logs", getModuleState(report.certificate_transparency).label, renderCt(report.certificate_transparency), getModuleState(report.certificate_transparency).tone)}
      ${card("被动 DNS", "Passive DNS", getModuleState(report.passive_dns).label, renderPassiveDns(report.passive_dns), getModuleState(report.passive_dns).tone)}
      ${card("ASN 与网络扩展", "ASN", getModuleState(report.asn_network).label, renderAsn(report.asn_network), getModuleState(report.asn_network).tone)}
      ${card("IP / Port 扫描", "IP Scan", getModuleState(report.ip_scan).label, renderIpScan(report.ip_scan), getModuleState(report.ip_scan).tone)}
    </div>
  `;
}

function renderCt(module) {
  const moduleState = getModuleState(module);
  if (moduleState.label !== "完成") return renderNotice(moduleState.detail, moduleState.tone);
  return `
    ${renderKVTable([
      ["数据源", module.source],
      ["总记录数", module.total_records],
      ["发现子域名", safeArray(module.discovered_subdomains).length],
    ])}
    <div style="margin-top:16px">${renderChips(safeArray(module.discovered_subdomains).slice(0, 24))}</div>
  `;
}

function renderPassiveDns(module) {
  const moduleState = getModuleState(module);
  if (moduleState.label !== "完成") return renderNotice(moduleState.detail, moduleState.tone);
  return `
    ${renderKVTable([
      ["解析 IP 数", safeArray(module.resolved_ips).length],
      ["历史子域名数", safeArray(module.historical_subdomains).length],
      ["来源数", Object.keys(module.sources || {}).length],
    ])}
    <div style="margin-top:16px">${renderChips(safeArray(module.resolved_ips).slice(0, 16))}</div>
    <div style="margin-top:16px">${renderChips(safeArray(module.historical_subdomains).slice(0, 16))}</div>
  `;
}

function renderAsn(module) {
  const moduleState = getModuleState(module);
  if (moduleState.label !== "完成") return renderNotice(moduleState.detail, moduleState.tone);
  return renderTable(
    ["IP", "ASN", "名称", "Prefix", "国家"],
    safeArray(module.records).map((row) => [row.ip, row.asn, row.asn_name, row.prefix, row.country_code])
  );
}

function renderIpScan(module) {
  const moduleState = getModuleState(module);
  if (moduleState.label !== "完成" && moduleState.label !== "已跳过") return renderNotice(moduleState.detail, moduleState.tone);

  const rows = [];
  Object.entries(module?.results || {}).forEach(([ip, record]) => {
    safeArray(record?.tcp?.open_ports).forEach((row) => rows.push([ip, "tcp", row.port, row.service, row.state, row.banner]));
    safeArray(record?.udp?.open_ports).forEach((row) => rows.push([ip, "udp", row.port, row.service, row.state, row.banner]));
  });

  return `
    ${renderKVTable([
      ["扫描是否执行", module?.scan_performed ? "是" : "否"],
      ["扫描引擎", module?.scanner],
      ["请求引擎", module?.requested_scanner],
      ["端口范围", module?.port_range],
      ["目标 IP 数", safeArray(module?.targets).length],
      ["跳过原因", module?.skip_reason],
    ])}
    <div style="margin-top:16px">${renderTable(["IP", "协议", "端口", "服务", "状态", "Banner"], rows)}</div>
  `;
}

function renderWeb(report) {
  if (!report) {
    refs.webPanel.innerHTML = renderNotice("暂无 Web 枚举数据。");
    return;
  }

  const web = report.web_assets;
  refs.webPanel.innerHTML = `
    <div class="panel-grid panel-grid--two">
      ${card("Web 枚举总览", "Web Assets", getModuleState(web).label, renderWebOverview(web), getModuleState(web).tone)}
      ${card("站内爬取", "Crawler", getModuleState(web?.crawler).label, renderCrawler(web?.crawler), getModuleState(web?.crawler).tone)}
      ${card("JS 提取", "JS Extraction", getModuleState(web?.js_extraction).label, renderJsExtraction(web?.js_extraction), getModuleState(web?.js_extraction).tone)}
      ${card("目录探测", "Directory Probe", getModuleState(web?.directory_probe).label, renderDirectoryProbe(web?.directory_probe), getModuleState(web?.directory_probe).tone)}
      ${card("敏感路径", "Sensitive Paths", getModuleState(web?.sensitive_paths).label, renderSensitivePaths(web?.sensitive_paths), getModuleState(web?.sensitive_paths).tone)}
    </div>
  `;
}

function renderWebOverview(module) {
  const moduleState = getModuleState(module);
  if (moduleState.label !== "完成") return renderNotice(moduleState.detail, moduleState.tone);
  return `
    ${renderKVTable([
      ["基础 URL", module.base_url],
      ["组合端点数", safeArray(module.combined_endpoints).length],
      ["敏感路径数", module.sensitive_paths?.count],
    ])}
    <div style="margin-top:16px">${renderChips(safeArray(module.combined_endpoints).slice(0, 20))}</div>
  `;
}

function renderCrawler(module) {
  const moduleState = getModuleState(module);
  if (moduleState.label !== "完成") return renderNotice(moduleState.detail, moduleState.tone);
  return `
    ${renderKVTable([
      ["页面数", module.page_count],
      ["JS 文件", safeArray(module.js_files).length],
      ["发现端点", safeArray(module.discovered_endpoints).length],
    ])}
    <div style="margin-top:16px">${renderChips(safeArray(module.pages).slice(0, 12).map((row) => `${row.status_code || "ERR"} ${row.url}`))}</div>
  `;
}

function renderJsExtraction(module) {
  const moduleState = getModuleState(module);
  if (moduleState.label !== "完成") return renderNotice(moduleState.detail, moduleState.tone);
  return `
    ${renderKVTable([
      ["端点数", safeArray(module.endpoints).length],
      ["敏感路径数", safeArray(module.sensitive_paths).length],
      ["样本数", safeArray(module.samples).length],
    ])}
    <div style="margin-top:16px">${renderChips(safeArray(module.endpoints).slice(0, 20))}</div>
  `;
}

function renderDirectoryProbe(module) {
  const moduleState = getModuleState(module);
  if (moduleState.label !== "完成") return renderNotice(moduleState.detail, moduleState.tone);
  return renderTable(
    ["URL", "状态码", "长度", "内容类型"],
    safeArray(module.hits).slice(0, 40).map((row) => [row.url, row.status_code, row.length, row.content_type || row.redirectlocation])
  );
}

function renderSensitivePaths(module) {
  const moduleState = getModuleState(module);
  if (moduleState.label !== "完成") return renderNotice(moduleState.detail, moduleState.tone);
  return renderChips(safeArray(module.items).slice(0, 30));
}

function renderRisk(report) {
  if (!report) {
    refs.riskPanel.innerHTML = renderNotice("暂无风险分析数据。");
    return;
  }

  const risk = report.service_risk;
  refs.riskPanel.innerHTML = `
    <div class="panel-grid panel-grid--two">
      ${card("服务清单", "Service Inventory", getModuleState(risk).label, renderServiceInventory(risk), getModuleState(risk).tone)}
      ${card("CVE 关联", "CVE Lookup", getModuleState(risk?.cve_lookup).label, renderCveLookup(risk?.cve_lookup), getModuleState(risk?.cve_lookup).tone)}
      ${card("弱配置检查", "Weak Checks", getModuleState(risk?.weak_checks).label, renderWeakChecks(risk?.weak_checks), getModuleState(risk?.weak_checks).tone)}
    </div>
  `;
}

function renderServiceInventory(module) {
  const moduleState = getModuleState(module);
  if (moduleState.label !== "完成") return renderNotice(moduleState.detail, moduleState.tone);
  return renderTable(
    ["IP", "端口", "协议", "服务", "状态", "CPE"],
    safeArray(module.services).slice(0, 60).map((row) => [row.ip, row.port, row.protocol, row.service, row.state, safeArray(row.cpe).join(", ")])
  );
}

function renderCveLookup(module) {
  const moduleState = getModuleState(module);
  if (module?.enabled === false) return renderNotice(module.message || "CVE 关联未启用。");
  const rows = [];
  safeArray(module?.matches).forEach((match) => {
    safeArray(match.cves).forEach((cve) => rows.push([match.cpe, cve.id, cve.severity, cve.base_score, cve.published]));
  });
  return `
    ${renderKVTable([
      ["CPE 数量", module?.cpe_count],
      ["匹配项", rows.length],
      ["说明", module?.message],
    ])}
    <div style="margin-top:16px">${renderTable(["CPE", "CVE", "Severity", "Score", "Published"], rows.slice(0, 50))}</div>
  `;
}

function renderWeakChecks(module) {
  if (module?.enabled === false) return renderNotice(module.message || "弱配置检查未启用。");
  const rows = [];
  Object.entries(module?.per_ip || {}).forEach(([ip, row]) => {
    safeArray(row?.ftp_anonymous_check?.findings).forEach((finding) => rows.push([ip, "ftp-anon", finding.port, finding.output]));
    safeArray(row?.tls_cipher_check?.findings).forEach((finding) => rows.push([ip, "ssl-enum-ciphers", finding.port, finding.output]));
  });
  return `
    ${renderKVTable([
      ["检查 IP 数", Object.keys(module?.per_ip || {}).length],
      ["发现数", rows.length],
      ["说明", module?.message],
    ])}
    <div style="margin-top:16px">${renderTable(["IP", "检查项", "端口", "输出"], rows.slice(0, 30))}</div>
  `;
}

function syncStatusPanel() {
  const report = state.currentReport;
  const job = state.currentJob;
  const status = job?.status || state.currentStatus || "idle";
  const tone = getStatusTone(status);
  const progress = getProgressPercent(status, report);

  refs.statusChip.textContent = status;
  refs.statusChip.className = "status-chip";
  refs.statusChip.dataset.tone = tone;
  refs.jobIdChip.textContent = job?.job_id ? `Job ${job.job_id.slice(0, 8)}` : "No Job";
  refs.currentTargetValue.textContent = report?.target?.input || refs.targetInput.value.trim() || "-";
  refs.createdAtValue.textContent = formatDateTime(job?.created_at || report?.meta?.generated_at);
  refs.runtimeValue.textContent = formatRuntime(job);
  refs.sourceValue.textContent = state.currentSource;
  refs.progressLabel.textContent = status === "completed" ? "报告已完成" : status === "failed" ? "任务失败" : status === "canceled" ? "任务已取消" : "任务进行中";
  refs.progressValue.textContent = `${progress}%`;
  refs.progressBar.style.width = `${progress}%`;
  refs.stopScanBtn.disabled = !job || !["queued", "running", "stopping"].includes(status);

  if (job?.error) {
    refs.statusMessage.textContent = `任务失败：${job.error}`;
  } else if (report?.error) {
    refs.statusMessage.textContent = `报告错误：${report.error}`;
  } else if (report?.canceled) {
    refs.statusMessage.textContent = report.message || "任务已取消。";
  } else if (job?.result?.meta) {
    refs.statusMessage.textContent = `最后生成时间：${formatDateTime(job.result.meta.generated_at)}。`;
  }
}

function syncView() {
  updateHero();
  syncStatusPanel();
  renderOverview(state.currentReport);
  renderIdentity(state.currentReport);
  renderInfrastructure(state.currentReport);
  renderWeb(state.currentReport);
  renderRisk(state.currentReport);
  refs.rawJsonView.textContent = state.currentReport ? JSON.stringify(state.currentReport, null, 2) : "暂无数据";
}

function handleReportFile(event) {
  const file = event.target.files?.[0];
  if (!file) return;
  const reader = new FileReader();
  reader.onload = () => {
    try {
      const report = JSON.parse(String(reader.result || "{}"));
      setCurrentReport(report, "imported-file");
      refs.importHint.textContent = `已导入 ${file.name}`;
      stopPolling();
    } catch (error) {
      refs.importHint.textContent = `解析文件失败：${error.message}`;
    }
  };
  reader.readAsText(file, "utf-8");
}

async function loadSampleReport() {
  const candidates = ["../report.json", "/report.json", "./report.json"];
  for (const url of candidates) {
    try {
      const response = await fetch(url);
      if (!response.ok) continue;
      const report = await response.json();
      setCurrentReport(report, "sample-report");
      refs.importHint.textContent = `已载入样例报告：${url}`;
      stopPolling();
      return;
    } catch (_error) {
      continue;
    }
  }
  refs.importHint.textContent = "未能加载样例报告，请确认 `report.json` 可被当前静态服务访问。";
}

function syncFormDependencies() {
  const customMode = refs.scanModeInput.value === "custom";
  refs.customPortsField.hidden = !customMode;
  refs.asnExpandInput.disabled = !refs.asnScanInput.checked;
  refs.webCrawlerInput.disabled = !refs.webAssetScanInput.checked;
  refs.webJsExtractInput.disabled = !refs.webAssetScanInput.checked;
  refs.webSensitiveInput.disabled = !refs.webAssetScanInput.checked;
  refs.webDirScanInput.disabled = !refs.webAssetScanInput.checked;
  refs.webDirFfufInput.disabled = !refs.webAssetScanInput.checked || !refs.webDirScanInput.checked;
  refs.cveLookupInput.disabled = !refs.serviceRiskInput.checked;
  refs.weakChecksInput.disabled = !refs.serviceRiskInput.checked;
  refs.moduleCount.textContent = String(countEnabledModules());
  refs.heroModules.textContent = String(countEnabledModules());
}

function bindTabs() {
  refs.tabs.forEach((tab) => {
    tab.addEventListener("click", () => {
      state.activeTab = tab.dataset.tab;
      refs.tabs.forEach((item) => item.classList.toggle("is-active", item === tab));
      refs.panels.forEach((panel) => panel.classList.toggle("is-active", panel.dataset.panel === state.activeTab));
    });
  });
}

function init() {
  refs.apiUrlInput.value = inferDefaultApiUrl();
  bindTabs();
  syncFormDependencies();
  syncView();

  refs.scanForm.addEventListener("submit", createScan);
  refs.stopScanBtn.addEventListener("click", stopCurrentScan);
  refs.reportFileInput.addEventListener("change", handleReportFile);
  refs.loadSampleBtn.addEventListener("click", loadSampleReport);
  refs.refreshJobsBtn.addEventListener("click", refreshJobs);

  [
    refs.scanModeInput,
    refs.tcpScanInput,
    refs.udpScanInput,
    refs.allowPrivateIpInput,
    refs.vtScanInput,
    refs.ctScanInput,
    refs.passiveDnsInput,
    refs.asnScanInput,
    refs.asnExpandInput,
    refs.webAssetScanInput,
    refs.webCrawlerInput,
    refs.webJsExtractInput,
    refs.webSensitiveInput,
    refs.webDirScanInput,
    refs.webDirFfufInput,
    refs.serviceRiskInput,
    refs.cveLookupInput,
    refs.weakChecksInput,
  ].forEach((input) => input.addEventListener("change", syncFormDependencies));

  refreshHealth();
  refreshJobs();
  state.healthTimer = window.setInterval(refreshHealth, 15000);
  state.jobsTimer = window.setInterval(refreshJobs, 20000);
  window.setInterval(() => {
    if (state.currentJob && ["queued", "running", "stopping"].includes(state.currentStatus)) {
      syncStatusPanel();
    }
  }, 1000);
}

init();
