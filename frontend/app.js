const terminal = document.getElementById("terminal");
const summary = document.getElementById("summary");
const rawOutput = document.getElementById("rawOutput");
const form = document.getElementById("scanForm");
const fileInput = document.getElementById("reportFile");
const reportDropzone = document.getElementById("reportDropzone");
const reportFileMeta = document.getElementById("reportFileMeta");
const reportFileName = document.getElementById("reportFileName");
const reportFileSize = document.getElementById("reportFileSize");
const reportFileType = document.getElementById("reportFileType");
const stopBtn = document.getElementById("stopBtn");
const downloadBtn = document.getElementById("downloadBtn");
const clearBtn = document.getElementById("clearBtn");
const progressText = document.getElementById("progressText");
const progressBar = document.getElementById("progressBar");
const apiInput = document.getElementById("apiUrl");
const targetInput = document.getElementById("target");
const vtScanInput = document.getElementById("vtScan");
const vtScanStateText = document.getElementById("vtScanStateText");
const vtOptions = document.getElementById("vtOptions");
const vtApiKeyInput = document.getElementById("vtApiKey");
const customPortsWrap = document.getElementById("customPortsWrap");
const customPortsInput = document.getElementById("customPorts");
const portScannerInput = document.getElementById("portScanner");
const scanModeRadios = document.querySelectorAll('input[name="scanMode"]');
const enablePortScan = document.getElementById("enablePortScan");
const portScanOptions = document.getElementById("portScanOptions");
const portScanStateText = document.getElementById("portScanStateText");
const ctScanInput = document.getElementById("ctScan");
const ctScanStateText = document.getElementById("ctScanStateText");
const passiveDnsScanInput = document.getElementById("passiveDnsScan");
const passiveDnsScanStateText = document.getElementById("passiveDnsScanStateText");
const asnScanInput = document.getElementById("asnScan");
const asnScanStateText = document.getElementById("asnScanStateText");
const webAssetScanInput = document.getElementById("webAssetScan");
const webAssetScanStateText = document.getElementById("webAssetScanStateText");
const serviceRiskScanInput = document.getElementById("serviceRiskScan");
const serviceRiskScanStateText = document.getElementById("serviceRiskScanStateText");
const allowPrivateIpInput = document.getElementById("allowPrivateIp");
const allowPrivateIpStateText = document.getElementById("allowPrivateIpStateText");

const asnOptions = document.getElementById("asnOptions");
const webAssetOptions = document.getElementById("webAssetOptions");
const serviceRiskOptions = document.getElementById("serviceRiskOptions");
const networkOptions = document.getElementById("networkOptions");
const moduleConfigStage = document.getElementById("moduleConfigStage");
const moduleConfigEmpty = document.getElementById("moduleConfigEmpty");

const asnExpandCSegmentInput = document.getElementById("asnExpandCSegment");
const webCrawlerInput = document.getElementById("webCrawler");
const webJsExtractInput = document.getElementById("webJsExtract");
const webSensitivePathExtractInput = document.getElementById("webSensitivePathExtract");
const webDirScanInput = document.getElementById("webDirScan");
const webDirUseFfufInput = document.getElementById("webDirUseFfuf");
const cveLookupInput = document.getElementById("cveLookup");
const weakNmapChecksInput = document.getElementById("weakNmapChecks");
const cidrTargetsInput = document.getElementById("cidrTargets");

const hudThreat = document.getElementById("hudThreat");
const hudSignal = document.getElementById("hudSignal");
const hudClock = document.getElementById("hudClock");
const hudPacketFlow = document.getElementById("hudPacketFlow");
const hudLatency = document.getElementById("hudLatency");
const hudModuleActive = document.getElementById("hudModuleActive");
const hudTaskState = document.getElementById("hudTaskState");
const hudTargetLock = document.getElementById("hudTargetLock");
const statusTarget = document.getElementById("statusTarget");
const missionTarget = document.getElementById("missionTarget");
const missionFocus = document.getElementById("missionFocus");
const missionMode = document.getElementById("missionMode");
const missionRisk = document.getElementById("missionRisk");
const coreTargetEcho = document.getElementById("coreTargetEcho");
const coreStatusLine = document.getElementById("coreStatusLine");
const coreSignalLane = document.getElementById("coreSignalLane");
const coreStateVector = document.getElementById("coreStateVector");
const historyList = document.getElementById("historyList");
const liveEvents = document.getElementById("liveEvents");
const moduleStatusList = document.getElementById("moduleStatusList");
const portsOutput = document.getElementById("portsOutput");
const techOutput = document.getElementById("techOutput");
const exportSource = document.getElementById("exportSource");
const exportTarget = document.getElementById("exportTarget");
const resultStatus = document.getElementById("resultStatus");
const resultOpenPorts = document.getElementById("resultOpenPorts");
const resultTechCount = document.getElementById("resultTechCount");
const resultSourceBadge = document.getElementById("resultSourceBadge");
const dockTabs = Array.from(document.querySelectorAll(".dock-tab"));
const dockPanels = Array.from(document.querySelectorAll(".dock-panel"));

const COMMON_PORT_RANGE =
  "21,22,23,25,53,80,110,111,135,139,143,389,443,445,465,587,993,995,1433,1521,1723,1883,1900,2049,2375,2376,3306,3389,5432,5900,6379,7001,8000,8080,8081,8443,8888,9200,11211,27017";
const HISTORY_KEY = "tokihane-scan-history";

let currentJobId = null;
let pollTimer = null;
let latestReport = null;
let latestReportSource = null;
let isRunning = false;
let progressValue = 0;
let hudRuntimeTick = 0;
let recentHistory = [];

const moduleToggleInputs = [
  vtScanInput,
  enablePortScan,
  ctScanInput,
  passiveDnsScanInput,
  asnScanInput,
  webAssetScanInput,
  serviceRiskScanInput,
  allowPrivateIpInput,
].filter(Boolean);

const optionPanels = [vtOptions, portScanOptions, asnOptions, webAssetOptions, serviceRiskOptions, networkOptions].filter(Boolean);
const moduleStatusDefinitions = [
  { input: vtScanInput, label: "VirusTotal" },
  { input: enablePortScan, label: "Port Scan" },
  { input: ctScanInput, label: "CT Logs" },
  { input: passiveDnsScanInput, label: "Passive DNS" },
  { input: asnScanInput, label: "ASN Expand" },
  { input: webAssetScanInput, label: "Web Assets" },
  { input: serviceRiskScanInput, label: "Service Risk" },
  { input: allowPrivateIpInput, label: "Private IP" },
].filter((item) => item.input);

function setNodeText(node, text, fallback = "N/A") {
  if (!node) {
    return;
  }
  const value = String(text ?? "").trim();
  node.textContent = value || fallback;
}

function loadHistory() {
  try {
    const raw = window.localStorage.getItem(HISTORY_KEY);
    if (!raw) {
      return [];
    }
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed.slice(0, 8) : [];
  } catch (_error) {
    return [];
  }
}

function saveHistory() {
  try {
    window.localStorage.setItem(HISTORY_KEY, JSON.stringify(recentHistory.slice(0, 8)));
  } catch (_error) {}
}

function formatHistoryTime(timestamp) {
  if (!timestamp) {
    return "just now";
  }
  const date = new Date(timestamp);
  if (Number.isNaN(date.getTime())) {
    return "just now";
  }
  return date.toLocaleString("zh-CN", {
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
  });
}

function renderHistory() {
  if (!historyList) {
    return;
  }

  historyList.innerHTML = "";
  if (!recentHistory.length) {
    const empty = document.createElement("div");
    empty.className = "history-item history-item--empty";
    empty.innerHTML = "<strong>No recent activity yet.</strong><span>Completed scans and imported reports will appear here.</span>";
    historyList.appendChild(empty);
    return;
  }

  recentHistory.forEach((entry) => {
    const item = document.createElement("div");
    item.className = "history-item";

    const title = document.createElement("strong");
    title.textContent = entry.title || "Untitled";

    const detail = document.createElement("span");
    detail.textContent = entry.detail || "Recent workspace event";

    const meta = document.createElement("div");
    meta.className = "history-item__meta";

    const time = document.createElement("span");
    time.textContent = formatHistoryTime(entry.timestamp);

    const status = document.createElement("span");
    status.className = "history-item__status";
    status.textContent = (entry.status || "READY").toUpperCase();
    status.dataset.state = (entry.status || "ready").toLowerCase();

    meta.append(time, status);
    item.append(title, detail, meta);
    historyList.appendChild(item);
  });
}

function pushHistoryEntry({ title, detail, status }) {
  recentHistory = [
    {
      title: title || "Workspace Event",
      detail: detail || "Recent workspace event",
      status: (status || "ready").toLowerCase(),
      timestamp: Date.now(),
    },
    ...recentHistory,
  ].slice(0, 8);
  saveHistory();
  renderHistory();
}

function formatFileSize(bytes) {
  const size = Number(bytes || 0);
  if (!Number.isFinite(size) || size <= 0) {
    return "Ready for import";
  }
  if (size >= 1024 * 1024) {
    return `${(size / (1024 * 1024)).toFixed(1)} MB`;
  }
  if (size >= 1024) {
    return `${Math.round(size / 1024)} KB`;
  }
  return `${size} B`;
}

function setReportFileState(file, detailText) {
  if (reportDropzone) {
    reportDropzone.classList.toggle("is-has-file", !!file);
  }
  if (reportFileMeta) {
    reportFileMeta.dataset.state = file ? "selected" : "idle";
  }
  setNodeText(reportFileName, file?.name || "No file selected", "No file selected");
  setNodeText(reportFileSize, detailText || formatFileSize(file?.size), "Ready for import");
  setNodeText(reportFileType, file?.type || "JSON report", "JSON report");
}

function resetReportFileState() {
  setReportFileState(null, "Ready for import");
}

function countOpenPorts(data) {
  const ipScan = data?.ip_scan || {};
  let total = 0;
  Object.values(ipScan.results || {}).forEach((result) => {
    const tcp = Array.isArray(result?.tcp?.open_ports) ? result.tcp.open_ports.length : Number(result?.tcp?.open_port_count || 0);
    const udp = Array.isArray(result?.udp?.open_ports) ? result.udp.open_ports.length : Number(result?.udp?.open_port_count || 0);
    total += tcp + udp;
  });
  return total;
}

function countTechSignals(data) {
  const tech = Array.isArray(data?.tech_stack?.detected_technologies) ? data.tech_stack.detected_technologies.length : 0;
  const cves = Array.isArray(data?.service_risk?.cve_lookup?.matches) ? data.service_risk.cve_lookup.matches.length : 0;
  const weak = Array.isArray(data?.service_risk?.weak_checks?.findings) ? data.service_risk.weak_checks.findings.length : 0;
  return tech + cves + weak;
}

function updateResultOverview(data) {
  setNodeText(resultOpenPorts, data ? String(countOpenPorts(data)) : "0", "0");
  setNodeText(resultTechCount, data ? String(countTechSignals(data)) : "0", "0");
  setNodeText(resultSourceBadge, latestReport ? String(latestReportSource || "scan").toUpperCase() : "NO DATA", "NO DATA");
}

function getTargetLabel() {
  return (
    targetInput?.value?.trim() ||
    latestReport?.meta?.target_input ||
    latestReport?.target?.input ||
    latestReport?.target?.domain ||
    latestReport?.target?.normalized_url ||
    ""
  );
}

function getTargetDisplayValue() {
  return getTargetLabel() || "NO TARGET";
}

function getCoreTargetValue() {
  return getTargetLabel() || "NO TARGET";
}

function getSelectedScanModeLabel() {
  if (!isPortScanEnabled()) {
    return "INTEL ONLY";
  }
  const mode = getSelectedScanMode();
  if (mode === "full") {
    return "FULL";
  }
  if (mode === "custom") {
    return "CUSTOM";
  }
  return "COMMON";
}

function updateMissionMode() {
  setNodeText(missionMode, getSelectedScanModeLabel(), "INTEL ONLY");
}

function updateMissionFocus() {
  const activeCount = moduleToggleInputs.reduce((count, input) => {
    return input?.checked ? count + 1 : count;
  }, 0);

  let focus = "Ready to Scan";
  if (isRunning) {
    focus = activeCount > 4 ? "Deep Scan Running" : "Target Scan Running";
  } else if (latestReport) {
    focus = latestReportSource === "file" ? "Report Loaded" : "Scan Complete";
  } else if (activeCount > 0) {
    focus = activeCount > 4 ? "Modules Armed" : "Scan Plan Ready";
  }

  setNodeText(missionFocus, focus, "Ready to Scan");
  setNodeText(coreSignalLane, isRunning ? "RUNNING" : activeCount > 0 ? "READY" : "IDLE", "IDLE");
}

function updateCoreStatusLine(message) {
  if (message) {
    setNodeText(coreStatusLine, message, "Scan engine idle. Enter a target to begin.");
    return;
  }

  const target = getTargetLabel();
  if (isRunning && target) {
    setNodeText(coreStatusLine, `Scanning ${target} for assets, ports, and risk signals.`, "Scan engine idle. Enter a target to begin.");
    return;
  }
  if (latestReport && target) {
    setNodeText(coreStatusLine, `Latest scan results loaded for ${target}.`, "Scan engine idle. Enter a target to begin.");
    return;
  }
  setNodeText(coreStatusLine, "Scan engine idle. Enter a target to begin.", "Scan engine idle. Enter a target to begin.");
}

function updateExportMeta() {
  setNodeText(exportSource, latestReport ? String(latestReportSource || "scan").toUpperCase() : "NO DATA", "NO DATA");
  setNodeText(exportTarget, getTargetDisplayValue(), "NO TARGET");
  updateResultOverview(latestReport);
}

function appendDockRows(container, rows, emptyText) {
  if (!container) {
    return;
  }
  container.innerHTML = "";
  const list = Array.isArray(rows) ? rows.filter(Boolean) : [];
  const source = list.length ? list : [emptyText];
  source.forEach((text) => {
    const item = document.createElement("div");
    item.className = "summary-item";
    item.textContent = text;
    container.appendChild(item);
  });
}

function renderModuleStatusList() {
  if (!moduleStatusList) {
    return;
  }
  moduleStatusList.innerHTML = "";
  moduleStatusDefinitions.forEach(({ input, label }) => {
    const row = document.createElement("div");
    row.className = "module-status";

    const name = document.createElement("span");
    name.textContent = label;

    const state = document.createElement("strong");
    const enabled = !!input?.checked;
    state.textContent = enabled ? "ON" : "OFF";
    state.dataset.state = enabled ? "on" : "off";

    row.append(name, state);
    moduleStatusList.appendChild(row);
  });
}

function pushLiveEvent(text, level = "info") {
  if (!liveEvents || !text) {
    return;
  }

  const line = document.createElement("div");
  const stamp = new Date().toLocaleTimeString("zh-CN", { hour12: false });
  line.className = "event-line";
  line.textContent = `[${stamp}] ${text}`;
  if (level === "error") {
    line.classList.add("is-danger");
  } else if (level === "ok") {
    line.classList.add("is-online");
  } else {
    line.classList.add("event-line--muted");
  }

  const placeholder = liveEvents.querySelector(".event-line--muted");
  if (placeholder && liveEvents.children.length === 1) {
    placeholder.remove();
  }

  liveEvents.prepend(line);
  while (liveEvents.children.length > 6) {
    liveEvents.removeChild(liveEvents.lastElementChild);
  }
}

function initDockTabs() {
  if (!dockTabs.length || !dockPanels.length) {
    return;
  }

  const activate = (tabName) => {
    dockTabs.forEach((tab) => {
      const active = tab.dataset.tab === tabName;
      tab.classList.toggle("is-active", active);
      tab.setAttribute("aria-selected", String(active));
    });

    dockPanels.forEach((panel) => {
      const active = panel.dataset.panel === tabName;
      panel.classList.toggle("is-active", active);
      panel.hidden = !active;
    });
  };

  dockTabs.forEach((tab) => {
    tab.addEventListener("click", () => {
      activate(tab.dataset.tab || "assets");
    });
  });
}

function setHudTaskState(stateText) {
  if (!hudTaskState) {
    return;
  }
  const nextState = stateText || "IDLE";
  hudTaskState.textContent = nextState;
  setNodeText(coreStateVector, nextState, "IDLE");
  setNodeText(resultStatus, nextState, "STANDBY");
  updateMissionFocus();
  updateCoreStatusLine();
}

function updateHudClock() {
  if (!hudClock) {
    return;
  }
  const now = new Date();
  hudClock.textContent = now.toLocaleTimeString("zh-CN", { hour12: false });
}

function updateHudSignal() {
  if (!hudSignal) {
    return;
  }
  const base = isRunning ? 95 : 98;
  const jitter = Math.floor(Math.random() * (isRunning ? 8 : 4));
  const value = Math.max(84, Math.min(100, base - jitter));
  hudSignal.textContent = `${value}%`;
}

function setHudThreat(level) {
  if (!hudThreat) {
    return;
  }
  const nextLevel = level || "LOW";
  hudThreat.textContent = nextLevel;
  setNodeText(missionRisk, nextLevel, "LOW");
}

function updateHudThreatFromReport(data) {
  const stats = data?.virustotal?.domain?.last_analysis_stats;
  if (!stats) {
    setHudThreat(isRunning ? "MEDIUM" : "LOW");
    return;
  }
  const malicious = Number(stats.malicious || 0);
  const suspicious = Number(stats.suspicious || 0);
  if (malicious > 0) {
    setHudThreat("CRITICAL");
  } else if (suspicious > 0) {
    setHudThreat("ELEVATED");
  } else {
    setHudThreat("LOW");
  }
}

function updateHudTargetLock() {
  setNodeText(hudTargetLock, getTargetLabel(), "ENTER TARGET");
  setNodeText(statusTarget, getTargetDisplayValue(), "NO TARGET");
  setNodeText(missionTarget, getTargetDisplayValue(), "NO TARGET");
  setNodeText(coreTargetEcho, getCoreTargetValue(), "NO TARGET");
  updateExportMeta();
  updateCoreStatusLine();
}

function updateModuleActiveCount() {
  if (!hudModuleActive) {
    return;
  }
  const activeCount = moduleToggleInputs.reduce((count, input) => {
    return input?.checked ? count + 1 : count;
  }, 0);
  hudModuleActive.textContent = String(activeCount);
  renderModuleStatusList();
  updateMissionMode();
  updateMissionFocus();
}

function syncModuleConfigStage() {
  const hasVisiblePanel = optionPanels.some((panel) => panel.classList.contains("is-open"));
  if (moduleConfigStage) {
    moduleConfigStage.classList.toggle("is-active", hasVisiblePanel);
  }
  if (moduleConfigEmpty) {
    moduleConfigEmpty.setAttribute("aria-hidden", String(hasVisiblePanel));
  }
}

function updateHudMetrics() {
  if (isRunning) {
    hudRuntimeTick += 1;
    if (hudPacketFlow) {
      const flow = 140 + ((hudRuntimeTick * 37) % 580);
      hudPacketFlow.textContent = `${flow} kb/s`;
    }
    if (hudLatency) {
      const latency = 12 + ((hudRuntimeTick * 11) % 56);
      hudLatency.textContent = `${latency} ms`;
    }
    return;
  }

  if (hudPacketFlow) {
    hudPacketFlow.textContent = "0 kb/s";
  }
  if (hudLatency) {
    hudLatency.textContent = "-- ms";
  }
}

function initHudRuntime() {
  updateHudClock();
  updateHudSignal();
  updateHudTargetLock();
  updateModuleActiveCount();
  updateHudMetrics();
  updateMissionMode();
  updateMissionFocus();
  updateExportMeta();
  renderModuleStatusList();

  setInterval(() => {
    updateHudClock();
    updateHudSignal();
    updateHudMetrics();
  }, 1000);
}

function shouldUsePerfLite() {
  const reduceMotion = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  const cpuCores = Number(navigator.hardwareConcurrency || 8);
  const memoryGb = Number(navigator.deviceMemory || 8);
  return reduceMotion || cpuCores <= 4 || memoryGb <= 4;
}

function applyPerformancePreset() {
  const perfLite = shouldUsePerfLite();
  document.documentElement.classList.toggle("perf-lite", perfLite);
  return perfLite;
}

function isLocalDevHost() {
  const host = window.location.hostname;
  return host === "localhost" || host === "127.0.0.1";
}

function inferDefaultApiUrl() {
  // Development: front-end and API often run on different ports.
  if (isLocalDevHost()) {
    return "http://127.0.0.1:8000/api/scan";
  }
  // Production: prefer same-origin reverse proxy (/api/* -> backend).
  return `${window.location.origin}/api/scan`;
}

function getApiUrl() {
  if (!apiInput) {
    return inferDefaultApiUrl();
  }
  const value = apiInput.value.trim();
  return value || inferDefaultApiUrl();
}

function getSelectedScanMode() {
  const selected = document.querySelector('input[name="scanMode"]:checked');
  return selected?.value || "common";
}

function isPortScanEnabled() {
  return enablePortScan ? enablePortScan.checked : true;
}

function setSwitchState(stateTextEl, inputEl) {
  if (!stateTextEl || !inputEl) {
    return;
  }
  stateTextEl.textContent = inputEl.checked ? "ON" : "OFF";
}

function syncScanModeUI() {
  if (!isPortScanEnabled()) {
    if (customPortsWrap) {
      customPortsWrap.classList.add("hidden");
    }
    if (customPortsInput) {
      customPortsInput.required = false;
    }
    updateMissionMode();
    return;
  }

  const mode = getSelectedScanMode();
  if (!customPortsWrap || !customPortsInput) {
    return;
  }
  if (mode === "custom") {
    customPortsWrap.classList.remove("hidden");
    customPortsInput.required = true;
  } else {
    customPortsWrap.classList.add("hidden");
    customPortsInput.required = false;
  }
  updateMissionMode();
}

function syncPortScannerUI() {
  if (!portScannerInput) {
    return;
  }
  const tcpScanInput = document.getElementById("tcpScan");
  const udpScanInput = document.getElementById("udpScan");
  if (!tcpScanInput || !udpScanInput) {
    return;
  }

  const portEnabled = isPortScanEnabled();
  tcpScanInput.disabled = !portEnabled;
  udpScanInput.disabled = !portEnabled;
}

function syncPortScanUI() {
  const enabled = isPortScanEnabled();

  setSwitchState(portScanStateText, enablePortScan);

  if (portScanOptions) {
    portScanOptions.classList.toggle("is-open", enabled);
    portScanOptions.classList.toggle("is-closed", !enabled);
    portScanOptions.querySelectorAll("input, select").forEach((field) => {
      field.disabled = !enabled;
    });
  }

  syncScanModeUI();
  syncPortScannerUI();
  updateModuleActiveCount();
  syncModuleConfigStage();
  updateMissionMode();
}

function syncVtScanUI() {
  setSwitchState(vtScanStateText, vtScanInput);
  const vtEnabled = !!vtScanInput?.checked;
  togglePanel(vtOptions, vtEnabled);
  if (vtApiKeyInput) {
    vtApiKeyInput.required = vtEnabled;
  }
  updateModuleActiveCount();
  syncModuleConfigStage();
}

function togglePanel(panel, enabled) {
  if (!panel) {
    return;
  }
  panel.classList.toggle("is-open", enabled);
  panel.classList.toggle("is-closed", !enabled);
  panel.querySelectorAll("input").forEach((input) => {
    input.disabled = !enabled;
  });
}

function initCyberNumberSteppers() {
  const stepButtons = document.querySelectorAll(".number-step-btn");
  stepButtons.forEach((button) => {
    button.addEventListener("click", () => {
      const targetId = button.getAttribute("data-target");
      const dir = button.getAttribute("data-dir");
      if (!targetId || !dir) {
        return;
      }
      const input = document.getElementById(targetId);
      if (!(input instanceof HTMLInputElement) || input.disabled) {
        return;
      }

      const stepRaw = Number.parseFloat(input.step || "1");
      const step = Number.isFinite(stepRaw) && stepRaw > 0 ? stepRaw : 1;
      const minRaw = Number.parseFloat(input.min);
      const maxRaw = Number.parseFloat(input.max);
      const currentRaw = Number.parseFloat(input.value);
      const current = Number.isFinite(currentRaw) ? currentRaw : Number.isFinite(minRaw) ? minRaw : 0;

      let next = dir === "up" ? current + step : current - step;
      if (Number.isFinite(minRaw)) {
        next = Math.max(minRaw, next);
      }
      if (Number.isFinite(maxRaw)) {
        next = Math.min(maxRaw, next);
      }

      const stepText = String(input.step || "1");
      const decimalIndex = stepText.indexOf(".");
      const decimals = decimalIndex >= 0 ? stepText.length - decimalIndex - 1 : 0;
      input.value = String(Number(next.toFixed(Math.max(0, decimals))));
      input.dispatchEvent(new Event("input", { bubbles: true }));
      input.dispatchEvent(new Event("change", { bubbles: true }));
    });
  });
}

function syncAdvancedFeatureUI() {
  setSwitchState(ctScanStateText, ctScanInput);
  setSwitchState(passiveDnsScanStateText, passiveDnsScanInput);
  setSwitchState(asnScanStateText, asnScanInput);
  setSwitchState(webAssetScanStateText, webAssetScanInput);
  setSwitchState(serviceRiskScanStateText, serviceRiskScanInput);
  setSwitchState(allowPrivateIpStateText, allowPrivateIpInput);

  togglePanel(asnOptions, !!asnScanInput?.checked);
  togglePanel(webAssetOptions, !!webAssetScanInput?.checked);
  togglePanel(serviceRiskOptions, !!serviceRiskScanInput?.checked);

  const allowPrivate = !!allowPrivateIpInput?.checked;
  togglePanel(networkOptions, allowPrivate);
  updateModuleActiveCount();
  syncModuleConfigStage();
  renderModuleStatusList();
}

function initMatrixRain() {
  const canvas = document.getElementById("matrixRain");
  if (!canvas) {
    return;
  }

  const ctx = canvas.getContext("2d");
  if (!ctx) {
    return;
  }

  const glyphs = "01234567890123456789";
  let columns = [];
  let fontSize = 17;
  let colWidth = fontSize * 1.08;
  let width = 0;
  let height = 0;
  ctx.imageSmoothingEnabled = false;

  function resize() {
    width = window.innerWidth;
    height = window.innerHeight;
    canvas.width = width;
    canvas.height = height;
    colWidth = fontSize * 1.08;
    const colCount = Math.max(1, Math.floor(width / colWidth));
    columns = Array.from({ length: colCount }, () => ({
      y: Math.random() * height,
      speed: 0.13 + Math.random() * 0.14,
    }));
  }

  function draw() {
    // Classic digital matrix trail.
    ctx.fillStyle = "rgba(2, 5, 3, 0.5)";
    ctx.fillRect(0, 0, width, height);

    ctx.font = `${fontSize}px Share Tech Mono`;
    ctx.textBaseline = "top";

    for (let i = 0; i < columns.length; i += 1) {
      const col = columns[i];
      const y = col.y;
      const x = i * colWidth;
      const headChar = glyphs[Math.floor(Math.random() * glyphs.length)];
      const tailChar = glyphs[Math.floor(Math.random() * glyphs.length)];

      // Tail glyph (dimmer green).
      ctx.fillStyle = "rgba(0, 255, 0, 0.42)";
      ctx.fillText(tailChar, x, y - fontSize * 2.2);

      // Head glyph (bright terminal green).
      ctx.fillStyle = "#00ff00";
      ctx.fillText(headChar, x, y);

      if (y > height + fontSize && Math.random() > 0.97) {
        col.y = -fontSize * (2 + Math.random() * 6);
        col.speed = 0.13 + Math.random() * 0.14;
      } else {
        col.y = y + fontSize * col.speed;
      }
    }
  }

  const targetFps = 36;
  const frameDuration = 1000 / targetFps;
  let lastTime = 0;
  function loop(timestamp) {
    if (!document.hidden && (!lastTime || timestamp - lastTime >= frameDuration)) {
      draw();
      lastTime = timestamp;
    }
    requestAnimationFrame(loop);
  }

  resize();
  window.addEventListener("resize", resize);
  requestAnimationFrame(loop);
}

function initVoidRainPanel() {
  const canvas = document.getElementById("voidRainPanel");
  const host = canvas?.closest(".cyber-void-art");
  if (!canvas || !host) {
    return;
  }

  const ctx = canvas.getContext("2d");
  if (!ctx) {
    return;
  }

  const glyphs = "0123456789TOKI";
  let columns = [];
  let width = 0;
  let height = 0;
  let fontSize = 15;
  let colWidth = 14;
  let dpr = 1;

  function pickGlyph() {
    // Keep digits as the main visual while occasionally mixing TOKI glyphs.
    if (Math.random() < 0.74) {
      return String(Math.floor(Math.random() * 10));
    }
    return glyphs[10 + Math.floor(Math.random() * 4)];
  }

  function resetColumns() {
    const colCount = Math.max(1, Math.floor(width / colWidth));
    columns = Array.from({ length: colCount }, () => ({
      y: Math.random() * height,
      speed: 0.09 + Math.random() * 0.11,
      head: pickGlyph(),
      tail: pickGlyph(),
    }));
  }

  function resize() {
    const rect = host.getBoundingClientRect();
    width = Math.max(1, Math.floor(rect.width));
    height = Math.max(1, Math.floor(rect.height));

    const perfLite = document.documentElement.classList.contains("perf-lite");
    dpr = perfLite ? 1 : Math.min(1.5, window.devicePixelRatio || 1);

    canvas.width = Math.floor(width * dpr);
    canvas.height = Math.floor(height * dpr);
    canvas.style.width = `${width}px`;
    canvas.style.height = `${height}px`;
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);

    fontSize = Math.max(14, Math.min(18, Math.round(width / 52)));
    colWidth = Math.max(13, Math.round(fontSize * 0.92));
    resetColumns();
  }

  function draw() {
    ctx.fillStyle = "rgba(2, 14, 9, 0.24)";
    ctx.fillRect(0, 0, width, height);

    ctx.font = `600 ${fontSize}px Share Tech Mono`;
    ctx.textBaseline = "top";

    for (let i = 0; i < columns.length; i += 1) {
      const col = columns[i];
      const x = i * colWidth + 1;
      const y = col.y;

      if (Math.random() < 0.03) {
        col.head = pickGlyph();
      }
      if (Math.random() < 0.03) {
        col.tail = pickGlyph();
      }

      ctx.fillStyle = "rgba(92, 255, 188, 0.4)";
      ctx.fillText(col.tail, x, y - fontSize * 1.9);
      ctx.fillStyle = "rgba(130, 255, 220, 0.9)";
      ctx.fillText(col.head, x, y);

      if (y > height + fontSize && Math.random() > 0.955) {
        col.y = -fontSize * (2 + Math.random() * 6);
        col.speed = 0.09 + Math.random() * 0.11;
      } else {
        col.y = y + fontSize * col.speed;
      }
    }
  }

  const targetFps = document.documentElement.classList.contains("perf-lite") ? 18 : 24;
  const frameDuration = 1000 / targetFps;
  let lastTime = 0;
  function loop(timestamp) {
    if (!document.hidden && (!lastTime || timestamp - lastTime >= frameDuration)) {
      draw();
      lastTime = timestamp;
    }
    requestAnimationFrame(loop);
  }

  resize();
  if (typeof ResizeObserver !== "undefined") {
    const observer = new ResizeObserver(() => resize());
    observer.observe(host);
  }
  window.addEventListener("resize", resize);
  requestAnimationFrame(loop);
}

function logLine(text, level = "info") {
  const line = document.createElement("div");
  line.textContent = `[${new Date().toLocaleTimeString()}] ${text}`;
  line.style.color = level === "error" ? "var(--alert)" : level === "ok" ? "var(--ok)" : "var(--cyan-hot)";
  terminal.appendChild(line);
  terminal.scrollTop = terminal.scrollHeight;
  pushLiveEvent(text, level);
  updateCoreStatusLine(text);
}

function renderPortInsights(data) {
  const ipScan = data?.ip_scan || {};
  const rows = [];

  Object.entries(ipScan.results || {}).forEach(([ip, result]) => {
    const tcpRows = Array.isArray(result?.tcp?.open_ports) ? result.tcp.open_ports : [];
    const udpRows = Array.isArray(result?.udp?.open_ports) ? result.udp.open_ports : [];

    tcpRows.forEach((row) => {
      rows.push(`${ip}:${row?.port}/${row?.protocol || "tcp"} / ${row?.service || "unknown"}`);
    });

    udpRows.forEach((row) => {
      rows.push(`${ip}:${row?.port}/${row?.protocol || "udp"} / ${row?.service || "unknown"}`);
    });
  });

  appendDockRows(portsOutput, rows, "No open port intelligence loaded.");
}

function renderTechInsights(data) {
  const tech = data?.tech_stack || {};
  const webAssets = data?.web_assets || {};
  const serviceRisk = data?.service_risk || {};
  const rows = [];

  const techList = Array.isArray(tech.detected_technologies) ? tech.detected_technologies : [];
  if (techList.length) {
    rows.push(`Detected technologies: ${techList.join(", ")}`);
  }

  const endpoints = Array.isArray(webAssets.combined_endpoints) ? webAssets.combined_endpoints.length : 0;
  const sensitive = Number(webAssets?.sensitive_paths?.count || 0);
  const dirHits = Number(webAssets?.directory_probe?.hit_count || 0);
  if (webAssets.enabled || endpoints || sensitive || dirHits) {
    rows.push(`Web assets / endpoints: ${endpoints} / sensitive paths: ${sensitive} / directory hits: ${dirHits}`);
  }

  const cveMatches = Array.isArray(serviceRisk?.cve_lookup?.matches) ? serviceRisk.cve_lookup.matches.length : 0;
  const weakChecks = Array.isArray(serviceRisk?.weak_checks?.findings) ? serviceRisk.weak_checks.findings.length : 0;
  if (serviceRisk.enabled || cveMatches || weakChecks) {
    rows.push(`Service risk / CVE matches: ${cveMatches} / weak findings: ${weakChecks}`);
  }

  appendDockRows(techOutput, rows, "No technology or service risk intelligence loaded.");
}

function formatSummary(data) {
  const ipScan = data?.ip_scan || {};
  const vt = data?.virustotal || {};
  const dns = data?.dns || {};
  const whois = data?.whois || {};
  const tech = data?.tech_stack || {};
  const ct = data?.certificate_transparency || {};
  const passiveDns = data?.passive_dns || {};
  const asn = data?.asn_network || {};
  const webAssets = data?.web_assets || {};
  const serviceRisk = data?.service_risk || {};

  const targetInput = data?.meta?.target_input || data?.target?.input || "N/A";
  const normalizedUrl = data?.target?.normalized_url || "N/A";
  const domain = data?.target?.domain || "N/A";

  let openTcp = 0;
  let openUdp = 0;
  const tcpAll = [];
  const udpAll = [];
  for (const ip of Object.keys(ipScan.results || {})) {
    const tcpResult = ipScan.results[ip]?.tcp || {};
    const udpResult = ipScan.results[ip]?.udp || {};
    const tcpRows = Array.isArray(tcpResult.open_ports) ? tcpResult.open_ports : [];
    const udpRows = Array.isArray(udpResult.open_ports) ? udpResult.open_ports : [];

    openTcp += tcpResult.open_port_count || tcpRows.length || 0;
    openUdp += udpResult.open_port_count || udpRows.length || 0;

    tcpRows.forEach((row) => {
      const serviceName = row?.service || "unknown";
      tcpAll.push(`${ip}:${row?.port}/${row?.protocol || "tcp"} (${serviceName})`);
    });
    udpRows.forEach((row) => {
      const serviceName = row?.service || "unknown";
      udpAll.push(`${ip}:${row?.port}/${row?.protocol || "udp"} (${serviceName})`);
    });
  }

  const dnsA = Array.isArray(dns.A) ? dns.A.join(", ") : "N/A";
  const dnsAAAA = Array.isArray(dns.AAAA) ? dns.AAAA.join(", ") : "N/A";
  const dnsNS = Array.isArray(dns.NS) ? dns.NS.join(", ") : "N/A";
  const dnsMX = Array.isArray(dns.MX) ? dns.MX.join(", ") : "N/A";
  const whoisRegistrar = whois?.registrar || "N/A";
  const whoisCreated = whois?.creation_date || "N/A";
  const whoisExpire = whois?.expiration_date || "N/A";
  const techList = Array.isArray(tech.detected_technologies) ? tech.detected_technologies : [];
  const techText = techList.length ? techList.join(", ") : "N/A";

  function vtStatsText(side) {
    const stats = side?.last_analysis_stats;
    if (!stats || typeof stats !== "object") {
      return "N/A";
    }
    const malicious = Number(stats.malicious || 0);
    const suspicious = Number(stats.suspicious || 0);
    const harmless = Number(stats.harmless || 0);
    const undetected = Number(stats.undetected || 0);
    return `malicious:${malicious}, suspicious:${suspicious}, harmless:${harmless}, undetected:${undetected}`;
  }
  const vtDomainStats = vtStatsText(vt?.domain);
  const vtUrlStats = vtStatsText(vt?.url);
  const ctSubdomains = Array.isArray(ct.discovered_subdomains) ? ct.discovered_subdomains.length : 0;
  const passiveSubdomains = Array.isArray(passiveDns.historical_subdomains) ? passiveDns.historical_subdomains.length : 0;
  const passiveIps = Array.isArray(passiveDns.resolved_ips) ? passiveDns.resolved_ips.length : 0;
  const asnRecords = Array.isArray(asn.records) ? asn.records.length : 0;
  const asnExpandedHosts = Array.isArray(asn.expanded_c_segment_hosts) ? asn.expanded_c_segment_hosts.length : 0;
  const webEndpoints = Array.isArray(webAssets.combined_endpoints) ? webAssets.combined_endpoints.length : 0;
  const webSensitive = Number(webAssets?.sensitive_paths?.count || 0);
  const webDirHits = Number(webAssets?.directory_probe?.hit_count || 0);
  const cveMatches = Array.isArray(serviceRisk?.cve_lookup?.matches) ? serviceRisk.cve_lookup.matches.length : 0;
  const ipScanWarnings = Array.isArray(ipScan?.warnings) ? ipScan.warnings.join(" | ") : "N/A";

  const blocks = [
    `Target input: ${targetInput}`,
    `Target domain: ${domain}`,
    `Normalized URL: ${normalizedUrl}`,
    `Scan mode: ${data?.meta?.scan_mode || "N/A"}`,
    `Port engine: ${ipScan.scanner || data?.meta?.requested_port_scanner || "N/A"}`,
    `Port warnings: ${ipScanWarnings}`,
    `Port range: ${ipScan.port_range || data?.meta?.requested_port_range || "N/A"}`,
    `TCP scan enabled: ${String(ipScan.tcp_scan_enabled ?? true)}`,
    `UDP scan enabled: ${String(ipScan.udp_scan_enabled ?? false)}`,
    `IP scan performed: ${String(ipScan.scan_performed ?? false)}`,
    `Targets(IP): ${(ipScan.targets || []).join(", ") || "N/A"}`,
    `Open TCP ports: ${openTcp}`,
    `Open UDP ports: ${openUdp}`,
    `TCP services: ${tcpAll.join(" | ") || "N/A"}`,
    `UDP services: ${udpAll.join(" | ") || "N/A"}`,
    `DNS A: ${dnsA}`,
    `DNS AAAA: ${dnsAAAA}`,
    `DNS NS: ${dnsNS}`,
    `DNS MX: ${dnsMX}`,
    `WHOIS registrar: ${whoisRegistrar}`,
    `WHOIS created: ${whoisCreated}`,
    `WHOIS expires: ${whoisExpire}`,
    `Detected technologies: ${techText}`,
    `VirusTotal enabled: ${String(vt.enabled ?? false)}`,
    `VirusTotal domain stats: ${vtDomainStats}`,
    `VirusTotal URL stats: ${vtUrlStats}`,
    `CT logs enabled: ${String(ct.enabled ?? false)} / subdomains: ${ctSubdomains}`,
    `Passive DNS enabled: ${String(passiveDns.enabled ?? false)} / historical subdomains: ${passiveSubdomains} / resolved IPs: ${passiveIps}`,
    `ASN enabled: ${String(asn.enabled ?? false)} / records: ${asnRecords} / expanded hosts: ${asnExpandedHosts}`,
    `Web asset enumeration enabled: ${String(webAssets.enabled ?? false)} / endpoints: ${webEndpoints} / sensitive paths: ${webSensitive} / directory hits: ${webDirHits}`,
    `Service risk enabled: ${String(serviceRisk.enabled ?? false)} / CPE-CVE matches: ${cveMatches}`,
  ];

  summary.innerHTML = "";
  blocks.forEach((text) => {
    const item = document.createElement("div");
    item.className = "summary-item";
    item.textContent = text;
    summary.appendChild(item);
  });
}

function renderReport(data, source = "scan") {
  formatSummary(data);
  renderPortInsights(data);
  renderTechInsights(data);
  rawOutput.textContent = JSON.stringify(data, null, 2);
  latestReport = data;
  latestReportSource = source;
  updateHudThreatFromReport(data);
  updateHudTargetLock();
  updateMissionMode();
  updateMissionFocus();
  updateExportMeta();
  updateResultOverview(data);
  logLine("Report rendered.", "ok");
}

function renderNoBackendState(message) {
  summary.innerHTML = "";
  const item = document.createElement("div");
  item.className = "summary-item";
  item.textContent = message;
  summary.appendChild(item);
  appendDockRows(portsOutput, [], "No open port intelligence loaded.");
  appendDockRows(techOutput, [], "No technology or service risk intelligence loaded.");
  rawOutput.textContent = "";
  updateExportMeta();
  if (!latestReport) {
    updateResultOverview(null);
  }
}

function setProgress(value, customText) {
  progressValue = Math.max(0, Math.min(100, Math.floor(value)));
  if (progressBar) {
    progressBar.style.width = `${progressValue}%`;
  }
  if (progressText) {
    progressText.textContent = customText || `Progress: ${progressValue}%`;
  }
}

function buildPayload() {
  const portScanEnabled = isPortScanEnabled();
  const portTimeoutInput = document.getElementById("portTimeout");
  const scanMode = getSelectedScanMode();
  const customPorts = (customPortsInput?.value || "").trim();
  const selectedPortScanner = (portScannerInput?.value || "auto").trim().toLowerCase();

  let fullPortScan = false;
  let portRange = "1-1024";
  let payloadScanMode = null;
  if (portScanEnabled) {
    payloadScanMode = scanMode;
    if (scanMode === "full") {
      fullPortScan = true;
      portRange = "1-65535";
    } else if (scanMode === "common") {
      fullPortScan = false;
      portRange = COMMON_PORT_RANGE;
    } else if (scanMode === "custom") {
      if (!customPorts) {
        throw new Error("Custom port mode requires a port range.");
      }
      fullPortScan = false;
      portRange = customPorts;
    }
  }

  const tcpScanEnabled = portScanEnabled ? document.getElementById("tcpScan").checked : false;
  const udpScanEnabled = portScanEnabled ? document.getElementById("udpScan").checked : false;
  if (portScanEnabled && !tcpScanEnabled && !udpScanEnabled) {
    throw new Error("Enable at least one protocol: TCP or UDP.");
  }

  return {
    target: document.getElementById("target").value.trim(),
    timeout: Number(document.getElementById("timeout").value || 10),
    vt_scan: vtScanInput ? vtScanInput.checked : false,
    vt_api_key: vtScanInput?.checked ? (vtApiKeyInput?.value || "").trim() : null,
    port_timeout: Number(portTimeoutInput?.value || 0.8),
    port_scanner: selectedPortScanner,
    port_range: portRange,
    full_port_scan: fullPortScan,
    scan_mode: payloadScanMode,
    custom_ports: portScanEnabled && scanMode === "custom" ? customPorts : null,
    tcp_scan: tcpScanEnabled,
    udp_scan: udpScanEnabled,
    allow_private_ip: allowPrivateIpInput ? allowPrivateIpInput.checked : false,
    cidr_targets: allowPrivateIpInput?.checked ? (cidrTargetsInput?.value || "").trim() : "",
    ct_scan: ctScanInput ? ctScanInput.checked : false,
    passive_dns_scan: passiveDnsScanInput ? passiveDnsScanInput.checked : false,
    asn_scan: asnScanInput ? asnScanInput.checked : false,
    asn_expand_c_segment: asnScanInput?.checked ? !!asnExpandCSegmentInput?.checked : false,
    web_asset_scan: webAssetScanInput ? webAssetScanInput.checked : false,
    web_crawler: webAssetScanInput?.checked ? !!webCrawlerInput?.checked : false,
    web_js_extract: webAssetScanInput?.checked ? !!webJsExtractInput?.checked : false,
    web_sensitive_path_extract: webAssetScanInput?.checked ? !!webSensitivePathExtractInput?.checked : false,
    web_dir_scan: webAssetScanInput?.checked ? !!webDirScanInput?.checked : false,
    web_dir_use_ffuf: webAssetScanInput?.checked ? !!webDirUseFfufInput?.checked : false,
    service_risk_scan: serviceRiskScanInput ? serviceRiskScanInput.checked : false,
    cve_lookup: serviceRiskScanInput?.checked ? !!cveLookupInput?.checked : false,
    weak_nmap_checks: serviceRiskScanInput?.checked ? !!weakNmapChecksInput?.checked : false,
  };
}

function setRunningState(running) {
  isRunning = running;
  const runBtn = document.getElementById("runBtn");
  if (runBtn) {
    runBtn.disabled = running;
  }
  if (stopBtn) {
    stopBtn.disabled = !running;
  }
  document.body.classList.toggle("scan-active", running);
  if (running) {
    setHudTaskState("RUNNING");
    setHudThreat("MEDIUM");
  } else if (!currentJobId) {
    setHudTaskState("IDLE");
  }
  updateHudMetrics();
  updateMissionFocus();
  updateCoreStatusLine();
}

function clearPollTimer() {
  if (pollTimer) {
    clearInterval(pollTimer);
    pollTimer = null;
  }
}

function normalizeApiUrl(apiUrl) {
  return apiUrl.replace(/\/+$/, "");
}

async function pollJobStatus(apiUrl, jobId) {
  const statusUrl = `${normalizeApiUrl(apiUrl)}/${jobId}`;
  const response = await fetch(statusUrl, { method: "GET" });
  if (!response.ok) {
    throw new Error(`HTTP ${response.status}`);
  }
  const data = await response.json();
  const status = data?.status || "unknown";

  if (status === "completed") {
    clearPollTimer();
    setRunningState(false);
    currentJobId = null;
    setHudTaskState("COMPLETED");
    setProgress(100, "Progress: 100% (completed)");
    if (data.result) {
      renderReport(data.result);
    } else {
      renderNoBackendState("Scan completed but no result returned.");
    }
    pushHistoryEntry({
      title: getTargetDisplayValue(),
      detail: "Completed scan result ready for review.",
      status: "completed",
    });
    logLine("Scan completed.", "ok");
    return;
  }

  if (status === "canceled") {
    clearPollTimer();
    setRunningState(false);
    currentJobId = null;
    setHudTaskState("CANCELED");
    setProgress(100, "Progress: 100% (stopped)");
    if (data.result) {
      renderReport(data.result);
    } else {
      renderNoBackendState("Scan canceled.");
    }
    pushHistoryEntry({
      title: getTargetDisplayValue(),
      detail: "Scan was canceled before completion.",
      status: "canceled",
    });
    logLine("Scan canceled.", "error");
    return;
  }

  if (status === "failed") {
    clearPollTimer();
    setRunningState(false);
    currentJobId = null;
    setHudTaskState("FAILED");
    setHudThreat("ELEVATED");
    setProgress(100, "Progress: 100% (failed)");
    renderNoBackendState(`Scan failed: ${data.error || "unknown error"}`);
    pushHistoryEntry({
      title: getTargetDisplayValue(),
      detail: `Scan failed: ${data.error || "unknown error"}`,
      status: "failed",
    });
    logLine(`Scan failed: ${data.error || "unknown error"}`, "error");
    return;
  }

  // running / queued / stopping
  if (status === "stopping") {
    setHudTaskState("STOPPING");
    setProgress(Math.max(progressValue, 95), "Progress: stopping...");
  } else if (status === "queued") {
    setHudTaskState("QUEUED");
    setProgress(Math.max(progressValue, 5), "Progress: queued...");
  } else {
    setHudTaskState("RUNNING");
    setProgress(Math.min(95, progressValue + 3));
  }
  renderNoBackendState(`Scan status: ${status} (job: ${jobId})`);
}

async function runScan(event) {
  event.preventDefault();
  if (isRunning) {
    logLine("A scan is already running. Stop it before launching another.", "error");
    return;
  }

  let payload;
  try {
    payload = buildPayload();
  } catch (error) {
    logLine(error.message || "Scan parameters are invalid.", "error");
    return;
  }

  if (!payload.target) {
    logLine("Target cannot be empty.", "error");
    return;
  }
  if (payload.vt_scan && !payload.vt_api_key) {
    logLine("VirusTotal is enabled. Enter your own API key first.", "error");
    return;
  }

  logLine(`Launching scan for ${payload.target}.`);
  updateHudTargetLock();
  setHudTaskState("LAUNCH");
  setHudThreat("MEDIUM");
  const apiUrl = getApiUrl();

  if (!apiUrl) {
    logLine("Backend API URL is missing.", "error");
    renderNoBackendState("Backend API is not connected. Enter an API URL first.");
    return;
  }

  try {
    latestReport = null;
    latestReportSource = null;
    updateResultOverview(null);
    setProgress(3, "Progress: booting...");
    const response = await fetch(apiUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });

    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }

    const data = await response.json();
    const jobId = data?.job_id;
    if (!jobId) {
      throw new Error("Missing job_id from API response.");
    }

    currentJobId = jobId;
    setRunningState(true);
    setHudTaskState("RUNNING");
    renderNoBackendState(`Scan job created. Job ID: ${jobId}`);
    pushHistoryEntry({
      title: payload.target,
      detail: `Scan launched. Job ${jobId} is now active.`,
      status: "running",
    });
    logLine(`Job created: ${jobId}.`, "ok");

    clearPollTimer();
    pollTimer = setInterval(() => {
      pollJobStatus(apiUrl, jobId).catch((error) => {
        clearPollTimer();
        setRunningState(false);
        currentJobId = null;
        setHudTaskState("ERROR");
        setHudThreat("ELEVATED");
        setProgress(0, "Progress: 0%");
        renderNoBackendState("Failed to poll job status.");
        logLine(`Polling failed (${error.message}).`, "error");
      });
    }, 1000);
  } catch (error) {
    setHudTaskState("ERROR");
    setHudThreat("ELEVATED");
    setProgress(0, "Progress: 0%");
    logLine(`API request failed (${error.message}).`, "error");
    renderNoBackendState("Backend request failed. Check the API URL and backend status.");
  }
}

async function stopScan() {
  const apiUrl = getApiUrl();
  if (!isRunning || !currentJobId) {
    logLine("There is no running scan to stop.", "error");
    return;
  }
  if (!apiUrl) {
    logLine("Backend API URL is empty.", "error");
    return;
  }

  const stopUrl = `${normalizeApiUrl(apiUrl)}/${currentJobId}/stop`;
  try {
    const response = await fetch(stopUrl, { method: "POST" });
    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }
    setProgress(Math.max(progressValue, 95), "Progress: stopping...");
    logLine("Stop signal sent.", "ok");
    renderNoBackendState(`Stopping job ${currentJobId} ...`);
  } catch (error) {
    logLine(`Stop request failed (${error.message}).`, "error");
  }
}

function downloadResult() {
  if (!latestReport || latestReportSource !== "scan") {
    logLine("No completed scan result is available for download yet.", "error");
    return;
  }
  const content = JSON.stringify(latestReport, null, 2);
  const blob = new Blob([content], { type: "application/json;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const stamp = new Date().toISOString().replace(/[:.]/g, "-");
  const a = document.createElement("a");
  a.href = url;
  a.download = `scan-result-${stamp}.json`;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
  logLine("Result download completed.", "ok");
}

function clearCurrentScan() {
  if (isRunning) {
    logLine("Stop the current scan before resetting the workspace.", "error");
    return;
  }
  latestReport = null;
  latestReportSource = null;
  currentJobId = null;
  rawOutput.textContent = "";
  summary.innerHTML = "";
  const item = document.createElement("div");
  item.className = "summary-item";
  item.textContent = "Workspace output has been cleared.";
  summary.appendChild(item);
  appendDockRows(portsOutput, [], "Open ports and service banners will appear here.");
  appendDockRows(techOutput, [], "Technologies, fingerprints, and service risk findings will appear here.");
  terminal.innerHTML = "";
  if (liveEvents) {
    liveEvents.innerHTML = '<div class="event-line event-line--muted">[standby] scan system ready. enter a target to begin.</div>';
  }
  setProgress(0, "Progress: 0%");
  updateResultOverview(null);
  if (fileInput) {
    fileInput.value = "";
  }
  resetReportFileState();

  // Reset all right-side module switches to OFF.
  moduleToggleInputs.forEach((input) => {
    input.checked = false;
  });
  syncVtScanUI();
  syncPortScanUI();
  syncAdvancedFeatureUI();
  syncModuleConfigStage();

  setHudTaskState("IDLE");
  setHudThreat("LOW");
  updateHudTargetLock();
  updateMissionFocus();
  updateMissionMode();
  updateExportMeta();
  logLine("Workspace cleared and all module switches were turned off.", "ok");
}

function handleFileUpload(event) {
  const file = event.target.files?.[0];
  if (!file) {
    return;
  }

  setReportFileState(file);

  const reader = new FileReader();
  reader.onload = () => {
    try {
      const data = JSON.parse(String(reader.result));
      logLine(`Loaded ${file.name}.`, "ok");
      renderReport(data, "file");
      setRunningState(false);
      setHudTaskState("REPORT");
      setProgress(100, "Progress: 100% (report loaded)");
      setReportFileState(file, `${formatFileSize(file.size)} / Imported`);
      pushHistoryEntry({
        title: file.name,
        detail: `Report imported for ${getTargetDisplayValue()}.`,
        status: "report",
      });
    } catch (_error) {
      setReportFileState(file, `${formatFileSize(file.size)} / Invalid JSON`);
      logLine("The selected file is not valid JSON.", "error");
    }
  };
  reader.readAsText(file, "utf-8");
}

function initReportDropzone() {
  if (!reportDropzone || !fileInput) {
    return;
  }

  ["dragenter", "dragover"].forEach((eventName) => {
    reportDropzone.addEventListener(eventName, (event) => {
      event.preventDefault();
      reportDropzone.classList.add("is-dragover");
    });
  });

  ["dragleave", "dragend", "drop"].forEach((eventName) => {
    reportDropzone.addEventListener(eventName, (event) => {
      event.preventDefault();
      reportDropzone.classList.remove("is-dragover");
    });
  });

  reportDropzone.addEventListener("drop", (event) => {
    const files = event.dataTransfer?.files;
    if (!files?.length) {
      return;
    }
    try {
      fileInput.files = files;
    } catch (_error) {}
    handleFileUpload({ target: { files } });
  });

  reportDropzone.addEventListener("click", (event) => {
    const target = event.target;
    if (!(target instanceof HTMLElement)) {
      return;
    }
    if (target.closest("input") || target.closest(".file-btn")) {
      return;
    }
    fileInput.click();
  });
}

if (form) {
  form.addEventListener("submit", runScan);
}
if (fileInput) {
  fileInput.addEventListener("change", handleFileUpload);
}
scanModeRadios.forEach((radio) => {
  radio.addEventListener("change", syncScanModeUI);
});
if (enablePortScan) {
  enablePortScan.addEventListener("change", syncPortScanUI);
}
if (portScannerInput) {
  portScannerInput.addEventListener("change", syncPortScannerUI);
}
if (vtScanInput) {
  vtScanInput.addEventListener("change", syncVtScanUI);
}
[
  ctScanInput,
  passiveDnsScanInput,
  asnScanInput,
  webAssetScanInput,
  serviceRiskScanInput,
  allowPrivateIpInput,
].forEach((input) => {
  if (input) {
    input.addEventListener("change", syncAdvancedFeatureUI);
  }
});
if (stopBtn) {
  stopBtn.addEventListener("click", stopScan);
}
if (downloadBtn) {
  downloadBtn.addEventListener("click", downloadResult);
}
if (clearBtn) {
  clearBtn.addEventListener("click", clearCurrentScan);
}
if (targetInput) {
  targetInput.addEventListener("input", updateHudTargetLock);
}
moduleToggleInputs.forEach((input) => {
  input.addEventListener("change", updateModuleActiveCount);
});
const perfLiteEnabled = applyPerformancePreset();
recentHistory = loadHistory();
initDockTabs();
initCyberNumberSteppers();
initReportDropzone();
initMatrixRain();
initVoidRainPanel();
initHudRuntime();
setRunningState(false);
setProgress(0, "Progress: 0%");
if (apiInput && !apiInput.value.trim()) {
  apiInput.value = inferDefaultApiUrl();
}
syncVtScanUI();
syncPortScanUI();
syncAdvancedFeatureUI();
syncModuleConfigStage();
updateHudTargetLock();
updateHudClock();
updateHudSignal();
updateModuleActiveCount();
updateMissionMode();
updateMissionFocus();
updateExportMeta();
renderHistory();
resetReportFileState();
if (perfLiteEnabled) {
  logLine("Performance mode enabled automatically to reduce heavy effects.", "ok");
}
logLine(`Workspace ready. API: ${getApiUrl()}`, "ok");
