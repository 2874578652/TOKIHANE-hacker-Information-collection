const terminal = document.getElementById("terminal");
const summary = document.getElementById("summary");
const rawOutput = document.getElementById("rawOutput");
const form = document.getElementById("scanForm");
const fileInput = document.getElementById("reportFile");
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
const liveEvents = document.getElementById("liveEvents");
const moduleStatusList = document.getElementById("moduleStatusList");
const portsOutput = document.getElementById("portsOutput");
const techOutput = document.getElementById("techOutput");
const exportSource = document.getElementById("exportSource");
const exportTarget = document.getElementById("exportTarget");
const dockTabs = Array.from(document.querySelectorAll(".dock-tab"));
const dockPanels = Array.from(document.querySelectorAll(".dock-panel"));

const COMMON_PORT_RANGE =
  "21,22,23,25,53,80,110,111,135,139,143,389,443,445,465,587,993,995,1433,1521,1723,1883,1900,2049,2375,2376,3306,3389,5432,5900,6379,7001,8000,8080,8081,8443,8888,9200,11211,27017";

let currentJobId = null;
let pollTimer = null;
let latestReport = null;
let latestReportSource = null;
let isRunning = false;
let progressValue = 0;
let hudRuntimeTick = 0;

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
  return getTargetLabel() || "UNASSIGNED";
}

function getCoreTargetValue() {
  return getTargetLabel() || "NO TARGET";
}

function getSelectedScanModeLabel() {
  if (!isPortScanEnabled()) {
    return "PASSIVE";
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
  setNodeText(missionMode, getSelectedScanModeLabel(), "PASSIVE");
}

function updateMissionFocus() {
  const activeCount = moduleToggleInputs.reduce((count, input) => {
    return input?.checked ? count + 1 : count;
  }, 0);

  let focus = "Passive Sweep";
  if (isRunning) {
    focus = activeCount > 4 ? "Deep Recon" : "Active Recon";
  } else if (latestReport) {
    focus = latestReportSource === "file" ? "Loaded Report" : "Captured Report";
  } else if (activeCount > 0) {
    focus = activeCount > 4 ? "Stacked Sweep" : "Prepared Sweep";
  }

  setNodeText(missionFocus, focus, "Passive Sweep");
  setNodeText(coreSignalLane, isRunning ? "ACTIVE" : activeCount > 0 ? "PRIMED" : "PASSIVE", "PASSIVE");
}

function updateCoreStatusLine(message) {
  if (message) {
    setNodeText(coreStatusLine, message, "Recon core in standby. Awaiting operator input.");
    return;
  }

  const target = getTargetLabel();
  if (isRunning && target) {
    setNodeText(coreStatusLine, `Recon sweep executing against ${target}.`, "Recon core in standby. Awaiting operator input.");
    return;
  }
  if (latestReport && target) {
    setNodeText(coreStatusLine, `Latest intelligence snapshot loaded for ${target}.`, "Recon core in standby. Awaiting operator input.");
    return;
  }
  setNodeText(coreStatusLine, "Recon core in standby. Awaiting operator input.", "Recon core in standby. Awaiting operator input.");
}

function updateExportMeta() {
  setNodeText(exportSource, latestReport ? String(latestReportSource || "scan").toUpperCase() : "NO REPORT", "NO REPORT");
  setNodeText(exportTarget, getTargetDisplayValue(), "UNASSIGNED");
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
  setNodeText(hudTargetLock, getTargetLabel(), "WAITING...");
  setNodeText(statusTarget, getTargetDisplayValue(), "UNASSIGNED");
  setNodeText(missionTarget, getTargetDisplayValue(), "UNASSIGNED");
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
  line.style.color = level === "error" ? "#ff8f9f" : level === "ok" ? "#9dffc3" : "#ffdce1";
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
    `目标输入: ${targetInput}`,
    `目标域名: ${domain}`,
    `规范化URL: ${normalizedUrl}`,
    `端口模式: ${data?.meta?.scan_mode || "N/A"}`,
    `端口扫描引擎: ${ipScan.scanner || data?.meta?.requested_port_scanner || "N/A"}`,
    `端口扫描告警: ${ipScanWarnings}`,
    `端口范围: ${ipScan.port_range || data?.meta?.requested_port_range || "N/A"}`,
    `TCP扫描: ${String(ipScan.tcp_scan_enabled ?? true)}`,
    `UDP扫描: ${String(ipScan.udp_scan_enabled ?? false)}`,
    `是否完成IP扫描: ${String(ipScan.scan_performed ?? false)}`,
    `Targets(IP): ${(ipScan.targets || []).join(", ") || "N/A"}`,
    `开放 TCP 端口数: ${openTcp}`,
    `开放 UDP 端口数: ${openUdp}`,
    `TCP 端口服务(全量): ${tcpAll.join(" | ") || "N/A"}`,
    `UDP 端口服务(全量): ${udpAll.join(" | ") || "N/A"}`,
    `DNS A: ${dnsA}`,
    `DNS AAAA: ${dnsAAAA}`,
    `DNS NS: ${dnsNS}`,
    `DNS MX: ${dnsMX}`,
    `WHOIS 注册商: ${whoisRegistrar}`,
    `WHOIS 创建时间: ${whoisCreated}`,
    `WHOIS 到期时间: ${whoisExpire}`,
    `技术栈识别: ${techText}`,
    `VT 已启用: ${String(vt.enabled ?? false)}`,
    `VT 域名统计: ${vtDomainStats}`,
    `VT URL统计: ${vtUrlStats}`,
    `CT 日志启用: ${String(ct.enabled ?? false)} / 子域名: ${ctSubdomains}`,
    `被动DNS启用: ${String(passiveDns.enabled ?? false)} / 历史子域: ${passiveSubdomains} / 解析IP: ${passiveIps}`,
    `ASN模块启用: ${String(asn.enabled ?? false)} / ASN记录: ${asnRecords} / C段扩展IP: ${asnExpandedHosts}`,
    `Web资产枚举启用: ${String(webAssets.enabled ?? false)} / 端点: ${webEndpoints} / 敏感路径: ${webSensitive} / 目录命中: ${webDirHits}`,
    `服务风险模块启用: ${String(serviceRisk.enabled ?? false)} / CPE-CVE查询条目: ${cveMatches}`,
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
}

function setProgress(value, customText) {
  progressValue = Math.max(0, Math.min(100, Math.floor(value)));
  if (progressBar) {
    progressBar.style.width = `${progressValue}%`;
  }
  if (progressText) {
    progressText.textContent = customText || `扫描进度：${progressValue}%`;
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
        throw new Error("自定义端口模式下，请填写端口范围。");
      }
      fullPortScan = false;
      portRange = customPorts;
    }
  }

  const tcpScanEnabled = portScanEnabled ? document.getElementById("tcpScan").checked : false;
  const udpScanEnabled = portScanEnabled ? document.getElementById("udpScan").checked : false;
  if (portScanEnabled && !tcpScanEnabled && !udpScanEnabled) {
    throw new Error("请至少启用一种协议：TCP 或 UDP。");
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
    setProgress(100, "扫描进度：100%（已完成）");
    if (data.result) {
      renderReport(data.result);
    } else {
      renderNoBackendState("Scan completed but no result returned.");
    }
    logLine("Scan completed.", "ok");
    return;
  }

  if (status === "canceled") {
    clearPollTimer();
    setRunningState(false);
    currentJobId = null;
    setHudTaskState("CANCELED");
    setProgress(100, "扫描进度：100%（已停止）");
    if (data.result) {
      renderReport(data.result);
    } else {
      renderNoBackendState("Scan canceled.");
    }
    logLine("Scan canceled.", "error");
    return;
  }

  if (status === "failed") {
    clearPollTimer();
    setRunningState(false);
    currentJobId = null;
    setHudTaskState("FAILED");
    setHudThreat("ELEVATED");
    setProgress(100, "扫描进度：100%（失败）");
    renderNoBackendState(`Scan failed: ${data.error || "unknown error"}`);
    logLine(`Scan failed: ${data.error || "unknown error"}`, "error");
    return;
  }

  // running / queued / stopping
  if (status === "stopping") {
    setHudTaskState("STOPPING");
    setProgress(Math.max(progressValue, 95), "扫描进度：停止中...");
  } else if (status === "queued") {
    setHudTaskState("QUEUED");
    setProgress(Math.max(progressValue, 5), "扫描进度：排队中...");
  } else {
    setHudTaskState("RUNNING");
    setProgress(Math.min(95, progressValue + 3));
  }
  renderNoBackendState(`Scan status: ${status} (job: ${jobId})`);
}

async function runScan(event) {
  event.preventDefault();
  if (isRunning) {
    logLine("已有扫描任务正在执行，请先停止。", "error");
    return;
  }

  let payload;
  try {
    payload = buildPayload();
  } catch (error) {
    logLine(error.message || "扫描参数无效。", "error");
    return;
  }

  if (!payload.target) {
    logLine("目标不能为空。", "error");
    return;
  }
  if (payload.vt_scan && !payload.vt_api_key) {
    logLine("已开启 VirusTotal，请先填写你自己的 API Key。", "error");
    return;
  }

  logLine(`开始扫描目标：${payload.target}`);
  updateHudTargetLock();
  setHudTaskState("LAUNCH");
  setHudThreat("MEDIUM");
  const apiUrl = getApiUrl();

  if (!apiUrl) {
    logLine("未填写后端 API 地址。", "error");
    renderNoBackendState("后端 API 未连接，请先填写 API 地址。");
    return;
  }

  try {
    latestReport = null;
    latestReportSource = null;
    setProgress(3, "扫描进度：启动中...");
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
    renderNoBackendState(`扫描任务已创建，任务ID：${jobId}`);
    logLine(`任务已创建：${jobId}`, "ok");

    clearPollTimer();
    pollTimer = setInterval(() => {
      pollJobStatus(apiUrl, jobId).catch((error) => {
        clearPollTimer();
        setRunningState(false);
        currentJobId = null;
        setHudTaskState("ERROR");
        setHudThreat("ELEVATED");
        setProgress(0, "扫描进度：0%");
        renderNoBackendState("轮询任务状态失败。");
        logLine(`轮询失败（${error.message}）。`, "error");
      });
    }, 1000);
  } catch (error) {
    setHudTaskState("ERROR");
    setHudThreat("ELEVATED");
    setProgress(0, "扫描进度：0%");
    logLine(`API 请求失败（${error.message}）。`, "error");
    renderNoBackendState("后端请求失败，请检查 API 地址和后端状态。");
  }
}

async function stopScan() {
  const apiUrl = getApiUrl();
  if (!isRunning || !currentJobId) {
    logLine("当前没有可停止的扫描任务。", "error");
    return;
  }
  if (!apiUrl) {
    logLine("后端 API 地址为空。", "error");
    return;
  }

  const stopUrl = `${normalizeApiUrl(apiUrl)}/${currentJobId}/stop`;
  try {
    const response = await fetch(stopUrl, { method: "POST" });
    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }
    setProgress(Math.max(progressValue, 95), "扫描进度：停止中...");
    logLine("已发送停止信号。", "ok");
    renderNoBackendState(`正在停止任务：${currentJobId} ...`);
  } catch (error) {
    logLine(`停止失败（${error.message}）。`, "error");
  }
}

function downloadResult() {
  if (!latestReport || latestReportSource !== "scan") {
    logLine("没有可下载的真实扫描结果。请先完成一次扫描。", "error");
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
  logLine("结果下载完成。", "ok");
}

function clearCurrentScan() {
  if (isRunning) {
    logLine("请先停止当前扫描，再执行清空。", "error");
    return;
  }
  latestReport = null;
  latestReportSource = null;
  currentJobId = null;
  rawOutput.textContent = "";
  summary.innerHTML = "";
  const item = document.createElement("div");
  item.className = "summary-item";
  item.textContent = "当前扫描结果已清空。";
  summary.appendChild(item);
  appendDockRows(portsOutput, [], "Open port intelligence will appear here.");
  appendDockRows(techOutput, [], "Technology and service risk insights will appear here.");
  terminal.innerHTML = "";
  if (liveEvents) {
    liveEvents.innerHTML = '<div class="event-line event-line--muted">[standby] console ready. awaiting mission lock.</div>';
  }
  setProgress(0, "扫描进度：0%");
  if (fileInput) {
    fileInput.value = "";
  }

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
  logLine("已清空当前扫描内容，并关闭全部模块开关。", "ok");
}

function handleFileUpload(event) {
  const file = event.target.files?.[0];
  if (!file) {
    return;
  }

  const reader = new FileReader();
  reader.onload = () => {
    try {
      const data = JSON.parse(String(reader.result));
      logLine(`Loaded ${file.name}.`, "ok");
      renderReport(data, "file");
      setRunningState(false);
      setHudTaskState("REPORT");
      setProgress(100, "扫描进度：100%（已加载）");
    } catch (_error) {
      logLine("JSON 文件格式无效。", "error");
    }
  };
  reader.readAsText(file, "utf-8");
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
initDockTabs();
initCyberNumberSteppers();
initMatrixRain();
initVoidRainPanel();
initHudRuntime();
setRunningState(false);
setProgress(0, "扫描进度：0%");
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
if (perfLiteEnabled) {
  logLine("已启用流畅模式（自动降特效渲染）。", "ok");
}
logLine(`界面已就绪。API: ${getApiUrl()}`, "ok");
