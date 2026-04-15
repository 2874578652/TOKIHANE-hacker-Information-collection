const refs = {
  bootOverlay: document.getElementById("bootOverlay"),
  bootFeed: document.getElementById("bootFeed"),
  navSignal: document.getElementById("navSignal"),
  navClock: document.getElementById("navClock"),
  heroFeed: document.getElementById("heroFeed"),
  heroThreatLabel: document.getElementById("heroThreatLabel"),
  heroGateStatus: document.getElementById("heroGateStatus"),
  entryTone: document.getElementById("entryTone"),
  heroVector: document.getElementById("heroVector"),
  heroCoreState: document.getElementById("heroCoreState"),
  heroCoreNote: document.getElementById("heroCoreNote"),
  heroPacket: document.getElementById("heroPacket"),
  heroNodeSync: document.getElementById("heroNodeSync"),
  heroPulse: document.getElementById("heroPulse"),
  heroPulseMirror: document.getElementById("heroPulseMirror"),
  snapshotThreat: document.getElementById("snapshotThreat"),
  snapshotNodes: document.getElementById("snapshotNodes"),
  snapshotSignal: document.getElementById("snapshotSignal"),
  snapshotModules: document.getElementById("snapshotModules"),
  transitionState: document.getElementById("transitionState"),
  transitionCode: document.getElementById("transitionCode"),
  portalMissionCount: document.getElementById("portalMissionCount"),
  portalSuccessRate: document.getElementById("portalSuccessRate"),
  portalRiskHits: document.getElementById("portalRiskHits"),
  portalCoverage: document.getElementById("portalCoverage"),
  portalJobList: document.getElementById("portalJobList"),
  reportTarget: document.getElementById("reportTarget"),
  reportSummary: document.getElementById("reportSummary"),
  reportPorts: document.getElementById("reportPorts"),
  reportRisks: document.getElementById("reportRisks"),
  reportTech: document.getElementById("reportTech"),
  reportEndpoints: document.getElementById("reportEndpoints"),
  reportModules: document.getElementById("reportModules"),
};

const TRANSITION_KEY = "tokihane-page-transition";
const landingDigitSelectors = [
  ".gate-nav",
  ".hero-stage",
  ".value-card",
  ".capability-band",
  ".workflow-step",
  ".snapshot-feature",
  ".snapshot-card",
  ".archive-panel",
  ".trust-card",
  ".transition-panel",
  ".nav-chip",
  ".meta-strip",
  ".hero-feed",
  ".readout-card",
  ".site-footer",
];
const digitCharacters = "00112233445566778899";

const bootMessages = [
  "[boot] mounting official portal entry layer...",
  "[boot] syncing scan task fabric and evidence model...",
  "[boot] probing api, report archive, and job ledger...",
  "[boot] staging recon modules and risk correlation rails...",
  "[boot] command portal is standing by for operator access...",
];

const feedMessages = [
  "portal handshake complete / target intake lane is ready...",
  "dns, whois, tech stack, and service probes are online...",
  "web crawler, js extraction, and directory probe are staged...",
  "risk review rail is waiting for fresh report evidence...",
  "mission ledger is mirroring the latest asynchronous jobs...",
  "operator can transfer into the scan console at any time...",
];

const threatStates = [
  {
    threat: "MONITORED",
    pulse: "LOW",
    tone: "READY",
    gate: "Portal Standing By",
    core: "ENTRY AUTHORIZED",
    note: "将目标接入扫描工作台，即可启动异步侦察与风险分析链路。",
    state: "READY FOR SCAN",
  },
  {
    threat: "REVIEW",
    pulse: "TRACKED",
    tone: "SYNCED",
    gate: "Modules Online",
    core: "SURFACE ENUM",
    note: "平台已同步目标、模块、任务状态与报告模型，等待下一次任务注入。",
    state: "MODULES ONLINE",
  },
  {
    threat: "ELEVATED",
    pulse: "HOT",
    tone: "ACTIVE",
    gate: "Risk Correlation Live",
    core: "EVIDENCE FUSION",
    note: "服务识别、Web 线索、风险匹配与报告归档会在同一条任务链路中闭合。",
    state: "COLLECTION ACTIVE",
  },
];

const vectors = [
  "TARGET GRID / 024.110 / 121.470",
  "TARGET GRID / 031.886 / 117.204",
  "TARGET GRID / 022.543 / 114.057",
  "TARGET GRID / 039.904 / 116.407",
];

const portalState = {
  health: null,
  jobs: [],
  report: null,
};

const fallbackReport = {
  target: {
    input: "portal-sample.target",
  },
  dns: {
    A: ["203.0.113.14"],
    NS: ["ns1.target.net", "ns2.target.net"],
  },
  whois: {
    registrar: "TOKI Registry",
  },
  tech_stack: {
    detected_technologies: ["nginx", "Vue", "Cloudflare", "OpenResty"],
  },
  web_assets: {
    combined_endpoints: ["/", "/api/login", "/api/v1/users", "/admin", "/assets/app.js", "/health"],
  },
  ip_scan: {
    results: {
      "203.0.113.14": {
        tcp: {
          open_port_count: 3,
          open_ports: [
            { port: 80, service: "http" },
            { port: 443, service: "https" },
            { port: 8443, service: "https-alt" },
          ],
        },
        udp: {
          open_port_count: 1,
          open_ports: [{ port: 53, service: "domain" }],
        },
      },
    },
  },
  certificate_transparency: {
    total_records: 12,
  },
  passive_dns: {
    sources: {
      sample: true,
    },
  },
  asn_network: {
    records: [{ ip: "203.0.113.14", asn: "AS64501" }],
  },
  service_risk: {
    cve_lookup: {
      matches: [
        {
          cves: [{ id: "CVE-2024-0001" }, { id: "CVE-2024-0009" }],
        },
      ],
    },
    weak_checks: {
      per_ip: {
        "203.0.113.14": {
          ftp_anonymous_check: {
            finding_count: 0,
          },
          tls_cipher_check: {
            finding_count: 1,
          },
        },
      },
    },
  },
};

let feedIndex = 0;
let threatIndex = 0;
let packetValue = 682;
let nodeValue = 128;
let signalValue = 99.1;
let moduleValue = 8;
let isPageNavigating = false;

function clamp(value, min, max) {
  return Math.max(min, Math.min(max, value));
}

function safeArray(value) {
  return Array.isArray(value) ? value : [];
}

function prefersReducedMotion() {
  return window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
}

function shouldUsePerfLite() {
  const reduceMotion = prefersReducedMotion();
  const cores = Number(navigator.hardwareConcurrency || 8);
  const memory = Number(navigator.deviceMemory || 8);
  const coarsePointer = window.matchMedia && window.matchMedia("(pointer: coarse)").matches;
  return reduceMotion || coarsePointer || cores <= 4 || memory <= 4;
}

function applyPerformancePreset() {
  document.documentElement.classList.toggle("perf-lite", shouldUsePerfLite());
}

function pickRandomDigit() {
  return digitCharacters[Math.floor(Math.random() * digitCharacters.length)] || "0";
}

function getDigitDensity() {
  if (document.documentElement.classList.contains("perf-lite")) {
    return 80;
  }
  return prefersReducedMotion() ? 48 : 164;
}

function buildDigitCloud(id, className, selectors, totalCount = 120) {
  const existing = document.getElementById(id);
  if (existing) {
    existing.remove();
  }

  const container = document.createElement("div");
  container.id = id;
  container.className = className;

  const targets = selectors
    .flatMap((selector) => Array.from(document.querySelectorAll(selector)))
    .filter((element) => {
      const rect = element.getBoundingClientRect();
      return rect.width > 24 && rect.height > 24;
    });

  const fallbackTargets = targets.length ? targets : [document.body];
  const areas = fallbackTargets.map((element) => {
    const rect = element.getBoundingClientRect();
    return Math.max(rect.width * rect.height, 1);
  });
  const totalArea = areas.reduce((sum, value) => sum + value, 0);

  fallbackTargets.forEach((element, index) => {
    const rect = element.getBoundingClientRect();
    const ratio = totalArea > 0 ? areas[index] / totalArea : 1 / fallbackTargets.length;
    const count = Math.max(4, Math.round(totalCount * ratio));

    for (let offset = 0; offset < count; offset += 1) {
      const char = document.createElement("span");
      const size = 11 + Math.random() * 13;
      char.className = `${className}__char`;
      char.textContent = pickRandomDigit();
      char.style.left = `${rect.left + Math.random() * rect.width}px`;
      char.style.top = `${rect.top + Math.random() * rect.height}px`;
      char.style.fontSize = `${size}px`;
      char.style.setProperty("--delay", `${Math.random() * 260}ms`);
      char.style.setProperty("--drift-x", `${(Math.random() - 0.5) * 240}px`);
      char.style.setProperty("--drift-y", `${-90 - Math.random() * 220}px`);
      char.style.setProperty("--from-x", `${(Math.random() - 0.5) * window.innerWidth * 0.62}px`);
      char.style.setProperty("--from-y", `${(Math.random() - 0.5) * window.innerHeight * 0.62}px`);
      char.style.setProperty("--start-scale", `${0.36 + Math.random() * 1.1}`);
      char.style.setProperty("--end-scale", `${0.72 + Math.random() * 1.08}`);
      char.style.setProperty("--rotate", `${(Math.random() - 0.5) * 240}deg`);
      container.appendChild(char);
    }
  });

  document.body.appendChild(container);
  return container;
}

function clearDigitCloud(id) {
  document.getElementById(id)?.remove();
}

function initReturnAssembly() {
  if (!document.documentElement.classList.contains("page-enter-landing")) {
    return;
  }

  try {
    window.sessionStorage.removeItem(TRANSITION_KEY);
  } catch (_error) {}

  buildDigitCloud("landingDigitCloud", "landing-digit-cloud", landingDigitSelectors, getDigitDensity());
  window.requestAnimationFrame(() => {
    document.body.classList.add("is-arriving-assembled");
  });

  window.setTimeout(() => {
    document.body.classList.remove("is-arriving-assembled");
    document.documentElement.classList.remove("page-enter-landing");
    clearDigitCloud("landingDigitCloud");
  }, prefersReducedMotion() ? 420 : 1480);
}

function beginConsoleTransition(href) {
  if (!href || isPageNavigating) {
    return;
  }

  isPageNavigating = true;

  try {
    window.sessionStorage.setItem(TRANSITION_KEY, "landing-to-console");
  } catch (_error) {}

  buildDigitCloud("landingDigitCloud", "landing-digit-cloud", landingDigitSelectors, getDigitDensity());
  document.body.classList.add("is-entering", "sweep-active", "is-digitizing-out");

  window.setTimeout(() => {
    window.location.href = href;
  }, prefersReducedMotion() ? 260 : 980);
}

function formatClock(date) {
  return date.toLocaleTimeString("zh-CN", {
    hour12: false,
    timeZone: "Asia/Shanghai",
  });
}

function formatDateTime(value) {
  if (!value) return "--";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return String(value);
  return new Intl.DateTimeFormat("zh-CN", {
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
  }).format(date);
}

function appendFeedLine(container, text, limit = 4) {
  if (!container) {
    return;
  }
  const line = document.createElement("div");
  line.textContent = text;
  container.prepend(line);
  while (container.children.length > limit) {
    container.removeChild(container.lastElementChild);
  }
}

function updateClock() {
  if (refs.navClock) {
    refs.navClock.textContent = formatClock(new Date());
  }
}

function updateLiveMetrics() {
  signalValue = clamp(signalValue + (Math.random() * 0.5 - 0.25), 97.8, 99.9);
  packetValue = clamp(packetValue + Math.floor(Math.random() * 42 - 21), 620, 860);
  nodeValue = clamp(nodeValue + Math.floor(Math.random() * 3 - 1), 124, 128);
  moduleValue = clamp(moduleValue + Math.floor(Math.random() * 3 - 1), 6, 10);

  if (refs.navSignal) {
    refs.navSignal.textContent = `${signalValue.toFixed(1)}%`;
  }
  if (refs.heroPacket) {
    refs.heroPacket.textContent = `${packetValue} KB/S`;
  }
  if (refs.heroNodeSync) {
    refs.heroNodeSync.textContent = `${nodeValue} / 128`;
  }
  if (refs.snapshotNodes) {
    refs.snapshotNodes.textContent = String(nodeValue);
  }
  if (refs.snapshotSignal) {
    refs.snapshotSignal.textContent = `${signalValue.toFixed(1)}%`;
  }
  if (refs.snapshotModules) {
    refs.snapshotModules.textContent = String(moduleValue).padStart(2, "0");
  }
}

function updateThreatState() {
  const state = threatStates[threatIndex % threatStates.length];
  const vector = vectors[threatIndex % vectors.length];

  if (refs.heroThreatLabel) {
    refs.heroThreatLabel.textContent = state.threat;
  }
  if (refs.heroPulse) {
    refs.heroPulse.textContent = state.pulse;
  }
  if (refs.heroPulseMirror) {
    refs.heroPulseMirror.textContent = state.pulse;
  }
  if (refs.entryTone) {
    refs.entryTone.textContent = state.tone;
  }
  if (refs.heroGateStatus) {
    refs.heroGateStatus.textContent = state.gate;
  }
  if (refs.heroCoreState) {
    refs.heroCoreState.textContent = state.core;
  }
  if (refs.heroCoreNote) {
    refs.heroCoreNote.textContent = state.note;
  }
  if (refs.transitionState) {
    refs.transitionState.textContent = state.state;
  }
  if (refs.snapshotThreat) {
    refs.snapshotThreat.textContent = state.threat;
  }
  if (refs.heroVector) {
    refs.heroVector.textContent = vector;
  }
  if (refs.transitionCode) {
    refs.transitionCode.textContent = `TKH-${String(nodeValue).padStart(3, "0")}-${state.threat}`;
  }

  threatIndex += 1;
}

function cycleFeed() {
  const message = feedMessages[feedIndex % feedMessages.length];
  appendFeedLine(refs.heroFeed, message, 4);
  feedIndex += 1;
}

function finishBoot() {
  document.body.classList.add("is-loaded");
}

function initBootSequence() {
  if (document.documentElement.classList.contains("page-enter-landing")) {
    finishBoot();
    return;
  }

  if (!refs.bootOverlay || !refs.bootFeed) {
    finishBoot();
    return;
  }

  let index = 0;
  const intervalId = window.setInterval(() => {
    if (index >= bootMessages.length) {
      window.clearInterval(intervalId);
      window.setTimeout(finishBoot, 420);
      return;
    }
    appendFeedLine(refs.bootFeed, bootMessages[index], 5);
    index += 1;
  }, 220);
}

function initLaserRain() {
  if (document.documentElement.classList.contains("perf-lite")) {
    return;
  }

  const canvas = document.getElementById("laserRain");
  if (!canvas) {
    return;
  }

  const ctx = canvas.getContext("2d");
  if (!ctx) {
    return;
  }

  let width = 0;
  let height = 0;
  let columns = [];

  function resize() {
    width = window.innerWidth;
    height = window.innerHeight;
    canvas.width = width;
    canvas.height = height;
    const count = Math.max(10, Math.floor(width / 120));
    columns = Array.from({ length: count }, (_, index) => ({
      x: index * (width / count),
      offset: Math.random() * height,
      speed: 40 + Math.random() * 50,
    }));
  }

  function draw() {
    ctx.clearRect(0, 0, width, height);
    columns.forEach((column) => {
      column.offset = (column.offset + column.speed / 60) % (height + 120);
      const gradient = ctx.createLinearGradient(column.x, column.offset - 120, column.x, column.offset);
      gradient.addColorStop(0, "rgba(57, 210, 255, 0)");
      gradient.addColorStop(1, "rgba(97, 255, 228, 0.28)");
      ctx.strokeStyle = gradient;
      ctx.lineWidth = 1;
      ctx.beginPath();
      ctx.moveTo(column.x, column.offset - 120);
      ctx.lineTo(column.x, column.offset);
      ctx.stroke();
    });
  }

  resize();
  window.addEventListener("resize", resize, { passive: true });

  const fps = 24;
  const frameDuration = 1000 / fps;
  let lastTime = 0;

  function loop(time) {
    if (!document.hidden && time - lastTime >= frameDuration) {
      draw();
      lastTime = time;
    }
    window.requestAnimationFrame(loop);
  }

  window.requestAnimationFrame(loop);
}

function initParticleField() {
  if (document.documentElement.classList.contains("perf-lite")) {
    return;
  }

  const canvas = document.getElementById("particleField");
  if (!canvas) {
    return;
  }

  const ctx = canvas.getContext("2d");
  if (!ctx) {
    return;
  }

  let width = 0;
  let height = 0;
  let particles = [];

  function resize() {
    width = window.innerWidth;
    height = window.innerHeight;
    canvas.width = width;
    canvas.height = height;
    const count = document.documentElement.classList.contains("perf-lite") ? 16 : 30;
    particles = Array.from({ length: count }, () => ({
      x: Math.random() * width,
      y: Math.random() * height,
      size: 1 + Math.random() * 2,
      speedY: 0.12 + Math.random() * 0.34,
      alpha: 0.08 + Math.random() * 0.18,
    }));
  }

  function draw() {
    ctx.clearRect(0, 0, width, height);
    particles.forEach((particle) => {
      particle.y += particle.speedY;
      if (particle.y > height + 10) {
        particle.y = -10;
        particle.x = Math.random() * width;
      }

      ctx.beginPath();
      ctx.fillStyle = `rgba(97, 255, 228, ${particle.alpha})`;
      ctx.arc(particle.x, particle.y, particle.size, 0, Math.PI * 2);
      ctx.fill();
    });
  }

  resize();
  window.addEventListener("resize", resize, { passive: true });

  const fps = 18;
  const frameDuration = 1000 / fps;
  let lastTime = 0;

  function loop(time) {
    if (!document.hidden && time - lastTime >= frameDuration) {
      draw();
      lastTime = time;
    }
    window.requestAnimationFrame(loop);
  }

  window.requestAnimationFrame(loop);
}

function initRevealObserver() {
  const items = Array.from(document.querySelectorAll(".reveal"));
  if (!items.length) {
    return;
  }

  if (!("IntersectionObserver" in window) || prefersReducedMotion()) {
    items.forEach((item) => item.classList.add("is-visible"));
    return;
  }

  const observer = new IntersectionObserver(
    (entries) => {
      entries.forEach((entry) => {
        if (!entry.isIntersecting) return;
        entry.target.classList.add("is-visible");
        observer.unobserve(entry.target);
      });
    },
    {
      rootMargin: "0px 0px -10% 0px",
      threshold: 0.14,
    }
  );

  items.forEach((item) => observer.observe(item));
}

function initNavState() {
  const sync = () => {
    document.body.classList.toggle("is-nav-scrolled", window.scrollY > 18);
  };

  sync();
  window.addEventListener("scroll", sync, { passive: true });
}

function initPointerGlow() {
  if (document.documentElement.classList.contains("perf-lite")) {
    return;
  }

  const root = document.documentElement;
  let idleTimer = 0;

  const setPointer = (x, y) => {
    root.style.setProperty("--landing-cursor-x", `${x}px`);
    root.style.setProperty("--landing-cursor-y", `${y}px`);
    document.body.classList.remove("is-pointer-idle");
    if (idleTimer) {
      window.clearTimeout(idleTimer);
    }
    idleTimer = window.setTimeout(() => {
      document.body.classList.add("is-pointer-idle");
    }, 1800);
  };

  setPointer(window.innerWidth * 0.5, window.innerHeight * 0.42);

  window.addEventListener(
    "pointermove",
    (event) => {
      if (event.pointerType === "touch") return;
      setPointer(event.clientX, event.clientY);
    },
    { passive: true }
  );
}

function inferApiRoot() {
  const { protocol, hostname, origin } = window.location;
  if (protocol === "file:" || hostname === "localhost" || hostname === "127.0.0.1") {
    return "http://127.0.0.1:8000";
  }
  return origin;
}

function getHealthUrl() {
  return `${inferApiRoot()}/health`;
}

function getJobsUrl() {
  return `${inferApiRoot()}/api/jobs`;
}

function getSampleReportCandidates() {
  return ["./report.json", "../report.json", "/report.json"];
}

function getStatusTone(status) {
  if (status === "completed") return "success";
  if (status === "failed" || status === "canceled") return "danger";
  if (status === "running" || status === "stopping") return "running";
  if (status === "queued") return "warning";
  return "neutral";
}

function fetchJson(url) {
  return fetch(url).then(async (response) => {
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

function computeCoverage(report) {
  if (!report) return "--";
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
  return `${filled}/${modules.length}`;
}

function getModuleStatus(module) {
  if (!module) return { tone: "neutral", label: "无数据" };
  if (module.error) return { tone: "danger", label: "失败" };
  if (module.canceled) return { tone: "warning", label: "已取消" };
  if (module.enabled === false) return { tone: "neutral", label: "未启用" };
  if (module.scan_performed === false) return { tone: "warning", label: "已跳过" };
  return { tone: "success", label: "完成" };
}

function getFallbackJobs() {
  return [
    {
      job_id: "fallback-001",
      target: { input: "alpha.example.com" },
      status: "completed",
      created_at: new Date(Date.now() - 1000 * 60 * 43).toISOString(),
      finished_at: new Date(Date.now() - 1000 * 60 * 37).toISOString(),
      result: portalState.report,
    },
    {
      job_id: "fallback-002",
      target: { input: "203.0.113.14" },
      status: "running",
      created_at: new Date(Date.now() - 1000 * 60 * 12).toISOString(),
    },
    {
      job_id: "fallback-003",
      target: { input: "gateway.target.tld" },
      status: "queued",
      created_at: new Date(Date.now() - 1000 * 60 * 4).toISOString(),
    },
  ];
}

function renderStatusPill(status) {
  const tone = getStatusTone(status);
  return `<span class="ops-ledger__status" data-tone="${tone}">${status || "idle"}</span>`;
}

function renderJobItem(job) {
  const target = job?.result?.target?.input || job?.target?.input || job?.target || job?.job_id || "未知目标";
  const createdAt = formatDateTime(job?.created_at || job?.finished_at);
  const hint =
    job?.status === "completed"
      ? "evidence package available"
      : job?.status === "running"
        ? "modules are collecting"
        : job?.status === "queued"
          ? "waiting for dispatch"
          : "status mirrored from task fabric";

  return `
    <article class="ops-ledger__item">
      <div class="ops-ledger__meta">
        <div>
          <strong class="ops-ledger__target">${target}</strong>
          <span class="ops-ledger__time">${createdAt}</span>
        </div>
        ${renderStatusPill(job?.status)}
      </div>
      <div class="ops-ledger__foot">
        <span>${hint}</span>
        <a href="./console.html">进入工作台</a>
      </div>
    </article>
  `;
}

function renderOpsLedger(jobs) {
  if (!refs.portalJobList) {
    return;
  }

  const sourceJobs = jobs.length ? jobs : getFallbackJobs();
  refs.portalJobList.innerHTML = sourceJobs.slice(0, 4).map(renderJobItem).join("");
}

function renderReportModules(report) {
  if (!refs.reportModules) {
    return;
  }

  if (!report) {
    refs.reportModules.innerHTML = `<span class="report-module">waiting for report feed...</span>`;
    return;
  }

  const modules = [
    ["DNS", report.dns],
    ["WHOIS", report.whois],
    ["Tech", report.tech_stack],
    ["CT", report.certificate_transparency],
    ["Passive DNS", report.passive_dns],
    ["ASN", report.asn_network],
    ["Web", report.web_assets],
    ["IP Scan", report.ip_scan],
    ["Risk", report.service_risk],
  ];

  refs.reportModules.innerHTML = modules
    .map(([label, module]) => {
      const status = getModuleStatus(module);
      return `<span class="report-module" data-tone="${status.tone}">${label} / ${status.label}</span>`;
    })
    .join("");
}

function pickBestReport(jobs, sampleReport) {
  const completedJob = jobs.find((job) => job?.status === "completed" && job?.result);
  return completedJob?.result || sampleReport || null;
}

function updatePortalOverview() {
  const jobs = portalState.jobs.length ? portalState.jobs : getFallbackJobs();
  const report = pickBestReport(jobs, portalState.report);

  const recentCount = jobs.length;
  const completedCount = jobs.filter((job) => job?.status === "completed").length;
  const resolvableCount = jobs.filter((job) => ["completed", "failed", "canceled"].includes(job?.status)).length;
  const successRate = resolvableCount > 0 ? Math.round((completedCount / resolvableCount) * 100) : 100;

  if (refs.portalMissionCount) {
    refs.portalMissionCount.textContent = String(recentCount || jobs.length).padStart(2, "0");
  }
  if (refs.portalSuccessRate) {
    refs.portalSuccessRate.textContent = `${successRate}%`;
  }
  if (refs.portalRiskHits) {
    refs.portalRiskHits.textContent = report ? String(computeRiskCount(report)).padStart(2, "0") : "--";
  }
  if (refs.portalCoverage) {
    refs.portalCoverage.textContent = computeCoverage(report);
  }

  if (refs.reportTarget) {
    refs.reportTarget.textContent = report?.target?.input || "等待载入样例报告";
  }
  if (refs.reportSummary) {
    refs.reportSummary.textContent = report
      ? `报告聚合了 ${safeArray(report.tech_stack?.detected_technologies).length} 个技术指纹、${computeOpenPorts(report)} 个开放端口与 ${safeArray(report.web_assets?.combined_endpoints).length} 条 Web 线索。`
      : "门户会尝试读取 `report.json`，用于展示平台的证据模型与模块输出结构。";
  }
  if (refs.reportPorts) {
    refs.reportPorts.textContent = report ? String(computeOpenPorts(report)) : "-";
  }
  if (refs.reportRisks) {
    refs.reportRisks.textContent = report ? String(computeRiskCount(report)) : "-";
  }
  if (refs.reportTech) {
    refs.reportTech.textContent = report ? String(safeArray(report.tech_stack?.detected_technologies).length) : "-";
  }
  if (refs.reportEndpoints) {
    refs.reportEndpoints.textContent = report ? String(safeArray(report.web_assets?.combined_endpoints).length) : "-";
  }

  renderReportModules(report);
  renderOpsLedger(jobs);
}

async function readHealth() {
  try {
    return await fetchJson(getHealthUrl());
  } catch (_error) {
    return null;
  }
}

async function readJobs() {
  try {
    const payload = await fetchJson(getJobsUrl());
    return safeArray(payload?.jobs);
  } catch (_error) {
    return [];
  }
}

async function readSampleReport() {
  for (const url of getSampleReportCandidates()) {
    try {
      return await fetchJson(url);
    } catch (_error) {
      continue;
    }
  }
  return fallbackReport;
}

async function refreshPortalData() {
  const [health, jobs, report] = await Promise.all([readHealth(), readJobs(), readSampleReport()]);
  portalState.health = health;
  portalState.jobs = jobs;
  portalState.report = report;
  updatePortalOverview();
}

function initEntryLinks() {
  Array.from(document.querySelectorAll('a[href="./console.html"]')).forEach((link) => {
    link.addEventListener("click", (event) => {
      const href = link.getAttribute("href");
      if (!href) {
        return;
      }
      event.preventDefault();
      beginConsoleTransition(href);
    });
  });
}

function redirectLegacyConsoleRoute() {
  const params = new URLSearchParams(window.location.search);
  if (params.get("view") !== "console") {
    return false;
  }
  window.location.replace("./console.html#workspace");
  return true;
}

function initPortal() {
  if (redirectLegacyConsoleRoute()) {
    return;
  }

  applyPerformancePreset();
  initReturnAssembly();
  initBootSequence();
  initRevealObserver();
  initNavState();
  initPointerGlow();
  updateClock();
  updateLiveMetrics();
  updateThreatState();
  cycleFeed();
  initLaserRain();
  initParticleField();
  initEntryLinks();
  refreshPortalData();

  window.setInterval(updateClock, 1000);
  window.setInterval(updateLiveMetrics, 1400);
  window.setInterval(updateThreatState, 3200);
  window.setInterval(cycleFeed, 2600);
  window.setInterval(refreshPortalData, 20000);
}

initPortal();
