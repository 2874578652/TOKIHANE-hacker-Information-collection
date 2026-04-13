const refs = {
  app: document.querySelector(".neo-app"),
  navTargetInput: document.getElementById("navTargetInput"),
  heroTargetInput: document.getElementById("heroTargetInput"),
  consoleTargetInput: document.getElementById("consoleTargetInput"),
  navLaunchBtn: document.getElementById("navLaunchBtn"),
  heroScanButton: document.getElementById("heroScanButton"),
  demoSampleBtn: document.getElementById("demoSampleBtn"),
  heroTargetEcho: document.getElementById("heroTargetEcho"),
  heroStatusLine: document.getElementById("heroStatusLine"),
  heroFeed: document.getElementById("heroFeed"),
  heroFeedState: document.getElementById("heroFeedState"),
  heroSignalIntegrity: document.getElementById("heroSignalIntegrity"),
  heroThreatPosture: document.getElementById("heroThreatPosture"),
  heroNodeStatus: document.getElementById("heroNodeStatus"),
  heroAssetFlow: document.getElementById("heroAssetFlow"),
  heroCollectorCount: document.getElementById("heroCollectorCount"),
  heroThreatLevel: document.getElementById("heroThreatLevel"),
  mobileMenuToggle: document.getElementById("mobileMenuToggle"),
  mobileDrawer: document.getElementById("mobileDrawer"),
  viewTabs: Array.from(document.querySelectorAll("[data-view-target]")),
  workspaceViews: Array.from(document.querySelectorAll(".workspace-view")),
  resultTabs: Array.from(document.querySelectorAll("[data-result-tab]")),
  resultPanels: Array.from(document.querySelectorAll("[data-result-panel]")),
  statScansToday: document.getElementById("statScansToday"),
  statTargetsTracked: document.getElementById("statTargetsTracked"),
  statVulnsFound: document.getElementById("statVulnsFound"),
  statActiveNodes: document.getElementById("statActiveNodes"),
  recentScansBody: document.getElementById("recentScansBody"),
  mapPins: document.getElementById("mapPins"),
  mapLocationCount: document.getElementById("mapLocationCount"),
  intelFeed: document.getElementById("intelFeed"),
  reportFileInput: document.getElementById("reportFileInput"),
  importReportBtn: document.getElementById("importReportBtn"),
  reportMeta: document.getElementById("reportMeta"),
  reportMetaName: document.getElementById("reportMetaName"),
  consoleStartBtn: document.getElementById("consoleStartBtn"),
  consoleStopBtn: document.getElementById("consoleStopBtn"),
  demoModeBtn: document.getElementById("demoModeBtn"),
  clearConsoleLogBtn: document.getElementById("clearConsoleLogBtn"),
  scanLog: document.getElementById("scanLog"),
  consoleStatusChip: document.getElementById("consoleStatusChip"),
  consoleTargetChip: document.getElementById("consoleTargetChip"),
  consoleThreatChip: document.getElementById("consoleThreatChip"),
  statusTransport: document.getElementById("statusTransport"),
  statusMode: document.getElementById("statusMode"),
  statusThreat: document.getElementById("statusThreat"),
  statusNodes: document.getElementById("statusNodes"),
  scanProgressBar: document.getElementById("scanProgressBar"),
  scanProgressText: document.getElementById("scanProgressText"),
  scanRuntimeText: document.getElementById("scanRuntimeText"),
  apiUrlInput: document.getElementById("apiUrlInput"),
  timeoutInput: document.getElementById("timeoutInput"),
  portTimeoutInput: document.getElementById("portTimeoutInput"),
  portModeInput: document.getElementById("portModeInput"),
  customPortsField: document.getElementById("customPortsField"),
  customPortsInput: document.getElementById("customPortsInput"),
  tcpEnabledInput: document.getElementById("tcpEnabledInput"),
  udpEnabledInput: document.getElementById("udpEnabledInput"),
  webCrawlerInput: document.getElementById("webCrawlerInput"),
  jsExtractInput: document.getElementById("jsExtractInput"),
  vtApiKeyInput: document.getElementById("vtApiKeyInput"),
  cidrTargetsInput: document.getElementById("cidrTargetsInput"),
  moduleCountChip: document.getElementById("moduleCountChip"),
  resultTargetKpi: document.getElementById("resultTargetKpi"),
  resultStatusKpi: document.getElementById("resultStatusKpi"),
  resultOpenPortsKpi: document.getElementById("resultOpenPortsKpi"),
  resultTechKpi: document.getElementById("resultTechKpi"),
  resultThreatScoreKpi: document.getElementById("resultThreatScoreKpi"),
  resultSourceKpi: document.getElementById("resultSourceKpi"),
  missionDigest: document.getElementById("missionDigest"),
  signalSynopsis: document.getElementById("signalSynopsis"),
  terminalHighlights: document.getElementById("terminalHighlights"),
  dnsTableBody: document.getElementById("dnsTableBody"),
  whoisTableBody: document.getElementById("whoisTableBody"),
  techChipList: document.getElementById("techChipList"),
  resolvedTargetsList: document.getElementById("resolvedTargetsList"),
  networkCanvas: document.getElementById("networkCanvas"),
  nodeLegend: document.getElementById("nodeLegend"),
  rerenderGraphBtn: document.getElementById("rerenderGraphBtn"),
  vulnCards: document.getElementById("vulnCards"),
  rawJsonView: document.getElementById("rawJsonView"),
  downloadReportBtn: document.getElementById("downloadReportBtn"),
  darkWebExportBtn: document.getElementById("darkWebExportBtn"),
  terminalFab: document.getElementById("terminalFab"),
  terminalOverlay: document.getElementById("terminalOverlay"),
  terminalCloseBtn: document.getElementById("terminalCloseBtn"),
  terminalOverlayLog: document.getElementById("terminalOverlayLog"),
  terminalCommandForm: document.getElementById("terminalCommandForm"),
  terminalCommandInput: document.getElementById("terminalCommandInput"),
  scanOverlay: document.getElementById("scanOverlay"),
  scanOverlayTitle: document.getElementById("scanOverlayTitle"),
  scanOverlayProgressBar: document.getElementById("scanOverlayProgressBar"),
  scanOverlayProgressText: document.getElementById("scanOverlayProgressText"),
  scanOverlayStatusText: document.getElementById("scanOverlayStatusText"),
  toastStack: document.getElementById("toastStack"),
  matrixRain: document.getElementById("matrixRain"),
  particleField: document.getElementById("particleField"),
  langButtons: Array.from(document.querySelectorAll(".lang-switch__btn")),
  copyButtons: Array.from(document.querySelectorAll("[data-copy-target]")),
};

const moduleDefs = [
  { id: "modulePassive", label: "Passive Recon", payload: "passive_dns_scan", defaultChecked: true },
  { id: "moduleDns", label: "DNS Enumeration", payload: null, defaultChecked: true },
  { id: "moduleSubdomain", label: "Subdomain Brute", payload: "ct_scan", defaultChecked: true },
  { id: "modulePort", label: "Port Scan", payload: "port_scan", defaultChecked: true },
  { id: "moduleWhois", label: "WHOIS + OSINT", payload: null, defaultChecked: true },
  { id: "moduleVuln", label: "Vulnerability Fingerprint", payload: "service_risk_scan", defaultChecked: true },
  { id: "moduleSocial", label: "Social Media Recon", payload: null, defaultChecked: false },
  { id: "moduleWeb", label: "Web Asset Crawl", payload: "web_asset_scan", defaultChecked: true },
  { id: "moduleAsn", label: "ASN Expansion", payload: "asn_scan", defaultChecked: false },
  { id: "moduleThreat", label: "Threat Intel", payload: "vt_scan", defaultChecked: false },
  { id: "modulePrivate", label: "Private Sweep", payload: "allow_private_ip", defaultChecked: false },
].map((item) => ({ ...item, input: document.getElementById(item.id) }));

const heroFeedPool = [
  "ghost collectors are calibrating passive channels...",
  "whois, dns, and header sensors are ready to deploy...",
  "raw export lanes are standing by for exfil package build...",
  "deep packet shadows indicate low-noise reconnaissance lanes...",
  "matrix beacons synced to distant proxy relays and safe exits...",
  "node graph renderer is primed for hostile surface mapping...",
];

const intelFeedPool = [
  { title: "ghost relay", text: "heuristic scanner reports fresh header anomalies on obfuscated infra." },
  { title: "night broker", text: "high-churn dns patterns detected on a known staging domain." },
  { title: "shadow pin", text: "new tls metadata stitched into the reconnaissance evidence graph." },
  { title: "wire jack", text: "cdn edge behavior is masking two suspicious service fingerprints." },
  { title: "dead sector", text: "exposed auth routes are surfacing in passive crawler traces." },
];

const WORLD_POINTS = [
  { label: "Neo-Tokyo", x: "82%", y: "38%" },
  { label: "Night City", x: "18%", y: "43%" },
  { label: "Seoul Grid", x: "77%", y: "34%" },
  { label: "Berlin Relay", x: "51%", y: "30%" },
  { label: "Lagos Ghost Hub", x: "49%", y: "56%" },
  { label: "Sao Flux", x: "31%", y: "71%" },
  { label: "Sydney Rift", x: "84%", y: "74%" },
  { label: "Dubai Veil", x: "59%", y: "42%" },
];

const translations = {
  en: {
    navLaunch: "Prime Console",
    heroScan: "INITIATE SCAN",
    openConsole: "OPEN CONSOLE",
    demoSample: "LOAD GHOST SAMPLE",
    terminal: "Terminal",
    navPlaceholder: "quick target // domain or ip",
    heroPlaceholder: "corp.tld / 8.8.8.8 / https://target.tld / ghost_handle",
    consolePlaceholder: "target.tld / 203.0.113.5 / https://portal.tld",
    terminalPlaceholder: "type help, status, scan example.com, view results...",
  },
  cn: {
    navLaunch: "启动控制台",
    heroScan: "开始扫描",
    openConsole: "打开控制台",
    demoSample: "载入样例",
    terminal: "终端",
    navPlaceholder: "快速目标 // 域名或 IP",
    heroPlaceholder: "corp.tld / 8.8.8.8 / https://target.tld / ghost_handle",
    consolePlaceholder: "target.tld / 203.0.113.5 / https://portal.tld",
    terminalPlaceholder: "输入 help、status、scan example.com、view results ...",
  },
};

const state = {
  view: "dashboard",
  resultTab: "overview",
  target: "",
  language: "en",
  scanning: false,
  scanSource: "idle",
  currentJobId: null,
  latestReport: null,
  latestSource: "NO DATA",
  progress: 0,
  runtimeSeconds: 0,
  progressTimer: null,
  runtimeTimer: null,
  pollTimer: null,
  ghostTimer: null,
  logTimer: null,
  overlayTimer: null,
  heroFeedTimer: null,
  intelFeedTimer: null,
  ambientTimer: null,
  recentScans: [],
  currentScanEntryId: null,
  currentThreat: "LOW",
};

let audioContext = null;

function inferDefaultApiUrl() {
  const host = window.location.hostname;
  if (host === "localhost" || host === "127.0.0.1") {
    return "http://127.0.0.1:8000/api/scan";
  }
  return `${window.location.origin}/api/scan`;
}

function hashString(value) {
  const text = String(value || "");
  let hash = 0;
  for (let index = 0; index < text.length; index += 1) {
    hash = (hash << 5) - hash + text.charCodeAt(index);
    hash |= 0;
  }
  return Math.abs(hash);
}

function clamp(value, min, max) {
  return Math.min(max, Math.max(min, value));
}

function pickFrom(items, seed) {
  return items[seed % items.length];
}

function formatNumber(value) {
  return String(value).padStart(2, "0");
}

function normalizeTarget(value) {
  return String(value || "").trim();
}

function parseTarget(target) {
  const input = normalizeTarget(target);
  if (!input) {
    return {
      input: "",
      domain: "",
      scheme: "",
      port: "",
      path: "",
      query: "",
      normalizedUrl: "",
      label: "NO TARGET",
      type: "unknown",
    };
  }

  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(input)) {
    return {
      input,
      domain: input,
      scheme: "",
      port: "",
      path: "",
      query: "",
      normalizedUrl: input,
      label: input,
      type: "ip",
    };
  }

  if (/^https?:\/\//i.test(input)) {
    try {
      const url = new URL(input);
      return {
        input,
        domain: url.hostname,
        scheme: url.protocol.replace(":", ""),
        port: url.port,
        path: url.pathname,
        query: url.search.replace(/^\?/, ""),
        normalizedUrl: url.toString(),
        label: url.hostname,
        type: "url",
      };
    } catch (_error) {}
  }

  if (input.includes("@") || (!input.includes(".") && !input.includes("/"))) {
    const clean = input.replace(/^@/, "");
    return {
      input,
      domain: `${clean}.ghost`,
      scheme: "profile",
      port: "",
      path: "",
      query: "",
      normalizedUrl: clean,
      label: clean,
      type: "username",
    };
  }

  return {
    input,
    domain: input.replace(/^https?:\/\//i, "").replace(/\/.*$/, ""),
    scheme: "https",
    port: "",
    path: "",
    query: "",
    normalizedUrl: `https://${input.replace(/^https?:\/\//i, "")}`,
    label: input.replace(/^https?:\/\//i, ""),
    type: "domain",
  };
}

function syntheticIp(seed, offset = 0) {
  const base = hashString(`${seed}:${offset}`);
  return `203.${(base % 180) + 10}.${(Math.floor(base / 7) % 200) + 10}.${(Math.floor(base / 11) % 220) + 20}`;
}

function uniqueList(items) {
  return Array.from(new Set(items.filter(Boolean)));
}

function getEnabledModules() {
  return moduleDefs.filter((item) => item.input?.checked);
}

function getModuleCount() {
  return getEnabledModules().length;
}

function isThreatIntelEnabled() {
  return !!document.getElementById("moduleThreat")?.checked;
}

function isPortScanEnabled() {
  return !!document.getElementById("modulePort")?.checked;
}

function deriveThreatLabel(score) {
  if (score >= 78) {
    return "CRITICAL";
  }
  if (score >= 54) {
    return "ELEVATED";
  }
  if (score >= 28) {
    return "TRACKED";
  }
  return "LOW";
}

function countOpenPorts(report) {
  const ipScan = report?.ip_scan || {};
  let total = 0;
  Object.values(ipScan.results || {}).forEach((result) => {
    const tcp = Array.isArray(result?.tcp?.open_ports) ? result.tcp.open_ports.length : Number(result?.tcp?.open_port_count || 0);
    const udp = Array.isArray(result?.udp?.open_ports) ? result.udp.open_ports.length : Number(result?.udp?.open_port_count || 0);
    total += tcp + udp;
  });
  return total;
}

function countTechSignals(report) {
  const tech = Array.isArray(report?.tech_stack?.detected_technologies) ? report.tech_stack.detected_technologies.length : 0;
  const cves = Array.isArray(report?.service_risk?.cve_lookup?.matches) ? report.service_risk.cve_lookup.matches.length : 0;
  const weak = Array.isArray(report?.service_risk?.weak_checks?.findings) ? report.service_risk.weak_checks.findings.length : 0;
  return tech + cves + weak;
}

function computeThreatScore(report) {
  const vtStats = report?.virustotal?.domain?.last_analysis_stats || {};
  const malicious = Number(vtStats.malicious || 0);
  const suspicious = Number(vtStats.suspicious || 0);
  const cveMatches = Array.isArray(report?.service_risk?.cve_lookup?.matches) ? report.service_risk.cve_lookup.matches.length : 0;
  const weakFindings = Array.isArray(report?.service_risk?.weak_checks?.findings) ? report.service_risk.weak_checks.findings.length : 0;
  const ports = countOpenPorts(report);
  const tech = countTechSignals(report);
  const score = malicious * 32 + suspicious * 12 + cveMatches * 14 + weakFindings * 8 + ports * 2 + tech;
  return clamp(score, 0, 99);
}

function buildSyntheticReport(rawTarget) {
  const target = parseTarget(rawTarget || "blackvault.neon");
  const seed = hashString(target.label);
  const domain = target.domain || `${target.label}.ghost`;
  const ips = uniqueList([syntheticIp(seed, 1), syntheticIp(seed, 2), syntheticIp(seed, 3)].slice(0, seed % 2 === 0 ? 2 : 3));
  const subdomains = uniqueList([
    `api.${domain}`,
    `edge.${domain}`,
    `cdn.${domain}`,
    `auth.${domain}`,
    `vault.${domain}`,
  ].slice(0, 3 + (seed % 2)));
  const techs = uniqueList([
    pickFrom(["nginx", "Cloudflare", "Next.js", "Node.js", "FastAPI", "React"], seed),
    pickFrom(["PostgreSQL", "Redis", "Tailwind", "Traefik", "Express"], seed + 1),
    pickFrom(["JWT", "GraphQL", "Vite", "Kubernetes", "Gunicorn"], seed + 2),
  ]);
  const openPorts = [22, 80, 443, 8080, 8443, 3306, 6379].slice(0, 2 + (seed % 4));
  const cves = openPorts.includes(8080)
    ? [
        {
          id: "CVE-2024-1312",
          severity: "high",
          product: "reverse proxy",
          description: "Header normalization bypass pattern detected in exposed edge tier.",
        },
      ]
    : [];
  const weakFindings = openPorts.includes(22)
    ? [
        {
          title: "SSH exposure",
          detail: "Administrative port responds on the public edge. Manual validation recommended.",
        },
      ]
    : [];
  const malicious = seed % 7 === 0 ? 1 : 0;
  const suspicious = 1 + (seed % 3);

  const results = {};
  ips.forEach((ip, index) => {
    const assignedPorts = openPorts.slice(index, openPorts.length).filter((_, portIndex) => portIndex % ips.length === index % ips.length);
    results[ip] = {
      tcp: {
        open_port_count: assignedPorts.length,
        open_ports: assignedPorts.map((port) => ({
          port,
          protocol: "tcp",
          service: pickFrom(["ssh", "http", "https", "jetty", "mysql", "redis"], seed + port),
        })),
      },
      udp: {
        open_port_count: 0,
        open_ports: [],
      },
    };
  });

  return {
    target: {
      input: target.input,
      domain,
      scheme: target.scheme || "https",
      port: target.port,
      path: target.path || "/",
      query: target.query,
      normalized_url: target.normalizedUrl || `https://${domain}`,
    },
    dns: {
      A: ips,
      AAAA: [],
      MX: [`mail.${domain}`],
      NS: [`ns1.${domain}`, `ns2.${domain}`],
      TXT: [`v=spf1 include:_spf.${domain} ~all`],
      CNAME: subdomains.slice(0, 1),
      SOA: [`ns1.${domain} hostmaster.${domain}`],
    },
    whois: {
      domain_name: domain,
      registrar: pickFrom(["GHOST REGISTRY", "NEONIC LTD", "BLACKBOX DOMAINS"], seed),
      whois_server: "whois.ghost-registry.neon",
      creation_date: "2023-02-14T02:22:00Z",
      expiration_date: "2027-02-14T02:22:00Z",
      updated_date: new Date().toISOString(),
      name_servers: [`ns1.${domain}`, `ns2.${domain}`],
      status: ["clientTransferProhibited", "serverUpdateProhibited"],
      emails: [`ops@${domain}`],
      dnssec: "unsigned",
    },
    tech_stack: {
      url: `https://${domain}`,
      status_code: openPorts.includes(443) ? 200 : 403,
      server_headers: {
        server: techs[0],
        "x-powered-by": techs[1] || "node",
      },
      detected_technologies: techs,
    },
    certificate_transparency: {
      enabled: !!document.getElementById("moduleSubdomain")?.checked,
      discovered_subdomains: subdomains,
    },
    passive_dns: {
      enabled: !!document.getElementById("modulePassive")?.checked,
      historical_subdomains: subdomains.slice().reverse(),
      resolved_ips: ips,
    },
    asn_network: {
      enabled: !!document.getElementById("moduleAsn")?.checked,
      records: [{ asn: `AS${65000 + (seed % 999)}`, prefix: `${ips[0].split(".").slice(0, 3).join(".")}.0/24` }],
      expanded_c_segment_hosts: !!document.getElementById("moduleAsn")?.checked ? ips.map((ip, index) => `${ip.split(".").slice(0, 3).join(".")}.${50 + index}`) : [],
    },
    web_assets: {
      enabled: !!document.getElementById("moduleWeb")?.checked,
      combined_endpoints: [`https://${domain}/login`, `https://${domain}/api/v1/session`, `https://${domain}/cdn/app.js`],
      sensitive_paths: {
        count: 2,
        hits: [`https://${domain}/.env`, `https://${domain}/backup.sql`],
      },
      directory_probe: {
        hit_count: 2,
        hits: [`/admin`, `/private`],
      },
    },
    service_risk: {
      enabled: !!document.getElementById("moduleVuln")?.checked,
      cve_lookup: {
        matches: cves,
      },
      weak_checks: {
        findings: weakFindings,
      },
    },
    ip_scan: {
      enabled: isPortScanEnabled(),
      scan_performed: isPortScanEnabled(),
      targets: ips,
      resolved_ips: ips,
      skipped_non_public_ips: [],
      skip_reason: "",
      warnings: [],
      scanner: "ghost-emulator",
      port_range: isPortScanEnabled() ? (refs.portModeInput.value === "full" ? "1-65535" : refs.portModeInput.value === "custom" ? normalizeTarget(refs.customPortsInput.value) || "custom" : "common") : "disabled",
      results,
    },
    virustotal: {
      enabled: isThreatIntelEnabled(),
      domain: {
        last_analysis_stats: {
          malicious,
          suspicious,
          harmless: 62,
          undetected: 15,
        },
      },
      url: {
        last_analysis_stats: {
          malicious: 0,
          suspicious: suspicious > 1 ? 1 : 0,
          harmless: 48,
          undetected: 24,
        },
      },
    },
    meta: {
      generated_at: new Date().toISOString(),
      target_input: target.input,
      scan_mode: isPortScanEnabled() ? refs.portModeInput.value : "intel-only",
      requested_port_range: refs.portModeInput.value === "custom" ? normalizeTarget(refs.customPortsInput.value) || "custom" : refs.portModeInput.value,
      source: "ghost",
    },
  };
}

function createRipple(event) {
  const target = event.currentTarget;
  if (!(target instanceof HTMLElement)) {
    return;
  }
  const rect = target.getBoundingClientRect();
  const ripple = document.createElement("span");
  ripple.className = "ripple-effect";
  ripple.style.left = `${event.clientX - rect.left}px`;
  ripple.style.top = `${event.clientY - rect.top}px`;
  target.appendChild(ripple);
  ripple.addEventListener("animationend", () => ripple.remove(), { once: true });
}

function bindRipples() {
  document.querySelectorAll(".ripple-target, .neo-button, .view-tab, .result-tab, .icon-button, .terminal-fab, .circuit-toggle").forEach((node) => {
    node.addEventListener("pointerdown", createRipple);
  });
}

function getAudioContext() {
  if (!audioContext) {
    const AudioCtx = window.AudioContext || window.webkitAudioContext;
    if (!AudioCtx) {
      return null;
    }
    audioContext = new AudioCtx();
  }
  return audioContext;
}

function playSfx(type) {
  const ctx = getAudioContext();
  if (!ctx) {
    return;
  }

  if (ctx.state === "suspended") {
    ctx.resume().catch(() => {});
  }

  const profiles = {
    scan: [240, 360, 520],
    glitch: [660, 420, 760],
    success: [440, 660, 880],
    error: [220, 180, 160],
  };

  const tones = profiles[type] || profiles.glitch;
  tones.forEach((frequency, index) => {
    const oscillator = ctx.createOscillator();
    const gain = ctx.createGain();
    oscillator.type = index % 2 === 0 ? "triangle" : "square";
    oscillator.frequency.setValueAtTime(frequency, ctx.currentTime);
    gain.gain.setValueAtTime(0.0001, ctx.currentTime);
    gain.gain.exponentialRampToValueAtTime(0.02, ctx.currentTime + 0.02 + index * 0.01);
    gain.gain.exponentialRampToValueAtTime(0.0001, ctx.currentTime + 0.12 + index * 0.04);
    oscillator.connect(gain);
    gain.connect(ctx.destination);
    oscillator.start(ctx.currentTime + index * 0.04);
    oscillator.stop(ctx.currentTime + 0.16 + index * 0.04);
  });
}

function showToast(title, message, type = "info") {
  if (!refs.toastStack) {
    return;
  }
  const toast = document.createElement("div");
  toast.className = `toast ${type === "success" ? "toast--success" : type === "error" ? "toast--error" : ""}`.trim();
  toast.innerHTML = `<strong>${title}</strong><span>${message}</span>`;
  refs.toastStack.appendChild(toast);
  window.setTimeout(() => {
    toast.style.opacity = "0";
    toast.style.transform = "translateY(-6px)";
    window.setTimeout(() => toast.remove(), 200);
  }, 3200);
}

function setActiveView(view, options = {}) {
  state.view = view;
  refs.app?.setAttribute("data-view", view);

  refs.workspaceViews.forEach((panel) => {
    panel.classList.toggle("is-active", panel.dataset.view === view);
  });

  refs.viewTabs.forEach((tab) => {
    if (tab.classList.contains("view-tab")) {
      tab.classList.toggle("is-active", tab.dataset.viewTarget === view);
    }
  });

  if (options.scroll) {
    document.getElementById("workspace")?.scrollIntoView({ behavior: "smooth", block: "start" });
  }
}

function setResultTab(tab) {
  state.resultTab = tab;
  refs.app?.setAttribute("data-result-tab", tab);

  refs.resultTabs.forEach((button) => {
    button.classList.toggle("is-active", button.dataset.resultTab === tab);
  });

  refs.resultPanels.forEach((panel) => {
    panel.classList.toggle("is-active", panel.dataset.resultPanel === tab);
  });

  if (tab === "network" && state.latestReport) {
    window.requestAnimationFrame(() => renderGraph(state.latestReport));
  }
}

function setTarget(value, source = null) {
  const nextTarget = normalizeTarget(value);
  state.target = nextTarget;

  [refs.navTargetInput, refs.heroTargetInput, refs.consoleTargetInput].forEach((input) => {
    if (!input || input === source) {
      return;
    }
    if (input.value !== nextTarget) {
      input.value = nextTarget;
    }
  });

  const parsed = parseTarget(nextTarget);
  refs.heroTargetEcho.textContent = parsed.label;
  refs.consoleTargetChip.textContent = parsed.label.toLowerCase() === "no target" ? "no target" : parsed.label;
  refs.heroStatusLine.textContent = nextTarget
    ? state.scanning
      ? `live trace engaged against ${parsed.label}`
      : state.latestReport
        ? `evidence package cached for ${parsed.label}`
        : `target ghosted into memory // ready for uplift`
    : "signal trace idle // feed a target to ignite the console";
}

function updateLanguage(lang) {
  state.language = lang;
  refs.langButtons.forEach((button) => button.classList.toggle("is-active", button.dataset.lang === lang));

  const t = translations[lang];
  refs.navLaunchBtn.textContent = t.navLaunch;
  refs.heroScanButton.textContent = t.heroScan;
  document.querySelectorAll('[data-view-target="console"]:not(.view-tab)').forEach((button) => {
    button.textContent = t.openConsole;
  });
  refs.demoSampleBtn.textContent = t.demoSample;
  refs.terminalFab.textContent = t.terminal;
  refs.navTargetInput.placeholder = t.navPlaceholder;
  refs.heroTargetInput.placeholder = t.heroPlaceholder;
  refs.consoleTargetInput.placeholder = t.consolePlaceholder;
  refs.terminalCommandInput.placeholder = t.terminalPlaceholder;
}

function renderFeedLine(container, message, max = 3) {
  if (!container) {
    return;
  }
  const row = document.createElement("div");
  row.textContent = message;
  container.prepend(row);
  while (container.children.length > max) {
    container.removeChild(container.lastElementChild);
  }
}

function buildStatusBadge(status) {
  const normalized = String(status || "idle").toLowerCase();
  const label = normalized.toUpperCase();
  const cls = normalized === "scanning" || normalized === "running"
    ? "table-status table-status--scanning"
    : normalized === "completed" || normalized === "imported"
      ? "table-status table-status--ok"
      : normalized === "failed" || normalized === "aborted"
        ? "table-status table-status--danger"
        : "table-status";
  return `<span class="${cls}">${label}</span>`;
}

function derivePoint(seed) {
  return WORLD_POINTS[seed % WORLD_POINTS.length];
}

function seedRecentScans() {
  state.recentScans = [
    {
      id: "seed-1",
      target: "night.market",
      type: "Passive Recon",
      status: "SCANNING",
      threat: "ELEVATED",
      timestamp: Date.now() - 1000 * 60 * 2,
      point: derivePoint(1),
    },
    {
      id: "seed-2",
      target: "veil-sector.io",
      type: "Port Fingerprint",
      status: "COMPLETED",
      threat: "TRACKED",
      timestamp: Date.now() - 1000 * 60 * 8,
      point: derivePoint(3),
    },
    {
      id: "seed-3",
      target: "203.0.113.77",
      type: "Threat Intel",
      status: "SCANNING",
      threat: "LOW",
      timestamp: Date.now() - 1000 * 60 * 14,
      point: derivePoint(5),
    },
    {
      id: "seed-4",
      target: "vault-shadow.net",
      type: "Web Crawl",
      status: "COMPLETED",
      threat: "CRITICAL",
      timestamp: Date.now() - 1000 * 60 * 29,
      point: derivePoint(7),
    },
  ];
}

function updateDashboardStats() {
  const scansToday = state.recentScans.length + (state.latestReport ? 1 : 0);
  const uniqueTargets = new Set(state.recentScans.map((entry) => entry.target));
  if (state.latestReport?.target?.input) {
    uniqueTargets.add(state.latestReport.target.input);
  }
  const vulnBase = state.latestReport ? countTechSignals(state.latestReport) : 21;
  refs.statScansToday.textContent = String(scansToday).padStart(3, "0");
  refs.statTargetsTracked.textContent = String(uniqueTargets.size).padStart(3, "0");
  refs.statVulnsFound.textContent = String(clamp(vulnBase, 0, 99)).padStart(3, "0");
  refs.statActiveNodes.textContent = state.scanning ? "132" : "128";
}

function renderRecentScans() {
  if (!refs.recentScansBody) {
    return;
  }

  refs.recentScansBody.innerHTML = "";
  state.recentScans
    .slice()
    .sort((left, right) => right.timestamp - left.timestamp)
    .slice(0, 8)
    .forEach((entry) => {
      const row = document.createElement("tr");
      const minutes = Math.max(1, Math.round((Date.now() - entry.timestamp) / 60000));
      row.innerHTML = `
        <td>${entry.target}</td>
        <td>${entry.type}</td>
        <td>${buildStatusBadge(entry.status)}</td>
        <td><span class="threat-pill threat-pill--${String(entry.threat).toLowerCase()}">${entry.threat}</span></td>
        <td>${minutes}m ago</td>
      `;
      refs.recentScansBody.appendChild(row);
    });
}

function renderMapPins() {
  if (!refs.mapPins) {
    return;
  }
  refs.mapPins.innerHTML = "";
  state.recentScans
    .slice(0, 6)
    .forEach((entry) => {
      const pin = document.createElement("span");
      pin.className = "map-pin";
      pin.style.setProperty("--x", entry.point.x);
      pin.style.setProperty("--y", entry.point.y);
      pin.title = `${entry.point.label} // ${entry.target}`;
      refs.mapPins.appendChild(pin);
    });

  if (refs.mapLocationCount) {
    refs.mapLocationCount.textContent = `${Math.min(state.recentScans.length, 6)} pins`;
  }
}

function renderIntelFeed() {
  if (!refs.intelFeed) {
    return;
  }

  refs.intelFeed.innerHTML = "";
  intelFeedPool.slice(0, 3).forEach((item) => {
    const block = document.createElement("div");
    block.className = "intel-feed__item";
    block.innerHTML = `<strong>${item.title}</strong><span>${item.text}</span>`;
    refs.intelFeed.appendChild(block);
  });
}

function rotateIntelFeed() {
  intelFeedPool.push(intelFeedPool.shift());
  renderIntelFeed();
}

function addRecentScanEntry(target, type = "Deep Recon") {
  const entry = {
    id: `scan-${Date.now()}`,
    target,
    type,
    status: "SCANNING",
    threat: "TRACKED",
    timestamp: Date.now(),
    point: derivePoint(hashString(target)),
  };
  state.currentScanEntryId = entry.id;
  state.recentScans.unshift(entry);
  state.recentScans = state.recentScans.slice(0, 10);
  renderRecentScans();
  renderMapPins();
  updateDashboardStats();
}

function updateRecentScanEntry(patch) {
  if (!state.currentScanEntryId) {
    return;
  }
  state.recentScans = state.recentScans.map((entry) => {
    if (entry.id !== state.currentScanEntryId) {
      return entry;
    }
    return { ...entry, ...patch };
  });
  renderRecentScans();
  renderMapPins();
  updateDashboardStats();
}

function appendLog(message, level = "info") {
  if (!refs.scanLog || !message) {
    return;
  }

  const line = document.createElement("div");
  line.className = `scan-log__line scan-log__line--${level === "success" ? "ok" : level === "error" ? "error" : level === "warn" ? "warn" : "info"}`;
  line.textContent = `[${new Date().toLocaleTimeString("zh-CN", { hour12: false })}] ${message}`;
  refs.scanLog.appendChild(line);
  refs.scanLog.scrollTop = refs.scanLog.scrollHeight;

  if (refs.terminalOverlayLog) {
    const clone = line.cloneNode(true);
    refs.terminalOverlayLog.appendChild(clone);
    refs.terminalOverlayLog.scrollTop = refs.terminalOverlayLog.scrollHeight;
  }
}

function clearScanLog() {
  refs.scanLog.innerHTML = "";
}

function ensureTerminalBoot() {
  if (!refs.terminalOverlayLog || refs.terminalOverlayLog.children.length) {
    return;
  }
  [
    "ghost shell mounted // type help for command list",
    "available commands: help, status, scan <target>, view dashboard|console|results, load demo, clear",
    "uplink sound placeholders wired through WebAudio synth beeps",
  ].forEach((text) => appendLog(text, "info"));
}

function updateModuleCountChip() {
  const count = getModuleCount();
  refs.moduleCountChip.textContent = `${String(count).padStart(2, "0")} armed`;
}

function syncCustomPortField() {
  const isCustom = refs.portModeInput.value === "custom";
  refs.customPortsField.classList.toggle("field-block--hidden", !isCustom);
}

function showOverlay(title, statusText) {
  if (!refs.scanOverlay) {
    return;
  }
  refs.scanOverlay.hidden = false;
  refs.scanOverlayTitle.textContent = title;
  refs.scanOverlayStatusText.textContent = statusText;
}

function hideOverlay(delay = 0) {
  window.clearTimeout(state.overlayTimer);
  state.overlayTimer = window.setTimeout(() => {
    refs.scanOverlay.hidden = true;
  }, delay);
}

function setProgress(value, message, overlayStatus) {
  state.progress = clamp(Math.round(value), 0, 100);
  const text = message || `decrypting... ${state.progress}%`;
  refs.scanProgressBar.style.width = `${state.progress}%`;
  refs.scanProgressText.textContent = text;
  refs.scanOverlayProgressBar.style.width = `${state.progress}%`;
  refs.scanOverlayProgressText.textContent = text;
  if (overlayStatus) {
    refs.scanOverlayStatusText.textContent = overlayStatus;
  }
}

function setThreatLabel(label) {
  state.currentThreat = label;
  refs.consoleThreatChip.textContent = label.toLowerCase();
  refs.statusThreat.textContent = label;
  refs.heroThreatLevel.textContent = label;
  refs.heroThreatPosture.textContent = label === "LOW" ? "MONITORED" : label;
}

function updateStatusUi() {
  const parsed = parseTarget(state.target || state.latestReport?.target?.input || "");
  refs.consoleTargetChip.textContent = parsed.label;
  refs.heroTargetEcho.textContent = parsed.label;
  refs.resultTargetKpi.textContent = parsed.label;
  refs.consoleStartBtn.disabled = state.scanning;
  refs.consoleStopBtn.disabled = !state.scanning;
  refs.consoleStatusChip.textContent = state.scanning ? "scanning" : state.latestReport ? "ready" : "idle";
  refs.resultStatusKpi.textContent = state.scanning ? "SCANNING" : state.latestReport ? "READY" : "STANDBY";
  refs.statusNodes.textContent = state.scanning ? "132" : "128";
  refs.heroNodeStatus.textContent = state.scanning ? "132 ONLINE" : "128 ONLINE";
  refs.heroFeedState.textContent = state.scanning ? "TRACKING" : "READY";
  refs.statusMode.textContent = isPortScanEnabled() ? refs.portModeInput.value.toUpperCase() : "INTEL";

  if (!state.target && !state.latestReport) {
    refs.heroStatusLine.textContent = "signal trace idle // feed a target to ignite the console";
  } else if (state.scanning) {
    refs.heroStatusLine.textContent = `uplink active // tracing ${parsed.label} across hostile layers`;
  } else if (state.latestReport) {
    refs.heroStatusLine.textContent = `evidence package compiled for ${parsed.label}`;
  } else {
    refs.heroStatusLine.textContent = `target ghosted into memory // ready for uplift`;
  }
}

function stopAllTimers() {
  ["progressTimer", "runtimeTimer", "pollTimer", "ghostTimer", "logTimer"].forEach((key) => {
    if (state[key]) {
      window.clearInterval(state[key]);
      state[key] = null;
    }
  });
}

function startRuntimeTimer() {
  if (state.runtimeTimer) {
    window.clearInterval(state.runtimeTimer);
  }
  state.runtimeSeconds = 0;
  refs.scanRuntimeText.textContent = "runtime // 00:00";
  state.runtimeTimer = window.setInterval(() => {
    state.runtimeSeconds += 1;
    const minutes = formatNumber(Math.floor(state.runtimeSeconds / 60));
    const seconds = formatNumber(state.runtimeSeconds % 60);
    refs.scanRuntimeText.textContent = `runtime // ${minutes}:${seconds}`;
  }, 1000);
}

function beginProgressPulse() {
  if (state.progressTimer) {
    window.clearInterval(state.progressTimer);
  }
  state.progressTimer = window.setInterval(() => {
    if (!state.scanning) {
      return;
    }
    if (state.progress < 92) {
      setProgress(state.progress + (state.progress < 38 ? 6 : state.progress < 68 ? 4 : 2), `decrypting... ${clamp(state.progress + 1, 0, 99)}%`);
    }
  }, 900);
}

function appendPhaseLogs(target) {
  const activeModules = getEnabledModules().map((item) => item.label);
  const script = [
    `uplink primed for ${target}`,
    `loading module lattice: ${activeModules.join(", ")}`,
    `passive traces ghosting around ${target}`,
    `dns residue being extracted from public record mirrors`,
    `service mesh fingerprinting phase armed`,
    `dark export channels waiting for encrypted evidence`,
  ];

  let index = 0;
  if (state.logTimer) {
    window.clearInterval(state.logTimer);
  }
  state.logTimer = window.setInterval(() => {
    if (!state.scanning) {
      return;
    }
    appendLog(script[index % script.length], index % 4 === 1 ? "warn" : "info");
    index += 1;
  }, 950);
}

function buildPayload(target) {
  const portMode = refs.portModeInput.value;
  const portEnabled = isPortScanEnabled();
  const threatIntelAllowed = isThreatIntelEnabled() && normalizeTarget(refs.vtApiKeyInput.value);

  if (isThreatIntelEnabled() && !threatIntelAllowed) {
    appendLog("threat intel key absent // live API run will skip VirusTotal lane", "warn");
  }

  return {
    target,
    timeout: Number(refs.timeoutInput.value || 10),
    port_timeout: Number(refs.portTimeoutInput.value || 0.8),
    port_scanner: "auto",
    full_port_scan: portEnabled && portMode === "full",
    tcp_scan: portEnabled ? !!refs.tcpEnabledInput.checked : false,
    udp_scan: portEnabled ? !!refs.udpEnabledInput.checked : false,
    vt_scan: !!threatIntelAllowed,
    vt_api_key: threatIntelAllowed ? normalizeTarget(refs.vtApiKeyInput.value) : null,
    allow_private_ip: !!document.getElementById("modulePrivate")?.checked,
    cidr_targets: document.getElementById("modulePrivate")?.checked ? normalizeTarget(refs.cidrTargetsInput.value) : "",
    ct_scan: !!document.getElementById("moduleSubdomain")?.checked,
    passive_dns_scan: !!document.getElementById("modulePassive")?.checked,
    asn_scan: !!document.getElementById("moduleAsn")?.checked,
    asn_expand_c_segment: !!document.getElementById("moduleAsn")?.checked,
    web_asset_scan: !!document.getElementById("moduleWeb")?.checked,
    web_crawler: !!document.getElementById("moduleWeb")?.checked && !!refs.webCrawlerInput.checked,
    web_js_extract: !!document.getElementById("moduleWeb")?.checked && !!refs.jsExtractInput.checked,
    web_sensitive_path_extract: !!document.getElementById("moduleWeb")?.checked,
    web_dir_scan: !!document.getElementById("moduleWeb")?.checked,
    web_dir_use_ffuf: false,
    service_risk_scan: !!document.getElementById("moduleVuln")?.checked,
    cve_lookup: !!document.getElementById("moduleVuln")?.checked,
    weak_nmap_checks: !!document.getElementById("moduleVuln")?.checked,
    scan_mode: portEnabled ? portMode : null,
    custom_ports: portEnabled && portMode === "custom" ? normalizeTarget(refs.customPortsInput.value) : null,
  };
}

function beginScanSession(source) {
  state.scanning = true;
  state.scanSource = source;
  state.currentJobId = null;
  state.latestSource = "NO DATA";
  refs.statusTransport.textContent = source === "ghost" ? "GHOST MODE" : "LIVE API";
  setProgress(4, "decrypting... 4%", "warming passive collectors");
  showOverlay(source === "ghost" ? "bootstrapping ghost simulation" : "bootstrapping live uplink", "warming passive collectors");
  hideOverlay(2200);
  startRuntimeTimer();
  beginProgressPulse();
  appendPhaseLogs(state.target);
  setThreatLabel("TRACKED");
  updateStatusUi();
  playSfx("scan");
}

function finishScan(report, source = "LIVE API") {
  state.scanning = false;
  state.currentJobId = null;
  state.latestReport = report;
  state.latestSource = source.toUpperCase();
  stopAllTimers();
  setProgress(100, "decrypting... 100%", "evidence package complete");
  setThreatLabel(deriveThreatLabel(computeThreatScore(report)));
  refs.resultSourceKpi.textContent = state.latestSource;
  refs.statusTransport.textContent = source === "ghost" ? "GHOST MODE" : source === "IMPORTED" ? "IMPORTED" : "LIVE API";
  renderReport(report);
  updateRecentScanEntry({
    status: source === "IMPORTED" ? "IMPORTED" : "COMPLETED",
    threat: deriveThreatLabel(computeThreatScore(report)),
  });
  updateStatusUi();
  updateDashboardStats();
  appendLog(`scan complete // evidence package forged via ${source.toLowerCase()}`, "success");
  setActiveView("results", { scroll: true });
  window.requestAnimationFrame(() => renderGraph(report));
  hideOverlay();
  playSfx("success");
  showToast("NEOSCAN", source === "IMPORTED" ? "Imported report injected into the results stack." : "Recon evidence package is ready.", "success");
}

function failScan(message) {
  state.scanning = false;
  stopAllTimers();
  state.currentJobId = null;
  refs.statusTransport.textContent = "LINK FAULT";
  setThreatLabel("LOW");
  setProgress(0, "decrypting... 0%", "uplink failure");
  updateRecentScanEntry({ status: "FAILED", threat: "LOW" });
  updateStatusUi();
  hideOverlay();
  appendLog(message, "error");
  playSfx("error");
  showToast("NEOSCAN", message, "error");
}

function startGhostMode(target) {
  const phases = [
    { progress: 12, message: "probing passive mirrors", overlay: "collecting passive residue" },
    { progress: 28, message: "enumerating records", overlay: "walking dns and whois shadows" },
    { progress: 46, message: "fingerprinting services", overlay: "mapping exposed surfaces" },
    { progress: 66, message: "cross-linking technology stack", overlay: "fusing technology signatures" },
    { progress: 84, message: "packaging evidence", overlay: "forging dark export bundle" },
    { progress: 100, message: "ghost package complete", overlay: "evidence ready" },
  ];

  let phaseIndex = 0;
  if (state.ghostTimer) {
    window.clearInterval(state.ghostTimer);
  }

  state.ghostTimer = window.setInterval(() => {
    if (!state.scanning) {
      return;
    }
    const phase = phases[phaseIndex];
    setProgress(phase.progress, `decrypting... ${phase.progress}%`, phase.overlay);
    appendLog(`${phase.message} // ${target}`, phase.progress >= 84 ? "warn" : "info");
    phaseIndex += 1;
    if (phaseIndex >= phases.length) {
      window.clearInterval(state.ghostTimer);
      state.ghostTimer = null;
      const report = buildSyntheticReport(target);
      finishScan(report, "GHOST");
    }
  }, 1300);
}

async function createRemoteScan(target) {
  const apiUrl = normalizeTarget(refs.apiUrlInput.value) || inferDefaultApiUrl();
  refs.apiUrlInput.value = apiUrl;
  const payload = buildPayload(target);

  if (isPortScanEnabled() && !refs.tcpEnabledInput.checked && !refs.udpEnabledInput.checked) {
    throw new Error("Enable at least one transport protocol before launching a live scan.");
  }

  const response = await fetch(apiUrl, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });

  if (!response.ok) {
    throw new Error(`uplink rejected with HTTP ${response.status}`);
  }

  const data = await response.json();
  if (!data?.job_id) {
    throw new Error("backend did not return a valid job id");
  }

  state.currentJobId = data.job_id;
  appendLog(`live uplink established // job ${data.job_id}`, "success");
  refs.scanOverlayTitle.textContent = "live uplink established";
  pollRemoteScan(apiUrl, data.job_id);
}

function pollRemoteScan(apiUrl, jobId) {
  if (state.pollTimer) {
    window.clearInterval(state.pollTimer);
  }

  state.pollTimer = window.setInterval(async () => {
    if (!state.scanning) {
      return;
    }

    try {
      const response = await fetch(`${apiUrl.replace(/\/+$/, "")}/${jobId}`);
      if (!response.ok) {
        throw new Error(`status poll failed with HTTP ${response.status}`);
      }
      const data = await response.json();
      const status = String(data?.status || "unknown").toLowerCase();

      if (status === "queued") {
        appendLog(`job ${jobId} queued in uplink tunnel`, "info");
        setProgress(Math.max(state.progress, 16), `decrypting... ${Math.max(state.progress, 16)}%`, "queueing reconnaissance workers");
        return;
      }

      if (status === "running" || status === "stopping") {
        appendLog(`job ${jobId} status // ${status}`, status === "stopping" ? "warn" : "info");
        setProgress(Math.max(state.progress, status === "stopping" ? 90 : 26), `decrypting... ${Math.max(state.progress, status === "stopping" ? 90 : 26)}%`);
        return;
      }

      if (status === "completed") {
        finishScan(data.result || buildSyntheticReport(state.target), "LIVE API");
        return;
      }

      if (status === "canceled") {
        failScan("remote job was canceled before package completion.");
        updateRecentScanEntry({ status: "ABORTED", threat: "LOW" });
        return;
      }

      if (status === "failed") {
        failScan(`remote scan failed: ${data.error || "unknown fault"}`);
      }
    } catch (error) {
      failScan(String(error.message || error));
    }
  }, 1400);
}

async function startScan({ demo = false } = {}) {
  if (state.scanning) {
    showToast("NEOSCAN", "An uplink is already active. Abort it first.", "error");
    return;
  }

  const target = normalizeTarget(refs.consoleTargetInput.value || refs.heroTargetInput.value || refs.navTargetInput.value);
  if (!target) {
    showToast("NEOSCAN", "Feed a domain, IP, URL, or username into the target channel first.", "error");
    playSfx("error");
    return;
  }

  setTarget(target);
  clearScanLog();
  appendLog(`target locked // ${target}`, "success");
  addRecentScanEntry(target, isPortScanEnabled() ? "Deep Recon" : "Passive Recon");
  setActiveView("console", { scroll: true });

  if (demo) {
    beginScanSession("ghost");
    startGhostMode(target);
    return;
  }

  beginScanSession("api");
  try {
    await createRemoteScan(target);
  } catch (error) {
    appendLog(`live uplink failed // ${error.message}. falling back to ghost mode.`, "warn");
    refs.statusTransport.textContent = "GHOST FALLBACK";
    state.scanSource = "ghost";
    startGhostMode(target);
  }
}

async function abortScan() {
  if (!state.scanning) {
    showToast("NEOSCAN", "No live uplink to abort.", "error");
    return;
  }

  if (state.scanSource === "api" && state.currentJobId) {
    const apiUrl = normalizeTarget(refs.apiUrlInput.value) || inferDefaultApiUrl();
    try {
      await fetch(`${apiUrl.replace(/\/+$/, "")}/${state.currentJobId}/stop`, { method: "POST" });
      appendLog(`abort signal transmitted // ${state.currentJobId}`, "warn");
      showToast("NEOSCAN", "Abort signal transmitted to remote uplink.", "success");
    } catch (error) {
      failScan(`abort request failed: ${error.message}`);
    }
    return;
  }

  state.scanning = false;
  stopAllTimers();
  setProgress(0, "decrypting... 0%", "ghost uplink aborted");
  updateRecentScanEntry({ status: "ABORTED", threat: "LOW" });
  updateStatusUi();
  hideOverlay();
  appendLog("ghost uplink aborted by operator", "warn");
  playSfx("error");
}

function summarizeReport(report) {
  const target = report?.target?.input || report?.meta?.target_input || "unknown";
  const domain = report?.target?.domain || "n/a";
  const dnsA = Array.isArray(report?.dns?.A) ? report.dns.A.join(", ") : "n/a";
  const registrar = report?.whois?.registrar || "n/a";
  const techs = Array.isArray(report?.tech_stack?.detected_technologies) ? report.tech_stack.detected_technologies.join(", ") : "n/a";
  const openPorts = countOpenPorts(report);
  const techCount = countTechSignals(report);
  const score = computeThreatScore(report);
  const vtStats = report?.virustotal?.domain?.last_analysis_stats;

  return {
    missionDigest: [
      `target input :: ${target}`,
      `domain :: ${domain}`,
      `generated :: ${report?.meta?.generated_at || new Date().toISOString()}`,
      `scan mode :: ${report?.meta?.scan_mode || refs.portModeInput.value || "common"}`,
      `source :: ${state.latestSource}`,
    ],
    signalSynopsis: [
      `dns A :: ${dnsA}`,
      `registrar :: ${registrar}`,
      `technologies :: ${techs}`,
      `open ports :: ${openPorts}`,
      `threat score :: ${score}`,
      vtStats ? `vt stats :: malicious ${vtStats.malicious || 0} / suspicious ${vtStats.suspicious || 0}` : "vt stats :: unavailable",
    ],
    target,
    openPorts,
    techCount,
    score,
  };
}

function fillList(container, items, emptyMessage) {
  if (!container) {
    return;
  }
  container.innerHTML = "";
  const list = (items || []).filter(Boolean);
  const source = list.length ? list : [emptyMessage];
  source.forEach((text) => {
    const row = document.createElement("div");
    row.textContent = text;
    container.appendChild(row);
  });
}

function renderDnsTable(report) {
  refs.dnsTableBody.innerHTML = "";
  const dns = report?.dns || {};
  const rows = [];
  Object.entries(dns).forEach(([type, value]) => {
    if (Array.isArray(value)) {
      value.forEach((item) => rows.push([type, item]));
    } else if (value) {
      rows.push([type, value]);
    }
  });
  if (!rows.length) {
    rows.push(["DNS", "No records surfaced."]);
  }
  rows.forEach(([type, value]) => {
    const row = document.createElement("tr");
    row.innerHTML = `<td>${type}</td><td>${value}</td>`;
    refs.dnsTableBody.appendChild(row);
  });
}

function renderWhoisTable(report) {
  refs.whoisTableBody.innerHTML = "";
  const whois = report?.whois || {};
  const rows = [
    ["Registrar", whois.registrar || "n/a"],
    ["Creation", whois.creation_date || "n/a"],
    ["Expiration", whois.expiration_date || "n/a"],
    ["Updated", whois.updated_date || "n/a"],
    ["Name servers", Array.isArray(whois.name_servers) ? whois.name_servers.join(", ") : "n/a"],
    ["Status", Array.isArray(whois.status) ? whois.status.join(", ") : whois.status || "n/a"],
  ];
  rows.forEach(([field, value]) => {
    const row = document.createElement("tr");
    row.innerHTML = `<td>${field}</td><td>${value}</td>`;
    refs.whoisTableBody.appendChild(row);
  });
}

function renderTechChips(report) {
  refs.techChipList.innerHTML = "";
  const techs = Array.isArray(report?.tech_stack?.detected_technologies) ? report.tech_stack.detected_technologies : [];
  const list = techs.length ? techs : ["No strong fingerprints"];
  list.forEach((item) => {
    const chip = document.createElement("span");
    chip.textContent = item;
    refs.techChipList.appendChild(chip);
  });
}

function renderResolvedTargets(report) {
  const ips = Array.isArray(report?.ip_scan?.resolved_ips) ? report.ip_scan.resolved_ips : [];
  const passive = Array.isArray(report?.passive_dns?.historical_subdomains) ? report.passive_dns.historical_subdomains : [];
  const ct = Array.isArray(report?.certificate_transparency?.discovered_subdomains) ? report.certificate_transparency.discovered_subdomains : [];
  fillList(refs.resolvedTargetsList, [...ips, ...passive, ...ct], "No passive relationships surfaced.");
}

function buildGraph(report) {
  const target = report?.target?.domain || report?.target?.input || "target";
  const nodes = [{ id: "target", label: target, type: "target" }];
  const links = [];

  const addNodes = (items, type) => {
    items.forEach((item, index) => {
      const id = `${type}-${index}-${item}`;
      nodes.push({ id, label: item, type });
      links.push({ from: "target", to: id });
    });
  };

  addNodes((report?.dns?.A || []).slice(0, 3), "ip");
  addNodes((report?.certificate_transparency?.discovered_subdomains || []).slice(0, 4), "subdomain");
  addNodes((report?.tech_stack?.detected_technologies || []).slice(0, 3), "tech");

  return { nodes, links };
}

function renderGraph(report) {
  const canvas = refs.networkCanvas;
  if (!canvas) {
    return;
  }

  const ctx = canvas.getContext("2d");
  if (!ctx) {
    return;
  }

  const rect = canvas.getBoundingClientRect();
  const width = Math.max(320, rect.width || 640);
  const height = Math.max(360, rect.height || 420);
  const dpr = Math.min(window.devicePixelRatio || 1, 2);
  canvas.width = Math.floor(width * dpr);
  canvas.height = Math.floor(height * dpr);
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  ctx.clearRect(0, 0, width, height);

  const graph = buildGraph(report);
  const centerX = width / 2;
  const centerY = height / 2;
  const orbit = Math.min(width, height) * 0.28;
  const positions = {};

  graph.nodes.forEach((node, index) => {
    if (node.type === "target") {
      positions[node.id] = { x: centerX, y: centerY };
      return;
    }
    const angle = ((Math.PI * 2) / (graph.nodes.length - 1 || 1)) * index;
    const radius = orbit + (node.type === "tech" ? 34 : node.type === "ip" ? -18 : 0);
    positions[node.id] = {
      x: centerX + Math.cos(angle) * radius,
      y: centerY + Math.sin(angle) * radius,
    };
  });

  graph.links.forEach((link) => {
    const from = positions[link.from];
    const to = positions[link.to];
    if (!from || !to) {
      return;
    }
    const gradient = ctx.createLinearGradient(from.x, from.y, to.x, to.y);
    gradient.addColorStop(0, "rgba(0,240,255,0.45)");
    gradient.addColorStop(1, "rgba(255,0,170,0.24)");
    ctx.strokeStyle = gradient;
    ctx.lineWidth = 1.4;
    ctx.beginPath();
    ctx.moveTo(from.x, from.y);
    ctx.lineTo(to.x, to.y);
    ctx.stroke();
  });

  graph.nodes.forEach((node) => {
    const pos = positions[node.id];
    if (!pos) {
      return;
    }
    ctx.beginPath();
    ctx.fillStyle = node.type === "target" ? "#00f0ff" : node.type === "ip" ? "#ff00aa" : node.type === "tech" ? "#00ff9f" : "#9ce7ff";
    ctx.shadowBlur = node.type === "target" ? 22 : 14;
    ctx.shadowColor = ctx.fillStyle;
    ctx.arc(pos.x, pos.y, node.type === "target" ? 10 : 7, 0, Math.PI * 2);
    ctx.fill();
    ctx.shadowBlur = 0;
    ctx.fillStyle = "#e7feff";
    ctx.font = `600 ${node.type === "target" ? 13 : 11}px Orbitron`;
    ctx.textAlign = "center";
    ctx.fillText(node.label.slice(0, 16), pos.x, pos.y + (node.type === "target" ? 30 : 24));
  });

  fillList(
    refs.nodeLegend,
    graph.nodes.map((node) => `${node.type} :: ${node.label}`),
    "No graph nodes available."
  );
}

function renderVulnCards(report) {
  refs.vulnCards.innerHTML = "";
  const cards = [];
  const vtStats = report?.virustotal?.domain?.last_analysis_stats;
  const cves = Array.isArray(report?.service_risk?.cve_lookup?.matches) ? report.service_risk.cve_lookup.matches : [];
  const weak = Array.isArray(report?.service_risk?.weak_checks?.findings) ? report.service_risk.weak_checks.findings : [];
  const ipScan = report?.ip_scan?.results || {};

  if (vtStats && (vtStats.malicious || vtStats.suspicious)) {
    cards.push({
      title: "Threat Intel Hit",
      severity: vtStats.malicious ? "critical" : "tracked",
      items: [
        `malicious verdicts :: ${vtStats.malicious || 0}`,
        `suspicious verdicts :: ${vtStats.suspicious || 0}`,
        "recommendation :: enrich with external reputation telemetry",
      ],
    });
  }

  if (cves.length) {
    cards.push({
      title: "CVE Correlation",
      severity: "critical",
      items: cves.map((item) => `${item.id} // ${item.product || "unknown product"} // ${item.description || item.severity || "high signal"}`),
    });
  }

  if (weak.length) {
    cards.push({
      title: "Weak Configuration Surface",
      severity: "elevated",
      items: weak.map((item) => `${item.title || "weak finding"} // ${item.detail || "manual validation required"}`),
    });
  }

  const exposed = [];
  Object.entries(ipScan).forEach(([ip, result]) => {
    (result?.tcp?.open_ports || []).forEach((row) => {
      if ([22, 3389, 3306, 6379].includes(Number(row.port))) {
        exposed.push(`${ip}:${row.port}/${row.protocol || "tcp"} // ${row.service || "service"} exposed on public edge`);
      }
    });
  });
  if (exposed.length) {
    cards.push({
      title: "Edge Exposure",
      severity: "tracked",
      items: exposed,
    });
  }

  if (!cards.length) {
    cards.push({
      title: "No Direct Vuln Hits",
      severity: "low",
      items: [
        "no confirmed exploitable fingerprints were emitted by automated lanes",
        "manual verification remains recommended for auth, upload, and hidden routes",
        "consider rerunning with deeper port and web asset expansion",
      ],
    });
  }

  cards.forEach((card) => {
    const article = document.createElement("article");
    article.className = "vuln-card";
    article.innerHTML = `
      <div class="vuln-card__head">
        <strong>${card.title}</strong>
        <span class="threat-pill threat-pill--${card.severity}">${card.severity.toUpperCase()}</span>
      </div>
      <ul>${card.items.map((item) => `<li>${item}</li>`).join("")}</ul>
    `;
    refs.vulnCards.appendChild(article);
  });
}

function renderReport(report) {
  const summary = summarizeReport(report);
  const score = summary.score;
  const threat = deriveThreatLabel(score);

  refs.resultTargetKpi.textContent = report?.target?.input || report?.meta?.target_input || "NO TARGET";
  refs.resultStatusKpi.textContent = "READY";
  refs.resultOpenPortsKpi.textContent = String(summary.openPorts);
  refs.resultTechKpi.textContent = String(summary.techCount);
  refs.resultThreatScoreKpi.textContent = String(score).padStart(2, "0");
  refs.resultSourceKpi.textContent = state.latestSource;

  fillList(refs.missionDigest, summary.missionDigest, "No mission digest available.");
  fillList(refs.signalSynopsis, summary.signalSynopsis, "No signal synopsis available.");
  fillList(
    refs.terminalHighlights,
    Array.from(refs.scanLog.children).slice(-6).map((line) => line.textContent),
    "Terminal highlights will appear after the first live operation."
  );

  renderDnsTable(report);
  renderWhoisTable(report);
  renderTechChips(report);
  renderResolvedTargets(report);
  renderGraph(report);
  renderVulnCards(report);
  refs.rawJsonView.textContent = JSON.stringify(report, null, 2);
  setThreatLabel(threat);
}

async function copyTargetContent(targetId) {
  const node = document.getElementById(targetId);
  if (!node) {
    return;
  }

  const text = node.innerText.trim();
  if (!text) {
    showToast("NEOSCAN", "Nothing to copy from that panel yet.", "error");
    return;
  }

  try {
    await navigator.clipboard.writeText(text);
    playSfx("glitch");
    showToast("NEOSCAN", "Panel content copied to clipboard.", "success");
  } catch (_error) {
    showToast("NEOSCAN", "Clipboard channel is blocked in this environment.", "error");
  }
}

function downloadLatestReport() {
  if (!state.latestReport) {
    showToast("NEOSCAN", "No evidence package has been generated yet.", "error");
    return;
  }
  const blob = new Blob([JSON.stringify(state.latestReport, null, 2)], { type: "application/json;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = `neoscan-${Date.now()}.json`;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  URL.revokeObjectURL(url);
  playSfx("success");
  showToast("NEOSCAN", "Evidence package downloaded.", "success");
}

function exportToDarkWeb() {
  playSfx("glitch");
  appendLog("onion uplink rejected // human approval required for off-grid export", "warn");
  showToast("Dark Web Relay", "Fake export button engaged. Human approval required for off-grid transfer.", "success");
}

function handleImportedReport(file) {
  const reader = new FileReader();
  reader.onload = () => {
    try {
      const report = JSON.parse(String(reader.result));
      setTarget(report?.target?.input || report?.meta?.target_input || state.target || file.name);
      refs.reportMetaName.textContent = file.name;
      refs.reportMeta.firstElementChild.textContent = `report imported // ${(file.size / 1024).toFixed(1)} KB`;
      state.latestReport = report;
      state.latestSource = "IMPORTED";
      finishScan(report, "IMPORTED");
    } catch (_error) {
      refs.reportMetaName.textContent = file.name;
      refs.reportMeta.firstElementChild.textContent = "import failed // invalid json";
      showToast("NEOSCAN", "Selected file is not valid JSON.", "error");
      playSfx("error");
    }
  };
  reader.readAsText(file, "utf-8");
}

function updateAmbientHud() {
  const seed = Date.now() / 1000;
  refs.heroSignalIntegrity.textContent = `${(99 + Math.sin(seed / 6) * 0.4).toFixed(1)}%`;
  refs.heroCollectorCount.textContent = `${127 + (Math.floor(seed) % 2)} / 128`;
  refs.heroAssetFlow.textContent = `${640 + (Math.floor(seed * 13) % 110)} KB/S`;
}

function initAmbientLoops() {
  updateAmbientHud();
  state.heroFeedTimer = window.setInterval(() => {
    heroFeedPool.push(heroFeedPool.shift());
    renderFeedLine(refs.heroFeed, heroFeedPool[0], 3);
  }, 2800);

  state.intelFeedTimer = window.setInterval(() => {
    rotateIntelFeed();
  }, 5200);

  state.ambientTimer = window.setInterval(updateAmbientHud, 1400);
}

function initMatrixRain() {
  const canvas = refs.matrixRain;
  if (!canvas) {
    return;
  }
  const ctx = canvas.getContext("2d");
  if (!ctx) {
    return;
  }

  const glyphs = "01NEOSCAN";
  let width = 0;
  let height = 0;
  let columns = [];
  let fontSize = 16;

  function resize() {
    width = window.innerWidth;
    height = window.innerHeight;
    canvas.width = width;
    canvas.height = height;
    const count = Math.max(1, Math.floor(width / fontSize));
    columns = Array.from({ length: count }, () => Math.random() * height);
  }

  function draw() {
    ctx.fillStyle = "rgba(2, 3, 10, 0.08)";
    ctx.fillRect(0, 0, width, height);
    ctx.font = `${fontSize}px Fira Code`;

    columns.forEach((y, index) => {
      const x = index * fontSize;
      const glyph = glyphs[Math.floor(Math.random() * glyphs.length)];
      ctx.fillStyle = Math.random() > 0.92 ? "rgba(255,0,170,0.35)" : "rgba(0,240,255,0.22)";
      ctx.fillText(glyph, x, y);
      columns[index] = y > height + fontSize ? 0 : y + fontSize * (0.6 + Math.random() * 0.5);
    });
    requestAnimationFrame(draw);
  }

  resize();
  window.addEventListener("resize", resize);
  requestAnimationFrame(draw);
}

function initParticleField() {
  const canvas = refs.particleField;
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
    particles = Array.from({ length: 32 }, () => ({
      x: Math.random() * width,
      y: Math.random() * height,
      vx: (Math.random() - 0.5) * 0.25,
      vy: (Math.random() - 0.5) * 0.25,
      r: 1 + Math.random() * 2.2,
    }));
  }

  function draw() {
    ctx.clearRect(0, 0, width, height);
    particles.forEach((particle) => {
      particle.x += particle.vx;
      particle.y += particle.vy;
      if (particle.x < 0 || particle.x > width) {
        particle.vx *= -1;
      }
      if (particle.y < 0 || particle.y > height) {
        particle.vy *= -1;
      }

      ctx.beginPath();
      ctx.fillStyle = "rgba(0,240,255,0.4)";
      ctx.shadowBlur = 18;
      ctx.shadowColor = "rgba(0,240,255,0.3)";
      ctx.arc(particle.x, particle.y, particle.r, 0, Math.PI * 2);
      ctx.fill();
      ctx.shadowBlur = 0;
    });

    for (let i = 0; i < particles.length; i += 1) {
      for (let j = i + 1; j < particles.length; j += 1) {
        const dx = particles[i].x - particles[j].x;
        const dy = particles[i].y - particles[j].y;
        const distance = Math.hypot(dx, dy);
        if (distance < 160) {
          ctx.strokeStyle = `rgba(0,240,255,${0.08 - distance / 2400})`;
          ctx.lineWidth = 1;
          ctx.beginPath();
          ctx.moveTo(particles[i].x, particles[i].y);
          ctx.lineTo(particles[j].x, particles[j].y);
          ctx.stroke();
        }
      }
    }

    requestAnimationFrame(draw);
  }

  resize();
  window.addEventListener("resize", resize);
  requestAnimationFrame(draw);
}

function toggleTerminal(open) {
  refs.terminalOverlay.hidden = !open;
  if (open) {
    ensureTerminalBoot();
    refs.terminalCommandInput.focus();
  }
}

function handleTerminalCommand(command) {
  const input = normalizeTarget(command);
  if (!input) {
    return;
  }

  appendLog(`shell command // ${input}`, "info");
  const [verb, ...args] = input.split(/\s+/);
  const argString = args.join(" ");

  if (verb === "help") {
    appendLog("commands :: help | status | clear | scan <target> | load demo | view dashboard|console|results | export", "success");
    return;
  }

  if (verb === "status") {
    appendLog(`status :: ${state.scanning ? "SCANNING" : state.latestReport ? "READY" : "IDLE"} // source ${state.latestSource}`, "success");
    return;
  }

  if (verb === "clear") {
    refs.terminalOverlayLog.innerHTML = "";
    return;
  }

  if (verb === "view") {
    if (["dashboard", "console", "results"].includes(argString)) {
      setActiveView(argString, { scroll: true });
      appendLog(`view switched :: ${argString}`, "success");
      return;
    }
    appendLog("invalid view target. use dashboard, console, or results.", "error");
    return;
  }

  if (verb === "scan") {
    const target = argString || state.target;
    setTarget(target);
    startScan();
    return;
  }

  if (verb === "load" && argString === "demo") {
    if (!state.target) {
      setTarget("blackvault.neon");
    }
    startScan({ demo: true });
    return;
  }

  if (verb === "export") {
    downloadLatestReport();
    return;
  }

  appendLog(`unknown command :: ${input}`, "error");
}

function initCopyButtons() {
  refs.copyButtons.forEach((button) => {
    button.addEventListener("click", (event) => {
      event.preventDefault();
      event.stopPropagation();
      copyTargetContent(button.dataset.copyTarget);
    });
  });
}

function initBindings() {
  bindRipples();
  updateLanguage("en");
  seedRecentScans();
  renderRecentScans();
  renderMapPins();
  renderIntelFeed();
  updateDashboardStats();
  updateModuleCountChip();
  syncCustomPortField();
  updateStatusUi();
  refs.apiUrlInput.value = inferDefaultApiUrl();
  refs.resultSourceKpi.textContent = "NO DATA";
  refs.resultStatusKpi.textContent = "STANDBY";
  refs.resultTargetKpi.textContent = "NO TARGET";
  refs.rawJsonView.textContent = "{\n  \"status\": \"no evidence package yet\"\n}";

  [refs.navTargetInput, refs.heroTargetInput, refs.consoleTargetInput].forEach((input) => {
    input?.addEventListener("input", (event) => setTarget(event.target.value, event.target));
  });

  refs.navLaunchBtn?.addEventListener("click", () => {
    setTarget(refs.navTargetInput.value || state.target);
    setActiveView("console", { scroll: true });
  });

  refs.heroScanButton?.addEventListener("click", () => startScan());
  refs.consoleStartBtn?.addEventListener("click", () => startScan());
  refs.demoModeBtn?.addEventListener("click", () => startScan({ demo: true }));
  refs.demoSampleBtn?.addEventListener("click", () => {
    if (!state.target) {
      setTarget("blackvault.neon");
    }
    startScan({ demo: true });
  });
  refs.consoleStopBtn?.addEventListener("click", abortScan);
  refs.clearConsoleLogBtn?.addEventListener("click", clearScanLog);

  refs.viewTabs.forEach((button) => {
    button.addEventListener("click", () => setActiveView(button.dataset.viewTarget, { scroll: button.classList.contains("view-tab") }));
  });

  refs.resultTabs.forEach((button) => {
    button.addEventListener("click", () => setResultTab(button.dataset.resultTab));
  });

  refs.portModeInput?.addEventListener("change", syncCustomPortField);
  moduleDefs.forEach((module) => {
    module.input?.addEventListener("change", () => {
      updateModuleCountChip();
      refs.statusMode.textContent = isPortScanEnabled() ? refs.portModeInput.value.toUpperCase() : "INTEL";
    });
  });

  refs.importReportBtn?.addEventListener("click", () => refs.reportFileInput?.click());
  refs.reportFileInput?.addEventListener("change", (event) => {
    const file = event.target.files?.[0];
    if (file) {
      handleImportedReport(file);
    }
  });

  refs.downloadReportBtn?.addEventListener("click", downloadLatestReport);
  refs.darkWebExportBtn?.addEventListener("click", exportToDarkWeb);
  document.getElementById("copyFeedBtn")?.addEventListener("click", (event) => {
    event.preventDefault();
    copyTargetContent("intelFeed");
  });
  refs.rerenderGraphBtn?.addEventListener("click", () => {
    if (state.latestReport) {
      renderGraph(state.latestReport);
    }
  });

  refs.terminalFab?.addEventListener("click", () => toggleTerminal(true));
  refs.terminalCloseBtn?.addEventListener("click", () => toggleTerminal(false));
  refs.terminalCommandForm?.addEventListener("submit", (event) => {
    event.preventDefault();
    const command = refs.terminalCommandInput.value;
    refs.terminalCommandInput.value = "";
    handleTerminalCommand(command);
  });

  refs.mobileMenuToggle?.addEventListener("click", () => {
    const next = refs.mobileDrawer.hidden;
    refs.mobileDrawer.hidden = !next;
    refs.mobileMenuToggle.setAttribute("aria-expanded", String(next));
  });

  refs.mobileDrawer?.querySelectorAll("a, button").forEach((node) => {
    node.addEventListener("click", () => {
      refs.mobileDrawer.hidden = true;
      refs.mobileMenuToggle?.setAttribute("aria-expanded", "false");
    });
  });

  refs.langButtons.forEach((button) => {
    button.addEventListener("click", () => updateLanguage(button.dataset.lang));
  });

  window.addEventListener("keydown", (event) => {
    if (event.key === "Escape") {
      toggleTerminal(false);
      refs.mobileDrawer.hidden = true;
    }
  });

  window.addEventListener("resize", () => {
    if (state.latestReport) {
      renderGraph(state.latestReport);
    }
  });

  initCopyButtons();
  initAmbientLoops();
  initMatrixRain();
  initParticleField();

  const params = new URLSearchParams(window.location.search);
  const initialTarget = normalizeTarget(params.get("target"));
  const initialView = normalizeTarget(params.get("view")).toLowerCase();
  const initialTab = normalizeTarget(params.get("tab")).toLowerCase();

  if (initialTarget) {
    setTarget(initialTarget);
  }
  if (["dashboard", "console", "results"].includes(initialView)) {
    setActiveView(initialView, { scroll: false });
  }
  if (["overview", "recon", "network", "vulns", "json"].includes(initialTab)) {
    setResultTab(initialTab);
  }
}

initBindings();
