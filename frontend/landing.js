const bootOverlay = document.getElementById("bootOverlay");
const bootFeed = document.getElementById("bootFeed");
const navSignal = document.getElementById("navSignal");
const navClock = document.getElementById("navClock");
const heroFeed = document.getElementById("heroFeed");
const heroThreatLabel = document.getElementById("heroThreatLabel");
const heroGateStatus = document.getElementById("heroGateStatus");
const entryTone = document.getElementById("entryTone");
const heroVector = document.getElementById("heroVector");
const heroCoreState = document.getElementById("heroCoreState");
const heroCoreNote = document.getElementById("heroCoreNote");
const heroPacket = document.getElementById("heroPacket");
const heroNodeSync = document.getElementById("heroNodeSync");
const heroPulse = document.getElementById("heroPulse");
const snapshotThreat = document.getElementById("snapshotThreat");
const snapshotNodes = document.getElementById("snapshotNodes");
const snapshotSignal = document.getElementById("snapshotSignal");
const snapshotModules = document.getElementById("snapshotModules");
const transitionState = document.getElementById("transitionState");
const transitionCode = document.getElementById("transitionCode");
const launchButton = document.getElementById("launchButton");
const enterButton = document.getElementById("enterButton");
const TRANSITION_KEY = "tokihane-page-transition";
const landingDigitSelectors = [
  ".gate-nav",
  ".hero-stage",
  ".value-card",
  ".capability-band",
  ".workflow-step",
  ".snapshot-feature",
  ".snapshot-card",
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
  "[boot] loading target intelligence engine...",
  "[boot] syncing domain and asset collectors...",
  "[boot] preparing scan workspace...",
  "[boot] verifying DNS, web, and service probes...",
  "[boot] confirming export and report handlers...",
];

const feedMessages = [
  "target input queue is ready for domains, URLs, and IPs...",
  "dns, certificate, and web collectors are standing by...",
  "service checks are prepared for the next live scan...",
  "risk review pipeline is waiting for new findings...",
  "workspace telemetry is synced with scan modules...",
  "json export handler is ready for completed results...",
];

const threatStates = [
  {
    threat: "MONITORED",
    pulse: "LOW",
    tone: "READY",
    gate: "Scanner Ready",
    core: "TARGET READY",
    note: "Enter a domain, URL, or IP to start collection.",
    state: "READY FOR SCAN",
  },
  {
    threat: "REVIEW",
    pulse: "TRACKED",
    tone: "SYNCED",
    gate: "Sources Online",
    core: "ASSET DISCOVERY",
    note: "Collectors are staged for DNS, web assets, and service enumeration.",
    state: "MODULES ONLINE",
  },
  {
    threat: "ELEVATED",
    pulse: "HOT",
    tone: "ACTIVE",
    gate: "Scan Queue Live",
    core: "RISK REVIEW",
    note: "Reputation, exposed services, and web assets will be correlated after submission.",
    state: "COLLECTION ACTIVE",
  },
];

const vectors = [
  "TARGET GRID / 024.110 / 121.470",
  "TARGET GRID / 031.886 / 117.204",
  "TARGET GRID / 022.543 / 114.057",
  "TARGET GRID / 039.904 / 116.407",
];

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

function prefersReducedMotion() {
  return window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
}

function pickRandomDigit() {
  return digitCharacters[Math.floor(Math.random() * digitCharacters.length)] || "0";
}

function getDigitDensity() {
  if (document.documentElement.classList.contains("perf-lite")) {
    return 84;
  }
  return prefersReducedMotion() ? 48 : 168;
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
  } catch (error) {}

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
  } catch (error) {}

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

function updateClock() {
  if (!navClock) {
    return;
  }
  navClock.textContent = formatClock(new Date());
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

function updateLiveMetrics() {
  signalValue = clamp(signalValue + (Math.random() * 0.5 - 0.25), 97.8, 99.9);
  packetValue = clamp(packetValue + Math.floor(Math.random() * 42 - 21), 620, 860);
  nodeValue = clamp(nodeValue + Math.floor(Math.random() * 3 - 1), 124, 128);
  moduleValue = clamp(moduleValue + Math.floor(Math.random() * 3 - 1), 6, 10);

  if (navSignal) {
    navSignal.textContent = `${signalValue.toFixed(1)}%`;
  }
  if (heroPacket) {
    heroPacket.textContent = `${packetValue} KB/S`;
  }
  if (heroNodeSync) {
    heroNodeSync.textContent = `${nodeValue} / 128`;
  }
  if (snapshotNodes) {
    snapshotNodes.textContent = String(nodeValue);
  }
  if (snapshotSignal) {
    snapshotSignal.textContent = `${signalValue.toFixed(1)}%`;
  }
  if (snapshotModules) {
    snapshotModules.textContent = String(moduleValue).padStart(2, "0");
  }
}

function updateThreatState() {
  const state = threatStates[threatIndex % threatStates.length];
  const vector = vectors[threatIndex % vectors.length];

  if (heroThreatLabel) {
    heroThreatLabel.textContent = state.threat;
  }
  if (heroPulse) {
    heroPulse.textContent = state.pulse;
  }
  if (entryTone) {
    entryTone.textContent = state.tone;
  }
  if (heroGateStatus) {
    heroGateStatus.textContent = state.gate;
  }
  if (heroCoreState) {
    heroCoreState.textContent = state.core;
  }
  if (heroCoreNote) {
    heroCoreNote.textContent = state.note;
  }
  if (transitionState) {
    transitionState.textContent = state.state;
  }
  if (snapshotThreat) {
    snapshotThreat.textContent = state.threat;
  }
  if (heroVector) {
    heroVector.textContent = vector;
  }
  if (transitionCode) {
    transitionCode.textContent = `TKH-${String(nodeValue).padStart(3, "0")}-${state.threat}`;
  }

  threatIndex += 1;
}

function cycleFeed() {
  const message = feedMessages[feedIndex % feedMessages.length];
  appendFeedLine(heroFeed, message, 4);
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

  if (!bootOverlay || !bootFeed) {
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
    appendFeedLine(bootFeed, bootMessages[index], 5);
    index += 1;
  }, 220);
}

function shouldUsePerfLite() {
  const reduceMotion = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  const cores = Number(navigator.hardwareConcurrency || 8);
  const memory = Number(navigator.deviceMemory || 8);
  return reduceMotion || cores <= 4 || memory <= 4;
}

function applyPerformancePreset() {
  document.documentElement.classList.toggle("perf-lite", shouldUsePerfLite());
}

function initLaserRain() {
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
  window.addEventListener("resize", resize);

  const fps = 24;
  const frameDuration = 1000 / fps;
  let lastTime = 0;
  function loop(time) {
    if (!document.hidden && time - lastTime >= frameDuration) {
      draw();
      lastTime = time;
    }
    requestAnimationFrame(loop);
  }
  requestAnimationFrame(loop);
}

function initParticleField() {
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
    const count = document.documentElement.classList.contains("perf-lite") ? 18 : 34;
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
  window.addEventListener("resize", resize);

  const fps = 18;
  const frameDuration = 1000 / fps;
  let lastTime = 0;
  function loop(time) {
    if (!document.hidden && time - lastTime >= frameDuration) {
      draw();
      lastTime = time;
    }
    requestAnimationFrame(loop);
  }
  requestAnimationFrame(loop);
}

function initEntryLinks() {
  Array.from(document.querySelectorAll('a[href="./console.html"]')).forEach((link) => {
    if (!link) {
      return;
    }
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

applyPerformancePreset();
initReturnAssembly();
initBootSequence();
updateClock();
updateLiveMetrics();
updateThreatState();
cycleFeed();
initLaserRain();
initParticleField();
initEntryLinks();

window.setInterval(updateClock, 1000);
window.setInterval(updateLiveMetrics, 1400);
window.setInterval(updateThreatState, 3200);
window.setInterval(cycleFeed, 2600);
