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

const bootMessages = [
  "[boot] aligning silent access corridor...",
  "[boot] stabilizing cyan lattice envelope...",
  "[boot] preparing console handoff sequence...",
  "[boot] verifying low-noise HUD channels...",
  "[boot] confirming operator-ready transition gate...",
];

const feedMessages = [
  "entry corridor secured through cold channel seven...",
  "future terminal posture remains stable and silent...",
  "recon bridge prepared for module handoff...",
  "threat lattice monitoring edge anomalies...",
  "lock vector calibrated for console transition...",
  "system gate holding quiet breach stance...",
];

const threatStates = [
  {
    threat: "WATCHFUL",
    pulse: "ELEVATED",
    tone: "STABLE",
    gate: "Console Ready",
    core: "SILENT ACCESS",
    note: "The entry system holds a cold lock while waiting for operator takeover.",
    state: "READY TO DEPLOY",
  },
  {
    threat: "FOCUSED",
    pulse: "TRACKED",
    tone: "TRACKING",
    gate: "Transition Armed",
    core: "SIGNAL LOCK",
    note: "The core node is drawing attention inward and the console transfer path is already formed.",
    state: "CHANNELS PRIMED",
  },
  {
    threat: "ELEVATED",
    pulse: "HOT",
    tone: "ACTIVE",
    gate: "Corridor Live",
    core: "THREAT LENS",
    note: "Edge anomalies remain under watch while the system preserves a quiet sense of danger.",
    state: "ENTRY WINDOW OPEN",
  },
];

const vectors = [
  "LOCK VECTOR / 024.110 / 121.470",
  "LOCK VECTOR / 031.886 / 117.204",
  "LOCK VECTOR / 022.543 / 114.057",
  "LOCK VECTOR / 039.904 / 116.407",
];

let feedIndex = 0;
let threatIndex = 0;
let packetValue = 682;
let nodeValue = 128;
let signalValue = 99.1;
let moduleValue = 8;

function clamp(value, min, max) {
  return Math.max(min, Math.min(max, value));
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
  [launchButton, enterButton].forEach((link) => {
    if (!link) {
      return;
    }
    link.addEventListener("click", (event) => {
      const href = link.getAttribute("href");
      if (!href) {
        return;
      }
      event.preventDefault();
      document.body.classList.add("is-entering");
      document.body.classList.add("sweep-active");
      window.setTimeout(() => {
        window.location.href = href;
      }, 220);
    });
  });
}

applyPerformancePreset();
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
