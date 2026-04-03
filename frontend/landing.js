const bootOverlay = document.getElementById("bootOverlay");
const bootFeed = document.getElementById("bootFeed");
const heroFeed = document.getElementById("heroFeed");
const telemetryList = document.getElementById("telemetryList");
const channelList = document.getElementById("channelList");
const gateClock = document.getElementById("gateClock");
const timestampReadout = document.getElementById("timestampReadout");
const signalQuality = document.getElementById("signalQuality");
const packetFlow = document.getElementById("packetFlow");
const nodeSync = document.getElementById("nodeSync");
const threatPulse = document.getElementById("threatPulse");
const threatIndex = document.getElementById("threatIndex");
const threatBar = document.getElementById("threatBar");
const threatState = document.getElementById("threatState");
const latencyPulse = document.getElementById("latencyPulse");
const channelCount = document.getElementById("channelCount");
const channelState = document.getElementById("channelState");
const nodeStability = document.getElementById("nodeStability");
const encryptedTunnels = document.getElementById("encryptedTunnels");
const packetIntegrity = document.getElementById("packetIntegrity");
const reconWindows = document.getElementById("reconWindows");
const sectorReadout = document.getElementById("sectorReadout");
const vectorReadout = document.getElementById("vectorReadout");
const vectorLock = document.getElementById("vectorLock");
const systemLog = document.getElementById("systemLog");
const systemLogState = document.getElementById("systemLogState");
const enterButton = document.getElementById("enterButton");
const threatCard = document.querySelector(".intel-card--threat");
const topbarLiveChip = document.querySelector(".topbar-chip--live");

const bootMessages = [
  "[boot] calibrating skyline pulse array...",
  "[boot] binding encrypted uplink channels...",
  "[boot] syncing threat lattice watchers...",
  "[boot] priming neon city telemetry mesh...",
  "[boot] confirming recon console handoff...",
  "[boot] verifying anomaly countermeasures...",
];

const heroMessages = [
  "AUTH handshake secured through cold channel 07.",
  "Three thousand virtual sectors now orbit the main frame.",
  "Quantum packet filters are tracking hostile bloom signatures.",
  "City-grid pulse array is alive and waiting for operator intent.",
  "Console bridge prepared for recon, scan, and threat correlation.",
  "Anomaly watchdogs are shadowing redline interference.",
];

const threatModes = [
  { label: "WATCHFUL", meter: 46, tone: "ok", channel: "ENCRYPTED", summary: "SPECTRUM STABLE / EDGE NOISE CONTAINED" },
  { label: "ELEVATED", meter: 73, tone: "alert", channel: "FILTERING", summary: "ANOMALY CLUSTERS MOVING THROUGH OUTER CITY GRID" },
  { label: "FOCUSED", meter: 61, tone: "ok", channel: "TRACKED", summary: "INTEL LOCKED / HIGH-VALUE SIGNALS UNDER OBSERVATION" },
  { label: "VOLATILE", meter: 85, tone: "alert", channel: "LOCKDOWN", summary: "CRITICAL HEAT BLOOMS TRACKED ACROSS CORE ROUTES" },
];

const sectors = [
  "NEON-17 / SHD-ARC",
  "GRID-09 / TOKI-RING",
  "ZONE-44 / SKY-VAULT",
  "SIGMA-12 / CITY-CORE",
  "GHOST-31 / RED-VAULT",
];

const channelInventory = [
  { label: "BLACK ICE", state: "ONLINE", tone: "ok" },
  { label: "NODE 17", state: "SEALED", tone: "ok" },
  { label: "ARC-LINK", state: "LOCKED", tone: "ok" },
  { label: "SIGINT", state: "UPLINK", tone: "ok" },
  { label: "REDLINE", state: "SYNCHED", tone: "ok" },
  { label: "VOIDBUS", state: "GHOSTED", tone: "ok" },
];

const channelStatePool = [
  { state: "ONLINE", tone: "ok" },
  { state: "SYNCED", tone: "ok" },
  { state: "SEALED", tone: "ok" },
  { state: "TRACE", tone: "ok" },
  { state: "FILTER", tone: "ok" },
  { state: "WARNING", tone: "alert" },
  { state: "SPIKE", tone: "alert" },
  { state: "JAMMED", tone: "alert" },
];

const logTemplates = [
  { tone: "ok", text: "node sync reaffirmed across skyline lattice" },
  { tone: "ok", text: "encrypted channel cascade remains stable" },
  { tone: "ok", text: "packet mirrors aligned with recon nucleus" },
  { tone: "ok", text: "city-grid telemetry refreshed from cold relay" },
  { tone: "ok", text: "operator entry corridor is standing by" },
  { tone: "alert", text: "anomaly detected on shadow relay / rerouting trace" },
  { tone: "alert", text: "threat bloom spiking near outer sector ingress" },
  { tone: "alert", text: "redline packet turbulence breaching threshold" },
  { tone: "alert", text: "hostile signal shimmer identified in transit mesh" },
  { tone: "alert", text: "warning: channel interference rising on node ring" },
];

const liveState = {
  signal: 99.2,
  packet: 684,
  latency: 18,
  nodes: 128,
  stability: 99.982,
  integrity: 96.4,
  tunnels: 42,
  windows: 8,
  vectorLat: 24.11,
  vectorLon: 121.47,
  altitude: 212,
  sector: sectors[0],
  threat: threatModes[1],
};

let heroMessageIndex = 0;
let telemetryOffset = 0;
let threatModeIndex = 1;
let sweepTimerId = null;
let isEntering = false;

function clamp(value, min, max) {
  return Math.min(max, Math.max(min, value));
}

function randomChoice(list) {
  return list[Math.floor(Math.random() * list.length)];
}

function shouldUsePerfLite() {
  const reduceMotion = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  const cores = Number(navigator.hardwareConcurrency || 8);
  const memory = Number(navigator.deviceMemory || 8);
  return reduceMotion || cores <= 4 || memory <= 4;
}

function applyPerformancePreset() {
  const perfLite = shouldUsePerfLite();
  document.documentElement.classList.toggle("perf-lite", perfLite);
  return perfLite;
}

function setStatusWord(element, value, tone = "ok") {
  if (!element) {
    return;
  }
  element.textContent = value;
  element.classList.remove("status-word--ok", "status-word--alert");
  element.classList.add(tone === "alert" ? "status-word--alert" : "status-word--ok");
}

function appendTerminalLine(container, text, limit = 6) {
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

function renderIntelList(container, items) {
  if (!container) {
    return;
  }
  container.innerHTML = "";

  items.forEach((item) => {
    const row = document.createElement("div");
    row.className = "intel-item";
    row.dataset.tone = item.tone || "ok";
    if (item.flash) {
      row.dataset.flash = "true";
    }

    const label = document.createElement("span");
    label.textContent = item.label;

    const value = document.createElement("strong");
    value.textContent = item.value;
    if (item.emphasis === "status") {
      value.classList.add("status-word", item.tone === "alert" ? "status-word--alert" : "status-word--ok");
    }

    row.append(label, value);
    container.appendChild(row);
  });
}

function formatClockStamp(date) {
  return date.toLocaleString("zh-CN", {
    hour12: false,
    timeZone: "Asia/Shanghai",
  });
}

function formatShortTime(date) {
  return date.toLocaleTimeString("zh-CN", {
    hour12: false,
    timeZone: "Asia/Shanghai",
  });
}

function updateClock() {
  const now = new Date();
  setStatusWord(gateClock, formatShortTime(now), "ok");
  if (timestampReadout) {
    timestampReadout.textContent = formatClockStamp(now);
  }
}

function pushSystemLog(template) {
  if (!systemLog) {
    return;
  }

  const entry = document.createElement("div");
  entry.className = "system-log__entry";
  entry.dataset.tone = template.tone || "ok";
  entry.dataset.typing = "true";

  const time = document.createElement("span");
  time.className = "system-log__time";
  time.textContent = `[${formatShortTime(new Date())}]`;

  const message = document.createElement("span");
  message.className = "system-log__message";

  entry.append(time, message);
  systemLog.appendChild(entry);

  while (systemLog.children.length > 16) {
    systemLog.removeChild(systemLog.firstElementChild);
  }

  let charIndex = 0;
  const fullText = template.text;
  const typingDelay = template.tone === "alert" ? 14 : 18;

  const intervalId = window.setInterval(() => {
    message.textContent = `${fullText.slice(0, charIndex)}${charIndex < fullText.length ? "_" : ""}`;
    charIndex += 1;
    if (charIndex > fullText.length) {
      window.clearInterval(intervalId);
      message.textContent = fullText;
      entry.dataset.typing = "false";
      entry.removeAttribute("data-typing");
    }
    systemLog.scrollTop = systemLog.scrollHeight;
  }, typingDelay);
}

function updateLiveMetrics() {
  liveState.signal = clamp(liveState.signal + (Math.random() * 0.72 - 0.36), 96.9, 99.9);
  liveState.packet = clamp(liveState.packet + Math.floor(Math.random() * 60 - 30), 520, 860);
  liveState.latency = clamp(liveState.latency + Math.floor(Math.random() * 5 - 2), 11, 34);
  liveState.nodes = clamp(liveState.nodes + Math.floor(Math.random() * 3 - 1), 124, 128);
  liveState.stability = clamp(liveState.stability + (Math.random() * 0.024 - 0.012), 99.821, 99.998);
  liveState.integrity = clamp(liveState.integrity + (Math.random() * 0.8 - 0.4), 94.8, 98.4);
  liveState.tunnels = clamp(liveState.tunnels + Math.floor(Math.random() * 3 - 1), 37, 49);
  liveState.windows = clamp(liveState.windows + Math.floor(Math.random() * 3 - 1), 6, 12);
  liveState.vectorLat = clamp(liveState.vectorLat + (Math.random() * 0.018 - 0.009), 24.05, 24.19);
  liveState.vectorLon = clamp(liveState.vectorLon + (Math.random() * 0.018 - 0.009), 121.41, 121.53);
  liveState.altitude = clamp(liveState.altitude + Math.floor(Math.random() * 9 - 4), 186, 268);

  if (signalQuality) {
    signalQuality.textContent = `${liveState.signal.toFixed(1)}%`;
  }
  if (packetFlow) {
    packetFlow.textContent = `${liveState.packet} KB/S`;
  }
  if (latencyPulse) {
    setStatusWord(latencyPulse, `${liveState.latency} MS`, liveState.latency >= 24 ? "alert" : "ok");
  }
  if (nodeSync) {
    nodeSync.textContent = `${liveState.nodes}/128`;
  }
  if (nodeStability) {
    nodeStability.textContent = `${liveState.stability.toFixed(3)}%`;
  }
  if (packetIntegrity) {
    packetIntegrity.textContent = `${liveState.integrity.toFixed(1)}%`;
  }
  if (encryptedTunnels) {
    encryptedTunnels.textContent = String(liveState.tunnels);
  }
  if (reconWindows) {
    reconWindows.textContent = String(liveState.windows).padStart(2, "0");
  }
  if (vectorReadout) {
    vectorReadout.textContent = `${liveState.vectorLat.toFixed(3)} / ${liveState.vectorLon.toFixed(3)} / ALT ${liveState.altitude}`;
  }
  if (vectorLock) {
    vectorLock.textContent = `VECTOR LOCK / ${liveState.vectorLat.toFixed(3)}N ${liveState.vectorLon.toFixed(3)}E`;
  }
}

function applyThreatVisualState(mode) {
  const isAlert = mode.tone === "alert";
  if (threatCard) {
    threatCard.classList.toggle("is-alert", isAlert);
  }
  if (topbarLiveChip) {
    topbarLiveChip.classList.toggle("is-alert", isAlert);
  }
  setStatusWord(threatPulse, mode.label, isAlert ? "alert" : "ok");
  setStatusWord(channelState, mode.channel, isAlert ? "alert" : "ok");
  setStatusWord(systemLogState, isAlert ? "ANOMALY WATCH" : "SYSTEM READY", isAlert ? "alert" : "ok");
  if (threatIndex) {
    setStatusWord(threatIndex, String(mode.meter), isAlert ? "alert" : "ok");
  }
}

function rotateThreatMode() {
  const mode = threatModes[threatModeIndex % threatModes.length];
  threatModeIndex += 1;
  liveState.threat = mode;

  applyThreatVisualState(mode);

  if (threatBar) {
    threatBar.style.width = `${mode.meter}%`;
  }
  if (threatState) {
    threatState.textContent = mode.summary;
  }
}

function rotateSector() {
  liveState.sector = randomChoice(sectors);
  if (sectorReadout) {
    sectorReadout.textContent = liveState.sector;
  }
}

function cycleHeroFeed() {
  const baseMessage = heroMessages[heroMessageIndex % heroMessages.length];
  heroMessageIndex += 1;
  const prefix = liveState.threat.tone === "alert" && Math.random() < 0.45 ? "[ALERT]" : "[LIVE]";
  appendTerminalLine(heroFeed, `${prefix} ${baseMessage}`, 6);
}

function buildTelemetryItems() {
  return [
    { label: "PACKET BURST", value: `${liveState.packet} KB/S`, tone: "ok" },
    { label: "NODE MIRROR", value: `${liveState.nodes} ACTIVE`, tone: liveState.nodes < 126 ? "alert" : "ok" },
    { label: "SIGMA GATE", value: liveState.signal > 98.5 ? "READY" : "HOLD", tone: liveState.signal > 98.5 ? "ok" : "alert", emphasis: "status" },
    { label: "THREAT BLOOM", value: liveState.threat.label, tone: liveState.threat.tone, emphasis: "status" },
    { label: "TRACE DEPTH", value: `${7 + Math.floor(liveState.packet / 80)} LAYERS`, tone: "ok" },
    { label: "RELAY DRIFT", value: `${liveState.latency} MS`, tone: liveState.latency > 23 ? "alert" : "ok" },
    { label: "NEURAL CACHE", value: liveState.integrity > 95.6 ? "READY" : "REBUILD", tone: liveState.integrity > 95.6 ? "ok" : "alert", emphasis: "status" },
    { label: "SCAN WINDOW", value: liveState.windows > 7 ? "OPEN" : "NARROW", tone: liveState.windows > 7 ? "ok" : "alert", emphasis: "status" },
  ];
}

function rotateTelemetry() {
  const source = buildTelemetryItems();
  const items = [];
  for (let index = 0; index < 4; index += 1) {
    items.push(source[(telemetryOffset + index) % source.length]);
  }
  telemetryOffset = (telemetryOffset + 1) % source.length;
  renderIntelList(telemetryList, items);
}

function mutateChannels() {
  const flashLabels = new Set();
  const mutationCount = liveState.threat.tone === "alert" ? 2 : 1;
  for (let index = 0; index < mutationCount; index += 1) {
    const channel = randomChoice(channelInventory);
    const nextState = randomChoice(channelStatePool);
    channel.state = nextState.state;
    channel.tone = nextState.tone;
    flashLabels.add(channel.label);
  }

  const activeCount = channelInventory.filter((channel) => channel.tone !== "alert").length;
  if (channelCount) {
    setStatusWord(channelCount, String(activeCount).padStart(2, "0"), activeCount < 5 ? "alert" : "ok");
  }

  renderIntelList(
    channelList,
    channelInventory.map((channel) => ({
      label: channel.label,
      value: channel.state,
      tone: channel.tone,
      emphasis: "status",
      flash: flashLabels.has(channel.label),
    })),
  );
}

function initChannels() {
  mutateChannels();
}

function triggerPageSweep() {
  document.body.classList.remove("sweep-active");
  window.requestAnimationFrame(() => {
    document.body.classList.add("sweep-active");
  });
  window.clearTimeout(sweepTimerId);
  sweepTimerId = window.setTimeout(() => {
    document.body.classList.remove("sweep-active");
  }, 1450);
}

function schedulePageSweeps(perfLite) {
  const minDelay = perfLite ? 6800 : 4200;
  const maxJitter = perfLite ? 2200 : 1800;

  function loop() {
    const delay = minDelay + Math.floor(Math.random() * maxJitter);
    window.setTimeout(() => {
      triggerPageSweep();
      loop();
    }, delay);
  }

  loop();
}

function initBootOverlay() {
  let bootIndex = 0;
  const intervalId = window.setInterval(() => {
    appendTerminalLine(bootFeed, bootMessages[bootIndex % bootMessages.length], 6);
    bootIndex += 1;
  }, 220);

  window.setTimeout(() => {
    window.clearInterval(intervalId);
    document.body.classList.add("is-loaded");
    if (bootOverlay) {
      bootOverlay.setAttribute("aria-hidden", "true");
    }
  }, 1750);
}

function initParallax() {
  const targets = Array.from(document.querySelectorAll("[data-parallax]"));
  if (!targets.length) {
    return;
  }

  function reset() {
    targets.forEach((target) => {
      target.style.transform = "";
    });
  }

  window.addEventListener("mousemove", (event) => {
    const x = event.clientX / window.innerWidth - 0.5;
    const y = event.clientY / window.innerHeight - 0.5;
    targets.forEach((target) => {
      const factor = Number(target.getAttribute("data-parallax") || 0);
      const moveX = x * factor;
      const moveY = y * factor;
      target.style.transform = `translate3d(${moveX}px, ${moveY}px, 0)`;
    });
  });

  window.addEventListener("mouseleave", reset);
}

function initEnterTransition() {
  const links = Array.from(document.querySelectorAll('a[href="./console.html"]'));
  links.forEach((link) => {
    link.addEventListener("click", (event) => {
      if (event.metaKey || event.ctrlKey || event.shiftKey || event.altKey || isEntering) {
        return;
      }
      event.preventDefault();
      isEntering = true;
      pushSystemLog({ tone: "ok", text: "operator handshake confirmed / initiating console bridge" });
      triggerPageSweep();
      document.body.classList.add("is-entering");
      window.setTimeout(() => {
        window.location.href = link.href;
      }, 430);
    });
  });

  if (enterButton) {
    enterButton.addEventListener("mouseenter", () => {
      if (Math.random() < 0.56) {
        triggerPageSweep();
      }
    });
  }
}

function initSystemLogs() {
  const initialEntries = [
    { tone: "ok", text: "quantum access gate online / awaiting operator intent" },
    { tone: "ok", text: "node sync revalidated against skyline relay mesh" },
    { tone: "alert", text: "warning: anomaly residue persists in lower city channel" },
  ];
  initialEntries.forEach((entry) => pushSystemLog(entry));
}

function feedSystemLogs() {
  const prefersAlert = liveState.threat.tone === "alert" || Math.random() < 0.32;
  const candidates = logTemplates.filter((entry) => (prefersAlert ? entry.tone === "alert" : entry.tone === "ok"));
  pushSystemLog(randomChoice(candidates));
}

function initLaserRain(perfLite) {
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
  let dpr = 1;
  const streaks = [];
  const glyphs = "01ZXTOKI<>[]{}#%";
  const streakCount = perfLite ? 58 : 124;

  function resize() {
    dpr = perfLite ? 1 : Math.min(1.6, window.devicePixelRatio || 1);
    width = window.innerWidth;
    height = window.innerHeight;
    canvas.width = Math.floor(width * dpr);
    canvas.height = Math.floor(height * dpr);
    canvas.style.width = `${width}px`;
    canvas.style.height = `${height}px`;
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);

    streaks.length = 0;
    for (let index = 0; index < streakCount; index += 1) {
      const anomaly = Math.random() < 0.18;
      const depth = 0.45 + Math.random() * 0.9;
      streaks.push({
        x: Math.random() * width,
        y: Math.random() * height,
        len: (30 + Math.random() * 220) * depth,
        speed: (1.8 + Math.random() * 4.8) * depth,
        drift: -0.35 + Math.random() * 0.7,
        alpha: 0.12 + Math.random() * 0.36,
        hue: anomaly ? 354 + Math.random() * 4 : 122 + Math.random() * 14,
        width: anomaly ? 1.8 : 1.1 + Math.random() * 0.4,
        anomaly,
      });
    }
  }

  function drawGlyph(x, y, hue, anomaly) {
    ctx.save();
    ctx.fillStyle = `hsla(${hue}, 96%, ${anomaly ? 68 : 74}%, 0.92)`;
    ctx.font = anomaly ? "700 13px Share Tech Mono" : "12px Share Tech Mono";
    ctx.fillText(glyphs[Math.floor(Math.random() * glyphs.length)], x + 4, y + 10);
    ctx.restore();
  }

  const targetFps = perfLite ? 24 : 38;
  const frameLength = 1000 / targetFps;
  let lastTime = 0;

  function draw() {
    ctx.fillStyle = "rgba(1, 4, 3, 0.2)";
    ctx.fillRect(0, 0, width, height);
    ctx.lineCap = "round";

    streaks.forEach((streak) => {
      const gradient = ctx.createLinearGradient(streak.x, streak.y, streak.x + streak.drift * streak.len, streak.y + streak.len);
      gradient.addColorStop(0, `hsla(${streak.hue}, 100%, 62%, 0)`);
      gradient.addColorStop(0.24, `hsla(${streak.hue}, 100%, 62%, ${streak.alpha})`);
      gradient.addColorStop(1, `hsla(${streak.hue}, 100%, 62%, 0)`);

      ctx.strokeStyle = gradient;
      ctx.lineWidth = streak.width;
      ctx.shadowBlur = streak.anomaly ? 16 : 10;
      ctx.shadowColor = `hsla(${streak.hue}, 100%, 62%, ${streak.anomaly ? 0.34 : 0.22})`;
      ctx.beginPath();
      ctx.moveTo(streak.x, streak.y);
      ctx.lineTo(streak.x + streak.drift * streak.len, streak.y + streak.len);
      ctx.stroke();
      ctx.shadowBlur = 0;

      if (!perfLite && Math.random() < (streak.anomaly ? 0.24 : 0.12)) {
        drawGlyph(streak.x, streak.y + streak.len * 0.22, streak.hue, streak.anomaly);
      }

      streak.y += streak.speed;
      streak.x += streak.drift * 0.18;

      if (streak.y - streak.len > height) {
        streak.x = Math.random() * width;
        streak.y = -streak.len;
      }
      if (streak.x < -100 || streak.x > width + 100) {
        streak.x = Math.random() * width;
      }
    });
  }

  function loop(timestamp) {
    if (!document.hidden && (!lastTime || timestamp - lastTime >= frameLength)) {
      draw();
      lastTime = timestamp;
    }
    window.requestAnimationFrame(loop);
  }

  resize();
  window.addEventListener("resize", resize);
  window.requestAnimationFrame(loop);
}

function initParticleField(perfLite) {
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
  let dpr = 1;
  const particles = [];
  const count = perfLite ? 28 : 66;

  function resize() {
    dpr = perfLite ? 1 : Math.min(1.6, window.devicePixelRatio || 1);
    width = window.innerWidth;
    height = window.innerHeight;
    canvas.width = Math.floor(width * dpr);
    canvas.height = Math.floor(height * dpr);
    canvas.style.width = `${width}px`;
    canvas.style.height = `${height}px`;
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);

    particles.length = 0;
    for (let index = 0; index < count; index += 1) {
      const depth = 0.28 + Math.random() * 1.18;
      const anomaly = Math.random() < 0.14;
      particles.push({
        x: Math.random() * width,
        y: Math.random() * height,
        px: Math.random() * width,
        py: Math.random() * height,
        size: 0.8 + depth * 2.1,
        depth,
        vx: (-0.12 + Math.random() * 0.24) * depth,
        vy: (0.08 + Math.random() * 0.32) * depth,
        hue: anomaly ? 352 + Math.random() * 6 : 120 + Math.random() * 16,
        anomaly,
      });
    }
  }

  const targetFps = perfLite ? 20 : 32;
  const frameLength = 1000 / targetFps;
  let lastTime = 0;

  function drawConnections() {
    if (perfLite) {
      return;
    }
    for (let i = 0; i < particles.length; i += 1) {
      for (let j = i + 1; j < particles.length; j += 1) {
        const a = particles[i];
        const b = particles[j];
        const dx = a.x - b.x;
        const dy = a.y - b.y;
        const distance = Math.hypot(dx, dy);
        if (distance > 150 || Math.abs(a.depth - b.depth) > 0.45) {
          continue;
        }
        const alpha = 0.075 * (1 - distance / 150);
        const hue = a.anomaly || b.anomaly ? 354 : 128;
        ctx.strokeStyle = `hsla(${hue}, 96%, 66%, ${alpha})`;
        ctx.lineWidth = 0.6;
        ctx.beginPath();
        ctx.moveTo(a.x, a.y);
        ctx.lineTo(b.x, b.y);
        ctx.stroke();
      }
    }
  }

  function draw() {
    ctx.clearRect(0, 0, width, height);
    drawConnections();

    particles.forEach((particle) => {
      particle.px = particle.x;
      particle.py = particle.y;
      particle.x += particle.vx;
      particle.y += particle.vy;

      if (particle.x < -40) particle.x = width + 40;
      if (particle.x > width + 40) particle.x = -40;
      if (particle.y < -40) particle.y = height + 40;
      if (particle.y > height + 40) particle.y = -40;

      ctx.strokeStyle = `hsla(${particle.hue}, 96%, ${particle.anomaly ? 66 : 72}%, ${0.08 + particle.depth * 0.08})`;
      ctx.lineWidth = particle.anomaly ? 1.2 : 0.9;
      ctx.beginPath();
      ctx.moveTo(particle.px, particle.py);
      ctx.lineTo(particle.x, particle.y);
      ctx.stroke();

      ctx.beginPath();
      ctx.fillStyle = `hsla(${particle.hue}, 96%, ${particle.anomaly ? 66 : 72}%, ${0.22 + particle.depth * 0.26})`;
      ctx.shadowBlur = 10 + particle.depth * 6;
      ctx.shadowColor = `hsla(${particle.hue}, 96%, 68%, ${0.18 + particle.depth * 0.18})`;
      ctx.arc(particle.x, particle.y, particle.size, 0, Math.PI * 2);
      ctx.fill();
      ctx.shadowBlur = 0;
    });
  }

  function loop(timestamp) {
    if (!document.hidden && (!lastTime || timestamp - lastTime >= frameLength)) {
      draw();
      lastTime = timestamp;
    }
    window.requestAnimationFrame(loop);
  }

  resize();
  window.addEventListener("resize", resize);
  window.requestAnimationFrame(loop);
}

const perfLite = applyPerformancePreset();
updateClock();
updateLiveMetrics();
rotateThreatMode();
rotateSector();
rotateTelemetry();
cycleHeroFeed();
initChannels();
initBootOverlay();
initParallax();
initEnterTransition();
initSystemLogs();
initLaserRain(perfLite);
initParticleField(perfLite);
schedulePageSweeps(perfLite);

window.setInterval(updateClock, 1000);
window.setInterval(updateLiveMetrics, 960);
window.setInterval(rotateThreatMode, 2600);
window.setInterval(rotateSector, 3200);
window.setInterval(cycleHeroFeed, 2000);
window.setInterval(rotateTelemetry, 1500);
window.setInterval(mutateChannels, 2100);
window.setInterval(feedSystemLogs, 1700);
