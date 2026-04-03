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
const nodeStability = document.getElementById("nodeStability");
const encryptedTunnels = document.getElementById("encryptedTunnels");
const packetIntegrity = document.getElementById("packetIntegrity");
const reconWindows = document.getElementById("reconWindows");
const sectorReadout = document.getElementById("sectorReadout");
const vectorReadout = document.getElementById("vectorReadout");
const vectorLock = document.getElementById("vectorLock");

const bootMessages = [
  "[boot] calibrating skyline pulse array...",
  "[boot] binding encrypted uplink channels...",
  "[boot] syncing threat lattice watchers...",
  "[boot] priming neon city telemetry mesh...",
  "[boot] confirming recon console handoff...",
];

const heroMessages = [
  "AUTH handshake secured through cold channel 07.",
  "Three thousand virtual sectors now orbit the main frame.",
  "Quantum packet filters are tracking hostile bloom signatures.",
  "City-grid pulse array is alive and waiting for operator intent.",
  "Console bridge prepared for recon, scan, and threat correlation.",
];

const telemetryMessages = [
  { label: "PACKET BURST", value: "684 KB/S" },
  { label: "NODE MIRROR", value: "128 ACTIVE" },
  { label: "SIGMA GATE", value: "STABLE" },
  { label: "THREAT BLOOM", value: "LOW VOLUME" },
  { label: "SKYLINE LINK", value: "SYNCED" },
  { label: "TRACE DEPTH", value: "11 LAYERS" },
  { label: "NEURAL CACHE", value: "READY" },
  { label: "SCAN WINDOW", value: "OPEN" },
];

const channelMessages = [
  { label: "BLACK ICE", value: "ONLINE" },
  { label: "NODE 17", value: "SEALED" },
  { label: "ARC-LINK", value: "LOCKED" },
  { label: "SIGINT", value: "UPLINK" },
  { label: "REDLINE", value: "SYNCHED" },
  { label: "VOIDBUS", value: "GHOSTED" },
];

const threatModes = [
  { label: "WATCHFUL", meter: 46, tone: "SPECTRUM STABLE / EDGE NOISE CONTAINED" },
  { label: "ELEVATED", meter: 73, tone: "ANOMALY CLUSTERS MOVING THROUGH OUTER CITY GRID" },
  { label: "FOCUSED", meter: 61, tone: "INTEL LOCKED / HIGH-VALUE SIGNALS UNDER OBSERVATION" },
  { label: "VOLATILE", meter: 85, tone: "CRITICAL HEAT BLOOMS TRACKED ACROSS CORE ROUTES" },
];

const sectors = [
  "NEON-17 / SHD-ARC",
  "GRID-09 / TOKI-RING",
  "ZONE-44 / SKY-VAULT",
  "SIGMA-12 / CITY-CORE",
];

let heroMessageIndex = 0;
let telemetryOffset = 0;
let threatModeIndex = 0;

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

function appendTerminalLine(container, text, limit = 5) {
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
    const label = document.createElement("span");
    label.textContent = item.label;
    const value = document.createElement("strong");
    value.textContent = item.value;
    row.append(label, value);
    container.appendChild(row);
  });
}

function updateClock() {
  const now = new Date();
  const time = now.toLocaleTimeString("zh-CN", {
    hour12: false,
    timeZone: "Asia/Shanghai",
  });
  const stamp = now.toLocaleString("zh-CN", {
    hour12: false,
    timeZone: "Asia/Shanghai",
  });
  if (gateClock) {
    gateClock.textContent = time;
  }
  if (timestampReadout) {
    timestampReadout.textContent = stamp;
  }
}

function updateLiveMetrics() {
  const signal = (98 + Math.random() * 1.8).toFixed(1);
  const packet = 540 + Math.floor(Math.random() * 220);
  const latency = 12 + Math.floor(Math.random() * 14);
  const nodeNumerator = 124 + Math.floor(Math.random() * 5);
  const stability = (99.82 + Math.random() * 0.17).toFixed(3);
  const integrity = (95.8 + Math.random() * 2.4).toFixed(1);
  const tunnels = 38 + Math.floor(Math.random() * 9);
  const windows = 6 + Math.floor(Math.random() * 5);
  const vectorLat = (24.05 + Math.random() * 0.12).toFixed(3);
  const vectorLon = (121.42 + Math.random() * 0.09).toFixed(3);
  const altitude = 180 + Math.floor(Math.random() * 70);

  if (signalQuality) {
    signalQuality.textContent = `${signal}%`;
  }
  if (packetFlow) {
    packetFlow.textContent = `${packet} KB/S`;
  }
  if (latencyPulse) {
    latencyPulse.textContent = `${latency} MS`;
  }
  if (nodeSync) {
    nodeSync.textContent = `${nodeNumerator}/128`;
  }
  if (nodeStability) {
    nodeStability.textContent = `${stability}%`;
  }
  if (packetIntegrity) {
    packetIntegrity.textContent = `${integrity}%`;
  }
  if (encryptedTunnels) {
    encryptedTunnels.textContent = String(tunnels);
  }
  if (reconWindows) {
    reconWindows.textContent = String(windows).padStart(2, "0");
  }
  if (vectorReadout) {
    vectorReadout.textContent = `${vectorLat} / ${vectorLon} / ALT ${altitude}`;
  }
  if (vectorLock) {
    vectorLock.textContent = `VECTOR LOCK / ${vectorLat}N ${vectorLon}E`;
  }
}

function rotateThreatMode() {
  const mode = threatModes[threatModeIndex % threatModes.length];
  threatModeIndex += 1;

  if (threatPulse) {
    threatPulse.textContent = mode.label;
  }
  if (threatIndex) {
    threatIndex.textContent = String(mode.meter);
  }
  if (threatBar) {
    threatBar.style.width = `${mode.meter}%`;
  }
  if (threatState) {
    threatState.textContent = mode.tone;
  }
}

function rotateSector() {
  const sector = sectors[Math.floor(Math.random() * sectors.length)];
  if (sectorReadout) {
    sectorReadout.textContent = sector;
  }
}

function cycleHeroFeed() {
  const message = heroMessages[heroMessageIndex % heroMessages.length];
  heroMessageIndex += 1;
  appendTerminalLine(heroFeed, message, 5);
}

function rotateTelemetry() {
  const items = [];
  for (let index = 0; index < 4; index += 1) {
    const entry = telemetryMessages[(telemetryOffset + index) % telemetryMessages.length];
    items.push(entry);
  }
  telemetryOffset = (telemetryOffset + 1) % telemetryMessages.length;
  renderIntelList(telemetryList, items);
}

function initChannels() {
  renderIntelList(channelList, channelMessages);
  if (channelCount) {
    channelCount.textContent = String(channelMessages.length).padStart(2, "0");
  }
}

function initBootOverlay() {
  let bootIndex = 0;
  const intervalId = window.setInterval(() => {
    const message = bootMessages[bootIndex % bootMessages.length];
    appendTerminalLine(bootFeed, message, 5);
    bootIndex += 1;
  }, 240);

  window.setTimeout(() => {
    window.clearInterval(intervalId);
    document.body.classList.add("is-loaded");
    if (bootOverlay) {
      bootOverlay.setAttribute("aria-hidden", "true");
    }
  }, 1700);
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
  const glyphs = "01ZXTOKI+-<>[]{}";
  const streakCount = perfLite ? 48 : 96;

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
      streaks.push({
        x: Math.random() * width,
        y: Math.random() * height,
        len: 40 + Math.random() * 180,
        speed: 2.4 + Math.random() * 4.8,
        drift: -0.5 + Math.random(),
        alpha: 0.12 + Math.random() * 0.38,
        hue: Math.random() < 0.8 ? 185 : 322,
      });
    }
  }

  function drawGlyph(x, y, hue) {
    ctx.save();
    ctx.fillStyle = `hsla(${hue}, 96%, 72%, 0.9)`;
    ctx.font = "12px Share Tech Mono";
    ctx.fillText(glyphs[Math.floor(Math.random() * glyphs.length)], x + 4, y + 10);
    ctx.restore();
  }

  const targetFps = perfLite ? 22 : 34;
  const frameLength = 1000 / targetFps;
  let lastTime = 0;

  function draw() {
    ctx.fillStyle = "rgba(2, 6, 10, 0.24)";
    ctx.fillRect(0, 0, width, height);
    ctx.lineCap = "round";

    streaks.forEach((streak) => {
      const gradient = ctx.createLinearGradient(streak.x, streak.y, streak.x + streak.drift * streak.len, streak.y + streak.len);
      gradient.addColorStop(0, `hsla(${streak.hue}, 100%, 68%, 0)`);
      gradient.addColorStop(0.22, `hsla(${streak.hue}, 100%, 68%, ${streak.alpha})`);
      gradient.addColorStop(1, `hsla(${streak.hue}, 100%, 68%, 0)`);

      ctx.strokeStyle = gradient;
      ctx.lineWidth = streak.hue === 322 ? 1.8 : 1.2;
      ctx.beginPath();
      ctx.moveTo(streak.x, streak.y);
      ctx.lineTo(streak.x + streak.drift * streak.len, streak.y + streak.len);
      ctx.stroke();

      if (!perfLite && Math.random() < 0.18) {
        drawGlyph(streak.x, streak.y + streak.len * 0.24, streak.hue);
      }

      streak.y += streak.speed;
      streak.x += streak.drift * 0.12;
      if (streak.y - streak.len > height) {
        streak.x = Math.random() * width;
        streak.y = -streak.len;
      }
      if (streak.x < -80 || streak.x > width + 80) {
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
  const count = perfLite ? 22 : 52;

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
      particles.push({
        x: Math.random() * width,
        y: Math.random() * height,
        size: 0.8 + Math.random() * 2.8,
        vx: -0.25 + Math.random() * 0.5,
        vy: -0.2 + Math.random() * 0.42,
        hue: Math.random() < 0.75 ? 188 : 328,
      });
    }
  }

  const targetFps = perfLite ? 18 : 30;
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
        if (distance > 140) {
          continue;
        }
        ctx.strokeStyle = `rgba(87, 245, 255, ${0.08 * (1 - distance / 140)})`;
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
      particle.x += particle.vx;
      particle.y += particle.vy;

      if (particle.x < -20) particle.x = width + 20;
      if (particle.x > width + 20) particle.x = -20;
      if (particle.y < -20) particle.y = height + 20;
      if (particle.y > height + 20) particle.y = -20;

      ctx.beginPath();
      ctx.fillStyle = `hsla(${particle.hue}, 96%, 72%, 0.72)`;
      ctx.shadowBlur = 14;
      ctx.shadowColor = `hsla(${particle.hue}, 96%, 72%, 0.42)`;
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
initLaserRain(perfLite);
initParticleField(perfLite);

window.setInterval(updateClock, 1000);
window.setInterval(updateLiveMetrics, 1200);
window.setInterval(rotateThreatMode, 2600);
window.setInterval(rotateSector, 3200);
window.setInterval(cycleHeroFeed, 2200);
window.setInterval(rotateTelemetry, 1800);
