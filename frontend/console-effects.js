(function initConsoleEffects() {
  const root = document.documentElement;
  const body = document.body;
  if (!body) {
    return;
  }

  const perfLite = root.classList.contains("perf-lite");
  const terminal = document.getElementById("terminal");
  const summary = document.getElementById("summary");
  const hudThreat = document.getElementById("hudThreat");
  const hudTaskState = document.getElementById("hudTaskState");
  const progressText = document.getElementById("progressText");
  const runButton = document.getElementById("runBtn");
  const stopButton = document.getElementById("stopBtn");
  const homeLink = document.querySelector(".console-home-link");
  const scrollLayers = [];
  const watchedValueIds = [
    "hudThreat",
    "hudSignal",
    "hudClock",
    "hudPacketFlow",
    "hudLatency",
    "hudModuleActive",
    "hudTaskState",
    "hudTargetLock",
    "progressText",
  ];

  const idleTelemetry = [
    "node mesh stable // awaiting mission lock",
    "spectral relay synchronized // channel integrity nominal",
    "passive telemetry buffer warm // recon core idle",
    "matrix rain resonance balanced // no hostile drift",
    "watch grid aligned // low-noise operational window",
  ];

  const activeTelemetry = [
    "packet burst detected // routing reconnaissance frames",
    "geo node sync engaged // anomaly sweep in progress",
    "encrypted channel hardened // telemetry uplink stable",
    "threat lattice recalibrated // signal density increasing",
    "active reconnaissance loop // tactical cache streaming",
    "redline signature watch // hostile pulse isolated",
  ];

  const decodeGlyphs = "01TOKI_X$#<>/\\[]{}*+=-";
  const scrollState = {
    lastY: window.scrollY || 0,
    lastSweepAt: 0,
    energy: 0,
  };

  const ensureOverlay = (id, className) => {
    let node = document.getElementById(id);
    if (!node) {
      node = document.createElement("div");
      node.id = id;
      node.className = className;
      body.appendChild(node);
    }
    return node;
  };

  const consoleSweep = ensureOverlay("consoleSweep", "console-sweep");
  const consoleFlash = ensureOverlay("consoleFlash", "console-flash");

  function setRootVar(name, value) {
    root.style.setProperty(name, value);
  }

  function queryAll(selector, context = document) {
    return Array.from(context.querySelectorAll(selector));
  }

  function addScrollLayer(selector, factor) {
    queryAll(selector).forEach((element, index) => {
      scrollLayers.push({
        element,
        factor: factor * (1 + index * 0.025),
      });
    });
  }

  function triggerConsoleSweep(force = false) {
    const now = performance.now();
    if (!force && now - scrollState.lastSweepAt < 1200) {
      return;
    }
    scrollState.lastSweepAt = now;
    body.classList.remove("console-sweep-active");
    void consoleSweep.offsetWidth;
    body.classList.add("console-sweep-active");
    window.setTimeout(() => {
      body.classList.remove("console-sweep-active");
    }, 1040);
  }

  function triggerConsoleFlash(alert = false) {
    consoleFlash.classList.toggle("is-alert", alert);
    body.classList.remove("console-flash-active");
    void consoleFlash.offsetWidth;
    body.classList.add("console-flash-active");
    window.setTimeout(() => {
      body.classList.remove("console-flash-active");
      consoleFlash.classList.remove("is-alert");
    }, 420);
  }

  function updateThreatState() {
    if (!hudThreat) {
      return;
    }
    const text = (hudThreat.textContent || "").trim().toLowerCase();
    let level = "low";
    if (text.includes("critical")) {
      level = "critical";
    } else if (text.includes("elevated") || text.includes("medium")) {
      level = "elevated";
    }
    hudThreat.dataset.threatLevel = level;
    hudThreat.classList.toggle("status-danger", level !== "low");
    hudThreat.classList.toggle("status-online", level === "low");
  }

  function updateTaskStateClass() {
    if (!hudTaskState) {
      return;
    }
    const text = (hudTaskState.textContent || "").trim().toLowerCase();
    const live = ["running", "launch", "queued", "stopping"].some((token) => text.includes(token));
    const warning = ["failed", "error", "canceled"].some((token) => text.includes(token));
    hudTaskState.classList.toggle("state-live", live);
    hudTaskState.classList.toggle("status-danger", warning);
    hudTaskState.classList.toggle("status-online", !warning);
  }

  function pingValue(element) {
    if (!element) {
      return;
    }
    element.classList.remove("value-ping");
    void element.offsetWidth;
    element.classList.add("value-ping");
  }

  function updateScrollEffects() {
    const currentY = window.scrollY || 0;
    const maxScroll = Math.max(1, document.documentElement.scrollHeight - window.innerHeight);
    const delta = Math.abs(currentY - scrollState.lastY);
    scrollState.energy = Math.min(1, scrollState.energy * 0.72 + delta / 1600);

    setRootVar("--console-scroll", `${currentY.toFixed(2)}px`);
    setRootVar("--console-scroll-progress", scrollState.energy.toFixed(3));
    setRootVar("--console-scroll-energy", scrollState.energy.toFixed(3));

    scrollLayers.forEach(({ element, factor }) => {
      element.style.setProperty("--scroll-lift", `${(currentY * factor).toFixed(2)}px`);
    });

    if (delta > 70) {
      triggerConsoleSweep();
    }

    const progressRatio = Math.min(1, currentY / maxScroll);
    setRootVar("--console-scroll-progress", progressRatio.toFixed(3));
    scrollState.lastY = currentY;
  }

  function startEnergyLoop() {
    const decay = () => {
      scrollState.energy *= 0.93;
      setRootVar("--console-scroll-energy", scrollState.energy.toFixed(3));
      window.requestAnimationFrame(decay);
    };
    window.requestAnimationFrame(decay);
  }

  function initPointerTracking() {
    let idleTimer = 0;

    const markIdleLater = () => {
      window.clearTimeout(idleTimer);
      idleTimer = window.setTimeout(() => {
        body.classList.add("is-pointer-idle");
      }, 1400);
    };

    const movePointer = (clientX, clientY) => {
      setRootVar("--console-cursor-x", `${clientX}px`);
      setRootVar("--console-cursor-y", `${clientY}px`);
      body.classList.remove("is-pointer-idle");
      markIdleLater();
    };

    body.classList.add("is-pointer-idle");
    markIdleLater();

    window.addEventListener("pointermove", (event) => {
      movePointer(event.clientX, event.clientY);
    });

    window.addEventListener(
      "touchmove",
      (event) => {
        const touch = event.touches?.[0];
        if (!touch) {
          return;
        }
        movePointer(touch.clientX, touch.clientY);
      },
      { passive: true }
    );
  }

  function prepareDecodeTargets() {
    queryAll(
      ".brand-copy h1, .logo-sub, .zone-head h2, .zone-head p, .module-config-head h2, .module-config-head p, .module-config-title, .terminal-wrap h2, .results-wrap h2, .hud-card span, .metric-card span"
    ).forEach((element) => {
      element.classList.add("decode-target");
      if (!element.dataset.decodeOriginal) {
        element.dataset.decodeOriginal = element.textContent || "";
      }
    });
  }

  function runDecode(element) {
    if (!element || element.dataset.decoded === "true" || element.dataset.decodeOriginal == null) {
      return;
    }
    const original = element.dataset.decodeOriginal;
    let frame = 0;
    element.dataset.decoded = "true";
    element.classList.add("is-decoding");

    const totalFrames = Math.max(10, Math.min(24, original.length + 6));
    const tick = () => {
      frame += 1;
      const revealCount = Math.floor((frame / totalFrames) * original.length);
      const nextText = original
        .split("")
        .map((char, index) => {
          if (char === " ") {
            return " ";
          }
          if (index < revealCount) {
            return original[index];
          }
          return decodeGlyphs[Math.floor(Math.random() * decodeGlyphs.length)];
        })
        .join("");

      element.textContent = nextText;

      if (frame < totalFrames) {
        window.setTimeout(tick, 28);
        return;
      }

      element.textContent = original;
      element.classList.remove("is-decoding");
    };

    tick();
  }

  function installSurfaceEffect(element, options = {}) {
    if (!element || element.dataset.surfaceFxInstalled === "true") {
      return;
    }
    element.dataset.surfaceFxInstalled = "true";
    element.classList.add("interactive-surface");

    const hoverGlow = document.createElement("span");
    hoverGlow.className = "fx-hover-glow";

    const clickWave = document.createElement("span");
    clickWave.className = "fx-click-wave";

    element.append(hoverGlow, clickWave);

    const maxTilt = options.maxTilt || 5;
    const pointerMove = (event) => {
      if (perfLite) {
        return;
      }
      const rect = element.getBoundingClientRect();
      if (!rect.width || !rect.height) {
        return;
      }
      const offsetX = event.clientX - rect.left;
      const offsetY = event.clientY - rect.top;
      const ratioX = offsetX / rect.width;
      const ratioY = offsetY / rect.height;
      const tiltY = (ratioX - 0.5) * maxTilt * 1.8;
      const tiltX = (0.5 - ratioY) * maxTilt * 1.5;

      element.style.setProperty("--fx-x", `${ratioX * 100}%`);
      element.style.setProperty("--fx-y", `${ratioY * 100}%`);
      element.style.setProperty("--tilt-x", `${tiltX.toFixed(2)}deg`);
      element.style.setProperty("--tilt-y", `${tiltY.toFixed(2)}deg`);
    };

    element.addEventListener("pointerenter", () => {
      element.classList.add("is-hovering");
      if (options.alert) {
        element.classList.add("is-alerting");
      }
    });

    element.addEventListener("pointermove", pointerMove);

    element.addEventListener("pointerleave", () => {
      element.classList.remove("is-hovering");
      element.classList.remove("is-alerting");
      element.style.removeProperty("--tilt-x");
      element.style.removeProperty("--tilt-y");
    });

    element.addEventListener("click", () => {
      element.classList.remove("is-pressed");
      void element.offsetWidth;
      element.classList.add("is-pressed");
      if (options.flash) {
        triggerConsoleFlash(Boolean(options.alert));
      }
      if (options.sweep) {
        triggerConsoleSweep(true);
      }
      window.setTimeout(() => {
        element.classList.remove("is-pressed");
      }, 480);
    });
  }

  function decorateFeatureSwitches() {
    queryAll(".feature-block .port-scan-master").forEach((label) => {
      const input = label.querySelector("input");
      const featureBlock = label.closest(".feature-block");
      if (!input) {
        return;
      }
      const applyState = () => {
        const active = input.checked;
        label.classList.toggle("is-active", active);
        featureBlock?.classList.toggle("is-active", active);
      };
      applyState();
      input.addEventListener("change", () => {
        applyState();
        triggerConsoleSweep(true);
      });
    });
  }

  function initInteractiveSurfaces() {
    queryAll(".console-home-link").forEach((element) => {
      installSurfaceEffect(element, { flash: true, sweep: true, maxTilt: 3 });
    });
    queryAll(".glow-btn, .file-btn").forEach((element) => {
      const isAlert = element.id === "stopBtn";
      installSurfaceEffect(element, {
        alert: isAlert,
        flash: true,
        sweep: element.classList.contains("primary-action"),
        maxTilt: 4,
      });
    });
    queryAll(".hud-card, .metric-card, .control-zone, .port-options-panel, .terminal-wrap, .results-wrap, .summary-item").forEach((element) => {
      installSurfaceEffect(element, { maxTilt: 4 });
    });
    queryAll(".feature-block .port-scan-master").forEach((element) => {
      installSurfaceEffect(element, { maxTilt: 5 });
    });
    decorateFeatureSwitches();
  }

  function initFocusLocks() {
    queryAll(".input-block").forEach((block) => {
      const field = block.querySelector("input, select, textarea");
      if (!field) {
        return;
      }
      field.addEventListener("focus", () => {
        block.classList.add("is-focus-armed");
        triggerConsoleSweep();
      });
      field.addEventListener("blur", () => {
        block.classList.remove("is-focus-armed");
      });
    });
  }

  function prepareWakeTargets() {
    queryAll(
      ".hud-card, .control-zone, .metric-card, .feature-block, #moduleConfigStage, .port-options-panel, .terminal-wrap, .results-wrap, .summary-item, .module-config-head, .brand-block"
    ).forEach((element) => {
      element.classList.add("wake-target");
    });
  }

  function initWakeObserver() {
    prepareWakeTargets();
    const observer = new IntersectionObserver(
      (entries) => {
        entries.forEach((entry) => {
          if (!entry.isIntersecting) {
            return;
          }
          const target = entry.target;
          target.classList.add("is-awake");
          queryAll(".decode-target", target).forEach((decodeTarget) => runDecode(decodeTarget));
          if (target.classList.contains("summary-item")) {
            target.classList.add("is-hot");
          }
          observer.unobserve(target);
        });
      },
      {
        threshold: 0.16,
        rootMargin: "0px 0px -10% 0px",
      }
    );

    queryAll(".wake-target").forEach((element) => observer.observe(element));
  }

  function classifyTerminalLine(line) {
    const text = (line.textContent || "").toLowerCase();
    const isError = /fail|error|stop|critical|anomaly|异常|失败|停止/.test(text);
    const isOk = /ready|ok|completed|loaded|online|result|完成|就绪|已/.test(text);
    const isAmbient = /node mesh|spectral relay|telemetry|matrix rain|watch grid|packet burst|threat lattice|uplink/.test(text);

    line.classList.add("terminal-line");
    line.classList.toggle("terminal-line--error", isError);
    line.classList.toggle("terminal-line--ok", !isError && isOk);
    line.classList.toggle("terminal-line--ambient", isAmbient);
  }

  function typeTerminalLine(line) {
    if (!line || line.dataset.typed === "true") {
      return;
    }
    const fullText = line.textContent || "";
    if (!fullText) {
      line.dataset.typed = "true";
      return;
    }

    classifyTerminalLine(line);
    line.dataset.typed = "true";
    line.classList.add("is-hot");

    if (perfLite) {
      return;
    }

    line.dataset.fullText = fullText;
    line.textContent = "";
    line.classList.add("is-typing");

    let index = 0;
    const stepSize = Math.max(1, Math.ceil(fullText.length / 34));
    const speed = Math.max(12, 22 - Math.floor(fullText.length / 24));

    const tick = () => {
      index = Math.min(fullText.length, index + stepSize);
      line.textContent = fullText.slice(0, index);
      if (terminal) {
        terminal.scrollTop = terminal.scrollHeight;
      }
      if (index < fullText.length) {
        window.setTimeout(tick, speed);
        return;
      }
      line.classList.remove("is-typing");
    };

    tick();
  }

  function trimTerminalLines(maxLines = 90) {
    if (!terminal) {
      return;
    }
    while (terminal.children.length > maxLines) {
      terminal.removeChild(terminal.firstElementChild);
    }
  }

  function appendAmbientLog(message, level = "ok") {
    if (typeof window.logLine === "function") {
      window.logLine(message, level);
      trimTerminalLines();
      return;
    }
    if (!terminal) {
      return;
    }
    const line = document.createElement("div");
    line.textContent = `[${new Date().toLocaleTimeString()}] ${message}`;
    terminal.appendChild(line);
    trimTerminalLines();
  }

  function initTerminalObserver() {
    if (!terminal) {
      return;
    }

    queryAll(":scope > div", terminal).forEach((line) => typeTerminalLine(line));

    const terminalObserver = new MutationObserver((mutations) => {
      mutations.forEach((mutation) => {
        mutation.addedNodes.forEach((node) => {
          if (!(node instanceof HTMLDivElement)) {
            return;
          }
          typeTerminalLine(node);
        });
      });
    });

    terminalObserver.observe(terminal, {
      childList: true,
    });

    const scheduleAmbientLog = () => {
      const messagePool = body.classList.contains("scan-active") ? activeTelemetry : idleTelemetry;
      const message = messagePool[Math.floor(Math.random() * messagePool.length)];
      const level = body.classList.contains("scan-active") && Math.random() < 0.24 ? "error" : "ok";
      appendAmbientLog(message, level);
      const nextDelay = body.classList.contains("scan-active") ? 5600 : 7600;
      window.setTimeout(scheduleAmbientLog, nextDelay);
    };

    window.setTimeout(scheduleAmbientLog, 3200);
  }

  function decorateSummaryItem(item) {
    if (!(item instanceof HTMLElement)) {
      return;
    }
    item.classList.add("wake-target", "is-awake", "is-hot");
    installSurfaceEffect(item, { maxTilt: 3 });
  }

  function initSummaryObserver() {
    if (!summary) {
      return;
    }
    queryAll(".summary-item", summary).forEach((item) => decorateSummaryItem(item));

    const summaryObserver = new MutationObserver((mutations) => {
      mutations.forEach((mutation) => {
        mutation.addedNodes.forEach((node) => {
          if (!(node instanceof HTMLElement) || !node.classList.contains("summary-item")) {
            return;
          }
          decorateSummaryItem(node);
        });
      });
    });

    summaryObserver.observe(summary, {
      childList: true,
    });
  }

  function initValueObservers() {
    watchedValueIds.forEach((id) => {
      const element = document.getElementById(id);
      if (!element) {
        return;
      }
      let lastText = element.textContent || "";
      const observer = new MutationObserver(() => {
        const nextText = element.textContent || "";
        if (nextText === lastText) {
          return;
        }
        lastText = nextText;
        pingValue(element);
        if (element === hudThreat) {
          updateThreatState();
        }
        if (element === hudTaskState) {
          updateTaskStateClass();
        }
      });
      observer.observe(element, {
        childList: true,
        subtree: true,
        characterData: true,
      });
    });
  }

  function initBodyStateObserver() {
    let lastRunning = body.classList.contains("scan-active");
    const observer = new MutationObserver(() => {
      const running = body.classList.contains("scan-active");
      if (running === lastRunning) {
        return;
      }
      lastRunning = running;
      triggerConsoleSweep(true);
      triggerConsoleFlash(!running && (hudTaskState?.textContent || "").toLowerCase().includes("fail"));
      appendAmbientLog(running ? "recon execution state elevated // core online" : "recon core cooled // standby lattice restored", running ? "ok" : "info");
      updateTaskStateClass();
      updateThreatState();
    });

    observer.observe(body, {
      attributes: true,
      attributeFilter: ["class"],
    });
  }

  function initScrollHandlers() {
    let ticking = false;
    const onScroll = () => {
      if (ticking) {
        return;
      }
      ticking = true;
      window.requestAnimationFrame(() => {
        updateScrollEffects();
        ticking = false;
      });
    };
    window.addEventListener("scroll", onScroll, { passive: true });
    updateScrollEffects();
  }

  function initHomeLinkTransition() {
    if (!homeLink) {
      return;
    }
    homeLink.addEventListener("click", (event) => {
      const href = homeLink.getAttribute("href");
      if (!href) {
        return;
      }
      event.preventDefault();
      triggerConsoleFlash(false);
      triggerConsoleSweep(true);
      window.setTimeout(() => {
        window.location.href = href;
      }, 180);
    });
  }

  function initActionHooks() {
    if (runButton) {
      runButton.addEventListener("click", () => {
        triggerConsoleFlash(false);
        triggerConsoleSweep(true);
      });
    }
    if (stopButton) {
      stopButton.addEventListener("click", () => {
        triggerConsoleFlash(true);
      });
    }
    queryAll(".toggle input, .port-scan-switch input").forEach((input) => {
      input.addEventListener("change", () => {
        triggerConsoleSweep();
      });
    });
  }

  prepareDecodeTargets();
  initPointerTracking();
  startEnergyLoop();
  addScrollLayer(".hud-top", -0.016);
  addScrollLayer(".console-panel", -0.014);
  addScrollLayer("#moduleConfigStage", -0.01);
  addScrollLayer(".bottom-console", -0.008);
  addScrollLayer(".control-zone", -0.016);
  addScrollLayer(".hud-card", -0.018);
  addScrollLayer(".metric-card", -0.02);
  addScrollLayer(".feature-block", -0.014);
  addScrollLayer(".port-options-panel", -0.01);
  addScrollLayer(".summary-item", -0.008);
  initScrollHandlers();
  initInteractiveSurfaces();
  initFocusLocks();
  initWakeObserver();
  initTerminalObserver();
  initSummaryObserver();
  initValueObservers();
  initBodyStateObserver();
  initHomeLinkTransition();
  initActionHooks();
  updateThreatState();
  updateTaskStateClass();
})();
