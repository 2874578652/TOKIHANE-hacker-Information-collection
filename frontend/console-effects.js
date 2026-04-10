(function initConsoleEffects() {
  const root = document.documentElement;
  const body = document.body;
  if (!body) {
    return;
  }

  const terminal = document.getElementById("terminal");
  const summary = document.getElementById("summary");
  const hudThreat = document.getElementById("hudThreat");
  const hudTaskState = document.getElementById("hudTaskState");
  const runButton = document.getElementById("runBtn");
  const stopButton = document.getElementById("stopBtn");
  const homeLink = document.querySelector(".console-home-link");
  const TRANSITION_KEY = "tokihane-page-transition";
  const consoleDigitSelectors = [
    ".brand-block",
    ".status-focus",
    ".hud-card",
    ".stack-section",
    ".feature-block",
    ".recon-core",
    ".module-config-stage",
    ".intel-panel",
    ".dock-panel",
  ];
  const digitCharacters = "00112233445566778899";
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

  let lastSweepAt = 0;
  let isPageNavigating = false;

  function ensureOverlay(id, className) {
    let node = document.getElementById(id);
    if (!node) {
      node = document.createElement("div");
      node.id = id;
      node.className = className;
      body.appendChild(node);
    }
    return node;
  }

  ensureOverlay("consoleSweep", "console-sweep");
  const flash = ensureOverlay("consoleFlash", "console-flash");
  ensureOverlay("consoleDepth", "console-depth");

  function prefersReducedMotion() {
    return window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  }

  function pickRandomDigit() {
    return digitCharacters[Math.floor(Math.random() * digitCharacters.length)] || "0";
  }

  function getDigitDensity() {
    if (root.classList.contains("perf-lite")) {
      return 84;
    }
    return prefersReducedMotion() ? 54 : 156;
  }

  function buildDigitCloud(id, className, selectors, totalCount = 120) {
    document.getElementById(id)?.remove();

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
        char.style.setProperty("--delay", `${Math.random() * 280}ms`);
        char.style.setProperty("--from-x", `${(Math.random() - 0.5) * window.innerWidth * 0.74}px`);
        char.style.setProperty("--from-y", `${(Math.random() - 0.5) * window.innerHeight * 0.74}px`);
        char.style.setProperty("--drift-x", `${(Math.random() - 0.5) * 140}px`);
        char.style.setProperty("--drift-y", `${-30 - Math.random() * 120}px`);
        char.style.setProperty("--start-scale", `${0.36 + Math.random() * 1.1}`);
        char.style.setProperty("--rotate", `${(Math.random() - 0.5) * 220}deg`);
        container.appendChild(char);
      }
    });

    body.appendChild(container);
    return container;
  }

  function initEntryTransition() {
    if (!root.classList.contains("page-enter-console")) {
      return;
    }

    try {
      window.sessionStorage.removeItem(TRANSITION_KEY);
    } catch (error) {}

    buildDigitCloud("consoleDigitCloud", "console-digit-cloud", consoleDigitSelectors, getDigitDensity());
    window.requestAnimationFrame(() => {
      body.classList.add("is-revealing-console");
    });

    window.setTimeout(() => {
      body.classList.remove("is-revealing-console");
      root.classList.remove("page-enter-console");
      document.getElementById("consoleDigitCloud")?.remove();
    }, prefersReducedMotion() ? 420 : 1420);
  }

  function triggerSweep(force = false) {
    const now = performance.now();
    if (!force && now - lastSweepAt < 900) {
      return;
    }
    lastSweepAt = now;
    body.classList.remove("console-sweep-active");
    void body.offsetWidth;
    body.classList.add("console-sweep-active");
    window.setTimeout(() => {
      body.classList.remove("console-sweep-active");
    }, 960);
  }

  function triggerFlash(alert = false) {
    flash.classList.toggle("is-alert", alert);
    body.classList.remove("console-flash-active");
    void body.offsetWidth;
    body.classList.add("console-flash-active");
    window.setTimeout(() => {
      body.classList.remove("console-flash-active");
      flash.classList.remove("is-alert");
    }, 360);
  }

  function initPointerTracking() {
    let idleTimer = 0;

    const markIdleLater = () => {
      window.clearTimeout(idleTimer);
      idleTimer = window.setTimeout(() => {
        body.classList.add("is-pointer-idle");
      }, 1400);
    };

    const movePointer = (x, y) => {
      root.style.setProperty("--console-cursor-x", `${x}px`);
      root.style.setProperty("--console-cursor-y", `${y}px`);
      body.classList.remove("is-pointer-idle");
      markIdleLater();
    };

    body.classList.add("is-pointer-idle");
    markIdleLater();

    window.addEventListener("pointermove", (event) => {
      movePointer(event.clientX, event.clientY);
    });
  }

  function initRevealObserver() {
    const targets = Array.from(document.querySelectorAll(".reveal"));
    if (!targets.length) {
      return;
    }

    if (typeof IntersectionObserver === "undefined") {
      targets.forEach((element) => element.classList.add("is-visible"));
      return;
    }

    const observer = new IntersectionObserver(
      (entries) => {
        entries.forEach((entry) => {
          if (!entry.isIntersecting) {
            return;
          }
          entry.target.classList.add("is-visible");
          observer.unobserve(entry.target);
        });
      },
      { threshold: 0.12, rootMargin: "0px 0px -8% 0px" }
    );

    targets.forEach((element) => observer.observe(element));
  }

  function classifyThreat() {
    if (!hudThreat) {
      return;
    }
    const text = (hudThreat.textContent || "").toLowerCase();
    const critical = text.includes("critical");
    const elevated = text.includes("elevated") || text.includes("medium");
    hudThreat.classList.toggle("status-danger", critical || elevated);
    hudThreat.classList.toggle("status-online", !critical && !elevated);
  }

  function classifyTaskState() {
    if (!hudTaskState) {
      return;
    }
    const text = (hudTaskState.textContent || "").toLowerCase();
    const warning = ["failed", "error", "canceled"].some((token) => text.includes(token));
    const active = ["running", "launch", "queued", "stopping", "report"].some((token) => text.includes(token));
    hudTaskState.classList.toggle("status-danger", warning);
    hudTaskState.classList.toggle("status-online", !warning && active);
  }

  function pingValue(element) {
    if (!element) {
      return;
    }
    element.classList.remove("value-ping");
    void element.offsetWidth;
    element.classList.add("value-ping");
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
          classifyThreat();
        }
        if (element === hudTaskState) {
          classifyTaskState();
        }
      });
      observer.observe(element, { childList: true, subtree: true, characterData: true });
    });
  }

  function classifyTerminalLine(line) {
    if (!(line instanceof HTMLElement)) {
      return;
    }
    const text = (line.textContent || "").toLowerCase();
    const isError = /fail|error|stop|critical|异常|失败|停止/.test(text);
    const isOk = /ready|ok|completed|loaded|online|result|完成|就绪|已/.test(text);
    line.classList.add("terminal-line");
    line.classList.toggle("terminal-line--error", isError);
    line.classList.toggle("terminal-line--ok", !isError && isOk);
    line.classList.add("is-hot");
    window.setTimeout(() => {
      line.classList.remove("is-hot");
    }, 600);
  }

  function initTerminalObserver() {
    if (!terminal) {
      return;
    }

    Array.from(terminal.children).forEach((line) => classifyTerminalLine(line));
    const observer = new MutationObserver((mutations) => {
      mutations.forEach((mutation) => {
        mutation.addedNodes.forEach((node) => classifyTerminalLine(node));
      });
    });
    observer.observe(terminal, { childList: true });
  }

  function initSummaryObserver() {
    if (!summary) {
      return;
    }
    const observer = new MutationObserver((mutations) => {
      mutations.forEach((mutation) => {
        mutation.addedNodes.forEach((node) => {
          if (!(node instanceof HTMLElement)) {
            return;
          }
          node.classList.add("is-hot");
          window.setTimeout(() => node.classList.remove("is-hot"), 600);
        });
      });
    });
    observer.observe(summary, { childList: true });
  }

  function initBodyObserver() {
    let lastRunning = body.classList.contains("scan-active");
    const observer = new MutationObserver(() => {
      const running = body.classList.contains("scan-active");
      if (running === lastRunning) {
        return;
      }
      lastRunning = running;
      triggerSweep(true);
      triggerFlash(!running && (hudTaskState?.textContent || "").toLowerCase().includes("fail"));
    });
    observer.observe(body, { attributes: true, attributeFilter: ["class"] });
  }

  function initActionHooks() {
    runButton?.addEventListener("click", () => {
      triggerSweep(true);
    });

    stopButton?.addEventListener("click", () => {
      triggerFlash(true);
    });

    document.querySelectorAll(".dock-tab, .toggle input, .port-scan-switch input, .glow-btn, .file-btn").forEach((element) => {
      element.addEventListener("click", () => {
        triggerSweep();
      });
    });
  }

  function initHomeLinkTransition() {
    if (!homeLink) {
      return;
    }
    homeLink.addEventListener("click", (event) => {
      const href = homeLink.getAttribute("href");
      if (!href || isPageNavigating) {
        return;
      }
      event.preventDefault();
      isPageNavigating = true;
      try {
        window.sessionStorage.setItem(TRANSITION_KEY, "console-to-landing");
      } catch (error) {}
      body.classList.add("is-sinking-home");
      window.setTimeout(() => {
        window.location.href = href;
      }, prefersReducedMotion() ? 420 : 1160);
    });
  }

  initEntryTransition();
  initPointerTracking();
  initRevealObserver();
  initValueObservers();
  initTerminalObserver();
  initSummaryObserver();
  initBodyObserver();
  initActionHooks();
  initHomeLinkTransition();
  classifyThreat();
  classifyTaskState();
})();
