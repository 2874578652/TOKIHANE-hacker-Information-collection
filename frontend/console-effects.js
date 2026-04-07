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
      if (!href) {
        return;
      }
      event.preventDefault();
      triggerFlash(false);
      triggerSweep(true);
      window.setTimeout(() => {
        window.location.href = href;
      }, 160);
    });
  }

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
