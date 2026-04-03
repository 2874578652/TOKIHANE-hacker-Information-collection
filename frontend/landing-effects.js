const landingRoot = document.documentElement;
const landingBody = document.body;
const landingPerfLite = document.documentElement.classList.contains("perf-lite");
const systemLog = document.getElementById("systemLog");
const ctaRack = document.querySelector(".cta-rack");

const landingScrollState = {
  lastY: window.scrollY,
  energy: 0,
  lastSweepAt: 0,
};

const landingScrollLayers = [];

function addLandingScrollLayer(selector, factor) {
  document.querySelectorAll(selector).forEach((element) => {
    landingScrollLayers.push({ element, factor });
  });
}

function setLandingRootVar(name, value) {
  landingRoot.style.setProperty(name, value);
}

function triggerLandingSweep(force = false) {
  const now = performance.now();
  if (!force && now - landingScrollState.lastSweepAt < 950) {
    return;
  }
  landingScrollState.lastSweepAt = now;
  landingBody.classList.remove("sweep-active");
  window.requestAnimationFrame(() => {
    landingBody.classList.add("sweep-active");
  });
  window.setTimeout(() => {
    landingBody.classList.remove("sweep-active");
  }, 1420);
}

function initLandingPointerTracking() {
  let idleTimerId = null;

  function markIdle() {
    landingBody.classList.add("is-pointer-idle");
  }

  landingBody.classList.add("is-pointer-idle");

  window.addEventListener(
    "mousemove",
    (event) => {
      setLandingRootVar("--landing-cursor-x", `${event.clientX}px`);
      setLandingRootVar("--landing-cursor-y", `${event.clientY}px`);
      landingBody.classList.remove("is-pointer-idle");
      if (idleTimerId) {
        window.clearTimeout(idleTimerId);
      }
      idleTimerId = window.setTimeout(markIdle, 900);
    },
    { passive: true },
  );
}

function updateLandingScrollEffects() {
  const maxScroll = Math.max(1, document.documentElement.scrollHeight - window.innerHeight);
  const currentY = window.scrollY;
  const delta = currentY - landingScrollState.lastY;
  landingScrollState.lastY = currentY;
  landingScrollState.energy = Math.max(landingScrollState.energy, Math.min(1, Math.abs(delta) / 120));

  setLandingRootVar("--landing-scroll", String(currentY));
  setLandingRootVar("--landing-scroll-progress", (currentY / maxScroll).toFixed(4));

  landingScrollLayers.forEach(({ element, factor }) => {
    element.style.setProperty("--scroll-lift", `${currentY * factor}px`);
  });

  if (Math.abs(delta) > 86) {
    triggerLandingSweep();
  }
}

function startLandingEnergyLoop() {
  function step() {
    landingScrollState.energy *= 0.9;
    if (landingScrollState.energy < 0.001) {
      landingScrollState.energy = 0;
    }
    setLandingRootVar("--landing-scroll-energy", landingScrollState.energy.toFixed(3));
    window.requestAnimationFrame(step);
  }

  step();
}

function prepareLandingDecodeTargets() {
  document
    .querySelectorAll(".topbar__brand strong, .intel-card__head strong, .status-panel__head strong, .hero-terminal__status, .enter-button__label, .ghost-button")
    .forEach((element) => {
      if (element.dataset.decodeFinal) {
        return;
      }
      element.classList.add("decode-target");
      element.dataset.decodeFinal = element.textContent || "";
    });
}

function runLandingDecode(element) {
  const finalText = element?.dataset?.decodeFinal;
  if (!finalText || element.dataset.decodeDone === "true") {
    return;
  }

  const characters = "01<>[]{}#%/ABCDEFGHIJKLMNOPQRSTUVWXYZ";
  let frame = 0;
  const totalFrames = 14;
  element.dataset.decodeDone = "true";
  element.classList.add("is-decoding");

  const intervalId = window.setInterval(() => {
    const progress = frame / totalFrames;
    const revealed = Math.floor(finalText.length * progress);
    const scrambled = finalText
      .split("")
      .map((char, index) => {
        if (char === " ") {
          return " ";
        }
        if (index < revealed) {
          return finalText[index];
        }
        return characters[Math.floor(Math.random() * characters.length)];
      })
      .join("");

    element.textContent = scrambled;
    frame += 1;

    if (frame > totalFrames) {
      window.clearInterval(intervalId);
      element.textContent = finalText;
      element.classList.remove("is-decoding");
    }
  }, 26);
}

function initLandingWakeObserver() {
  const targets = Array.from(
    document.querySelectorAll(".topbar-chip, .hero-copy, .hero-core, .hero-terminal, .intel-card, .status-panel, .system-log-panel, .ticker-shell"),
  );

  targets.forEach((target, index) => {
    target.classList.add("wake-target");
    target.style.setProperty("transition-delay", `${Math.min(index * 40, 220)}ms`);
  });

  const observer = new IntersectionObserver(
    (entries) => {
      entries.forEach((entry) => {
        if (!entry.isIntersecting) {
          return;
        }
        entry.target.classList.add("is-awake");
        entry.target.querySelectorAll(".decode-target").forEach((decodeTarget) => {
          runLandingDecode(decodeTarget);
        });
      });
    },
    {
      rootMargin: "0px 0px -12% 0px",
      threshold: 0.24,
    },
  );

  targets.forEach((target) => observer.observe(target));
}

function installLandingSurfaceEffect(element, options = {}) {
  if (!element) {
    return;
  }

  element.classList.add("surface-fx");

  if (!element.querySelector(":scope > .fx-hover-glow")) {
    const hoverGlow = document.createElement("span");
    hoverGlow.className = "fx-hover-glow";
    hoverGlow.setAttribute("aria-hidden", "true");
    element.appendChild(hoverGlow);
  }

  if (!element.querySelector(":scope > .fx-click-wave")) {
    const clickWave = document.createElement("span");
    clickWave.className = "fx-click-wave";
    clickWave.setAttribute("aria-hidden", "true");
    element.appendChild(clickWave);
  }

  const maxTilt = options.maxTilt || 7;

  element.addEventListener("mouseenter", () => {
    element.classList.add("is-hovering");
    if (element.classList.contains("enter-button")) {
      triggerLandingSweep();
    }
  });

  element.addEventListener("mouseleave", () => {
    element.classList.remove("is-hovering");
    element.style.setProperty("--surface-tilt-x", "0deg");
    element.style.setProperty("--surface-tilt-y", "0deg");
  });

  element.addEventListener("mousemove", (event) => {
    const rect = element.getBoundingClientRect();
    const x = ((event.clientX - rect.left) / rect.width) * 100;
    const y = ((event.clientY - rect.top) / rect.height) * 100;
    element.style.setProperty("--hover-x", `${x}%`);
    element.style.setProperty("--hover-y", `${y}%`);

    if (landingPerfLite) {
      return;
    }

    const rotateY = ((x / 100) - 0.5) * maxTilt;
    const rotateX = (0.5 - (y / 100)) * maxTilt;
    element.style.setProperty("--surface-tilt-x", `${rotateX.toFixed(2)}deg`);
    element.style.setProperty("--surface-tilt-y", `${rotateY.toFixed(2)}deg`);
  });

  element.addEventListener("click", () => {
    element.classList.remove("is-clicked");
    window.requestAnimationFrame(() => {
      element.classList.add("is-clicked");
    });
    window.setTimeout(() => {
      element.classList.remove("is-clicked");
    }, 420);
  });
}

function initLandingInteractiveSurfaces() {
  const selectors = [
    ".topbar-chip",
    ".hero-terminal",
    ".intel-card",
    ".status-box",
    ".coordinate-panel > div",
    ".system-log-panel",
    ".ticker-shell",
    ".enter-button",
    ".ghost-button",
  ];

  selectors.forEach((selector) => {
    document.querySelectorAll(selector).forEach((element) => {
      installLandingSurfaceEffect(element, {
        maxTilt: element.matches(".enter-button, .ghost-button") ? 5.5 : 6.5,
      });
    });
  });
}

function initLandingHotZoneObserver() {
  if (!ctaRack) {
    return;
  }

  const observer = new IntersectionObserver(
    (entries) => {
      entries.forEach((entry) => {
        ctaRack.classList.toggle("is-hot", entry.isIntersecting);
      });
    },
    {
      threshold: 0.65,
    },
  );

  observer.observe(ctaRack);
}

function initLandingSystemLogObserver() {
  if (!systemLog) {
    return;
  }

  const observer = new MutationObserver((mutations) => {
    mutations.forEach((mutation) => {
      mutation.addedNodes.forEach((node) => {
        if (!(node instanceof HTMLElement)) {
          return;
        }
        node.classList.add("is-hot");
        window.setTimeout(() => {
          node.classList.remove("is-hot");
        }, 1200);
      });
    });
  });

  observer.observe(systemLog, { childList: true });
}

function initLandingEnhancements() {
  addLandingScrollLayer(".hero-copy .eyebrow", -0.022);
  addLandingScrollLayer(".hero-copy .glitch-title", -0.048);
  addLandingScrollLayer(".hero-copy .hero-copy__lead", -0.03);
  addLandingScrollLayer(".hero-copy .cta-rack", -0.018);
  addLandingScrollLayer(".hero-copy .hero-terminal", -0.012);
  addLandingScrollLayer(".hero-core .core-stage", -0.024);
  addLandingScrollLayer(".intel-column > *", -0.016);
  addLandingScrollLayer(".dashboard-grid > *", -0.01);
  addLandingScrollLayer(".ticker-shell", -0.006);

  prepareLandingDecodeTargets();
  initLandingPointerTracking();
  updateLandingScrollEffects();
  window.addEventListener("scroll", updateLandingScrollEffects, { passive: true });
  window.addEventListener("resize", updateLandingScrollEffects);
  startLandingEnergyLoop();
  initLandingWakeObserver();
  initLandingInteractiveSurfaces();
  initLandingHotZoneObserver();
  initLandingSystemLogObserver();
}

initLandingEnhancements();
