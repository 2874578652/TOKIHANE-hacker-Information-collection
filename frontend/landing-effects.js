(function initLandingEffects() {
  const root = document.documentElement;
  const body = document.body;
  if (!body) {
    return;
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
      root.style.setProperty("--landing-cursor-x", `${x}px`);
      root.style.setProperty("--landing-cursor-y", `${y}px`);
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
      targets.forEach((target) => target.classList.add("is-visible"));
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
      { threshold: 0.14, rootMargin: "0px 0px -8% 0px" }
    );

    targets.forEach((target) => observer.observe(target));
  }

  function initScrollSweep() {
    let lastY = window.scrollY || 0;
    let lastSweepAt = 0;

    window.addEventListener(
      "scroll",
      () => {
        const currentY = window.scrollY || 0;
        const delta = Math.abs(currentY - lastY);
        lastY = currentY;
        const now = performance.now();
        if (delta > 90 && now - lastSweepAt > 1000) {
          lastSweepAt = now;
          body.classList.remove("sweep-active");
          void body.offsetWidth;
          body.classList.add("sweep-active");
          window.setTimeout(() => {
            body.classList.remove("sweep-active");
          }, 1020);
        }
      },
      { passive: true }
    );
  }

  initPointerTracking();
  initRevealObserver();
  initScrollSweep();
})();
