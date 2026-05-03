(function() {
  const TOTAL_SECONDS = 420; // 7:00 target talk pace
  let running = false;
  let lastFrame = null;
  let elapsed = 0;            // seconds of "talk time" consumed
  let totalScrollable = 0;

  const indicator = document.getElementById('indicator');
  const status = document.getElementById('status');
  const progress = document.getElementById('progress');

  function fmtTime(s) {
    s = Math.max(0, Math.floor(s));
    const m = Math.floor(s / 60);
    const ss = (s % 60).toString().padStart(2, '0');
    return `${m}:${ss}`;
  }

  function recalc() {
    totalScrollable = Math.max(1, document.documentElement.scrollHeight - window.innerHeight);
  }

  function updateUI() {
    const pct = (window.scrollY / totalScrollable) * 100;
    progress.style.width = pct + '%';
    const label = running ? 'rolling' : 'paused';
    status.textContent = `${label} ${fmtTime(elapsed)} / ${fmtTime(TOTAL_SECONDS)}`;
    indicator.classList.toggle('running', running);
  }

  function tick(now) {
    if (!running) return;
    if (lastFrame !== null) {
      const dt = (now - lastFrame) / 1000;
      // hard cap dt at 0.5s so resume after a long pause doesn't lurch
      const cappedDt = Math.min(dt, 0.5);
      elapsed += cappedDt;
    }
    lastFrame = now;
    // drive scroll position from elapsed time directly — avoids sub-pixel
    // rounding errors that stall scrollBy() when pxPerSecond < 1
    const targetY = (elapsed / TOTAL_SECONDS) * totalScrollable;
    window.scrollTo(0, targetY);
    updateUI();
    if (elapsed >= TOTAL_SECONDS || window.scrollY >= totalScrollable - 1) {
      running = false;
      updateUI();
      return;
    }
    requestAnimationFrame(tick);
  }

  function start() {
    if (running) return;
    recalc();  // ensure fresh measurements in case layout has shifted
    running = true;
    lastFrame = null;
    updateUI();
    requestAnimationFrame(tick);
  }

  function stop() {
    running = false;
    updateUI();
  }

  function toggle() {
    running ? stop() : start();
  }

  // spacebar — start/stop. ignore if focus is inside an input.
  document.addEventListener('keydown', (e) => {
    if (e.code === 'Space' && !['INPUT','TEXTAREA','SELECT'].includes((e.target.tagName||''))) {
      e.preventDefault();
      toggle();
    }
  });

  // manual scroll while running: don't pause, just keep rolling from
  // the new position. resetting lastFrame avoids a big jump from any
  // dt accumulated during the manual scroll gesture, AND also rolls
  // back the elapsed counter to match scroll position.
  function syncElapsedToScroll() {
    elapsed = (window.scrollY / totalScrollable) * TOTAL_SECONDS;
  }

  function noteUserScroll() {
    if (running) {
      lastFrame = null;
      // re-sync elapsed counter to current scroll position so the
      // displayed time matches reality after a manual jump
      syncElapsedToScroll();
      updateUI();
    } else {
      // even when paused, keep elapsed in sync with scroll position
      syncElapsedToScroll();
      updateUI();
    }
  }
  // wheel + touchmove cover most manual scroll inputs
  window.addEventListener('wheel', noteUserScroll, { passive: true });
  window.addEventListener('touchmove', noteUserScroll, { passive: true });
  // also react to keyboard scroll (arrows, page up/down, home/end)
  document.addEventListener('keydown', (e) => {
    if (['ArrowDown','ArrowUp','PageDown','PageUp','Home','End'].includes(e.code)) {
      // let default scroll happen, then sync after a frame
      requestAnimationFrame(noteUserScroll);
    }
  });

  // initial setup
  window.addEventListener('resize', () => { recalc(); updateUI(); });
  window.addEventListener('load', () => {
    recalc();
    syncElapsedToScroll();
    updateUI();
  });
})();
