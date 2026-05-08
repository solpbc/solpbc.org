(function() {
  // v27 — named-state cue card. Each slide is tagged with data-state="..."
  // matching a deck STEPS[].name. Local space/←/R broadcast 'advance'/
  // 'back'/'reset' to the deck (press relay). The cue card slide changes
  // ONLY when the deck broadcasts a 'walk-state' event with a name we
  // know about — slide ordering is decoupled from press counts entirely,
  // so speed-running, animation snaps, and auto-advance regions all just
  // work. Dedup is on the deck side (broadcastState fires only on change).

  const slides = [...document.querySelectorAll('.slide')];
  const N = slides.length;
  let current = 0;

  // Build name → slide-index map from data-state attributes. Slides
  // without a data-state are unreachable via walk-state and only show if
  // arrowed to manually (none in v27, but harmless to allow).
  const slideForState = {};
  slides.forEach((el, idx) => {
    const state = el.dataset.state;
    if (state) slideForState[state] = idx;
  });

  const indicator = document.getElementById('indicator');
  const statusEl = document.getElementById('status');
  const hintEl = document.getElementById('hint');
  const progressEl = document.getElementById('progress');

  // Build the dot row — one dot per slide.
  for (let i = 0; i < N; i++) {
    const d = document.createElement('div');
    d.className = 'dot';
    progressEl.appendChild(d);
  }
  const dots = [...progressEl.querySelectorAll('.dot')];

  // BroadcastChannel — bidirectional sync between cue card and deck.
  const chan = ('BroadcastChannel' in window) ? new BroadcastChannel('demo-day') : null;
  function deckSend(cmd) {
    if (!chan) return;
    try { chan.postMessage({ cmd, from: 'walkthrough' }); } catch (_) {}
  }

  // ---- per-slide auto-scroll ----
  // Each slide's .body element scrolls internally at a paced rate while
  // the slide is active. Pace is computed from word count (~140 wpm) so
  // long slides scroll for longer and short slides finish quickly. When
  // a slide changes, the running animation is canceled and the new
  // slide starts fresh from its top.
  const WORDS_PER_SEC = 2.76;      // ~166 wpm — 20% faster than the 140 wpm baseline (5/4 dress-rehearsal tune)
  const MIN_DURATION_MS = 6700;    // floor scaled down 20% in lockstep with the rate bump
  let activeRAF = null;

  function cancelSlideAutoScroll() {
    if (activeRAF) {
      cancelAnimationFrame(activeRAF);
      activeRAF = null;
    }
  }

  function startSlideAutoScroll(slide) {
    cancelSlideAutoScroll();
    const body = slide.querySelector('.body');
    if (!body) return;
    body.scrollTop = 0;
    // Defer one frame so layout is settled before measuring scrollHeight
    // (the new slide just got .active applied, opacity transitioning).
    requestAnimationFrame(() => {
      const distance = body.scrollHeight - body.clientHeight;
      if (distance <= 1) return; // fits in viewport, no scrolling needed
      const words = (body.textContent || '').trim().split(/\s+/).filter(Boolean).length;
      const durationMs = Math.max(MIN_DURATION_MS, (words / WORDS_PER_SEC) * 1000);
      // Rate-based scroll instead of t*distance from start. Each tick
      // reads body.scrollTop, advances by pxPerMs*dt, and writes it back —
      // so any manual scroll (wheel/trackpad/touch) is honored: jer can
      // jump to top or bottom and the scroll resumes from wherever he
      // landed. Loop runs until the slide changes (cancelSlideAutoScroll
      // tears it down on showSlide); at max it idles harmlessly.
      const pxPerMs = distance / durationMs;
      let lastFrame = performance.now();
      // Track our own fractional position so per-frame increments < 1px
      // accumulate (browser rounds scrollTop, so reading it back loses the
      // fraction and a small dt advance can stall forever). On each tick:
      // if body.scrollTop diverged from what we last wrote (jer dragged
      // it), adopt the new position; otherwise advance our fractional
      // counter and write the rounded value.
      let pos = 0;
      let lastSet = 0;
      function tick(now) {
        const dt = now - lastFrame;
        lastFrame = now;
        const max = body.scrollHeight - body.clientHeight;
        if (max > 0) {
          if (Math.abs(body.scrollTop - lastSet) > 1) {
            pos = body.scrollTop; // user dragged — resume from here
          }
          pos = Math.min(max, pos + pxPerMs * dt);
          body.scrollTop = pos;
          lastSet = body.scrollTop;
        }
        activeRAF = requestAnimationFrame(tick);
      }
      activeRAF = requestAnimationFrame(tick);
    });
  }

  function showSlide(i) {
    i = Math.max(0, Math.min(N - 1, i));
    current = i;
    // Note: re-applying the same slide restarts auto-scroll. The deck
    // dedupes walk-state on its side (broadcastState only fires on
    // change), so duplicate events shouldn't reach us.
    slides.forEach((el, idx) => el.classList.toggle('active', idx === i));
    dots.forEach((d, idx) => {
      d.classList.toggle('active', idx === i);
      d.classList.toggle('passed', idx < i);
    });
    const stateName = slides[i].dataset.state || '?';
    statusEl.textContent = `${stateName} · ${i + 1} / ${N}`;
    if (i === 0) {
      hintEl.textContent = 'space to begin';
    } else if (i === N - 1) {
      hintEl.textContent = 'final beat';
    } else {
      hintEl.textContent = 'space → next · ← → previous · R → reset';
    }
    // Kick off internal scroll for the new slide. Title (slide 0) has
    // a non-scrollable body, so this is a no-op there.
    startSlideAutoScroll(slides[i]);
  }

  // Local actions — drive the deck only; cue-card slide changes are
  // gated on the deck's walk-state broadcasts. The deck is the single
  // source of truth for "where in the talk we are."
  function localAdvance() { deckSend('advance'); }
  function localBack()    { deckSend('back');    }
  function localReset()   { deckSend('reset');   }

  document.addEventListener('keydown', (e) => {
    if (e.code === 'Space') { e.preventDefault(); localAdvance(); return; }
    if (e.code === 'ArrowLeft') { e.preventDefault(); localBack(); return; }
    if (e.code === 'ArrowRight') { e.preventDefault(); localAdvance(); return; }
    if (e.code === 'KeyR') { e.preventDefault(); localReset(); return; }
  });

  // Channel listener — apply named-state callbacks from the deck.
  // BroadcastChannel doesn't deliver to the sender; the `from` check is
  // defense-in-depth.
  if (chan) {
    chan.onmessage = (ev) => {
      const m = ev.data;
      if (!m || typeof m !== 'object') return;
      if (m.from === 'walkthrough') return;
      if (m.cmd === 'walk-state') {
        const idx = slideForState[m.name];
        if (typeof idx === 'number') showSlide(idx);
        // Unknown name → transient (auto-advance pass-through); ignore.
      }
      // Plain advance/back/reset are press relays we sent toward the deck;
      // ignore them here — slide changes only happen on walk-state.
    };
  }

  // Initial paint.
  showSlide(0);
})();
