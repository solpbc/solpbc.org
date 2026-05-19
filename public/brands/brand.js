/* brands page — progressive enhancement only.
 *
 * the page is fully usable with this file blocked or absent: every copyable
 * value is visible, selectable text and every asset has a real <a download>.
 * this script adds copy-to-clipboard, the scrollspy nav state, and nothing
 * else. no third-party code, no network calls (the brands CSP has no
 * connect-src — the Clipboard API is not a fetch). build spec §5.5 / §5.6.
 */
(function () {
  'use strict';

  // reveal copy buttons only once JS is confirmed running, so no-JS visitors
  // never see a dead control (they get selectable text + download links).
  document.documentElement.classList.add('js');

  var live = document.getElementById('copy-live');
  var SUCCESS = 'copied';        // build spec §6.9
  var FALLBACK = 'select and copy';
  var HOLD_MS = 1500;            // "~1.5s" — build spec §6.9

  function announce(msg) { if (live) { live.textContent = ''; live.textContent = msg; } }

  // text to copy for a given button, byte-exact where it matters.
  function resolveText(btn) {
    // the v̇ constant: build from explicit code points so editor/encoding
    // normalization can never corrupt it. byte target (build spec §6.5):
    // const VIT_MARK = '<U+0076><U+0307>';
    if (btn.hasAttribute('data-copy-text-const')) {
      return "const VIT_MARK = '" + String.fromCodePoint(0x76, 0x0307) + "';";
    }
    if (btn.hasAttribute('data-copy-text')) {
      return btn.getAttribute('data-copy-text');
    }
    var sel = btn.getAttribute('data-copy-from');
    if (sel) {
      var src = document.querySelector(sel);
      if (!src) return null;
      var skip = btn.getAttribute('data-skip');
      if (skip) {
        // copy the value without its little "kind" label
        var clone = src.cloneNode(true);
        clone.querySelectorAll(skip).forEach(function (n) { n.remove(); });
        return clone.textContent;
      }
      // textContent of an element holding e.g. v&#x307; is exactly the two
      // code points U+0076 U+0307 — byte-exact, single-sourced from the DOM.
      return src.textContent;
    }
    return null;
  }

  function selectSource(btn) {
    var sel = btn.getAttribute('data-copy-from');
    if (!sel) return;
    var src = document.querySelector(sel);
    if (!src || !src.offsetParent) return; // not selectable if not visible
    try {
      var range = document.createRange();
      range.selectNodeContents(src);
      var s = window.getSelection();
      s.removeAllRanges();
      s.addRange(range);
    } catch (e) { /* selection unsupported — value is still visible text */ }
  }

  function flash(btn, label, state) {
    if (btn._t) { clearTimeout(btn._t); }
    // swatch chips have no text label — confirm via data-state (CSS pill) +
    // the aria-live announcement only; don't write text into the color block.
    var isChip = btn.classList.contains('chip');
    if (!isChip) {
      if (btn._orig == null) { btn._orig = btn.textContent; }
      btn.textContent = label;
    }
    if (state) { btn.setAttribute('data-state', state); }
    btn._t = setTimeout(function () {
      if (!isChip) { btn.textContent = btn._orig; }
      btn.removeAttribute('data-state');
      btn._t = null;
    }, HOLD_MS);
  }

  function onCopy(btn) {
    var text = resolveText(btn);
    if (text == null) { return; }
    var ok = function () { flash(btn, SUCCESS, 'done'); announce(SUCCESS); };
    var fail = function () {
      selectSource(btn);
      flash(btn, FALLBACK, 'manual');
      announce('copy failed — ' + FALLBACK);
    };
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(ok, fail);
    } else {
      fail();
    }
  }

  // .copy-btn = labelled buttons (revealed only with JS). .swatch .chip =
  // the color block itself, always visible, click-to-copy its hex (§5.2.5);
  // its no-JS path is the selectable hex text rendered beside it.
  document.querySelectorAll('.copy-btn, .swatch .chip').forEach(function (btn) {
    btn.addEventListener('click', function () { onCopy(btn); });
  });

  // --- scrollspy: reflect the section in view on the sticky nav ---
  var links = {};
  document.querySelectorAll('nav.bar a').forEach(function (a) {
    links[a.getAttribute('href').slice(1)] = a;
  });
  var sections = document.querySelectorAll('main section[id]');
  if ('IntersectionObserver' in window && sections.length) {
    var current = null;
    var io = new IntersectionObserver(function (entries) {
      entries.forEach(function (en) {
        if (en.isIntersecting) {
          if (current && links[current]) { links[current].removeAttribute('aria-current'); }
          current = en.target.id;
          if (links[current]) { links[current].setAttribute('aria-current', 'true'); }
        }
      });
    }, { rootMargin: '-45% 0px -50% 0px', threshold: 0 });
    sections.forEach(function (s) { io.observe(s); });
  }
})();
