// Toggles data-scrolled on the header for the CSS border underline,
// writes --scroll-progress (0..1) used as the reading-progress fill,
// toggles is-scrolled-deep on <html> to reveal the scroll-to-top button,
// and toggles is-idle after IDLE_TIMEOUT ms of no scrolling to dim it.
(function () {
    var header = document.getElementById('site-header');
    if (!header) return;

    var DEEP_THRESHOLD = 1500;
    var IDLE_TIMEOUT = 1500;
    var root = document.documentElement;
    var raf = null;
    var idleTimer = null;

    function markActive() {
        root.classList.remove('is-idle');
        if (idleTimer) clearTimeout(idleTimer);
        idleTimer = setTimeout(function () {
            root.classList.add('is-idle');
        }, IDLE_TIMEOUT);
    }

    function update() {
        raf = null;
        var y = window.scrollY;
        header.setAttribute('data-scrolled', y > 4 ? 'true' : 'false');
        root.classList.toggle('is-scrolled-deep', y > DEEP_THRESHOLD);
        // Skip the --scroll-progress write during a drag; the pump() below
        // owns it and any real-scroll write would fight the optimistic one
        // and cause the bar to flicker between the finger and the page.
        if (!scrubbing) {
            var max = root.scrollHeight - window.innerHeight;
            var p = max > 0 ? Math.min(1, Math.max(0, y / max)) : 0;
            header.style.setProperty('--scroll-progress', p);
        }
        markActive();
    }
    function schedule() { if (raf == null) raf = requestAnimationFrame(update); }

    update();
    window.addEventListener('scroll', schedule, { passive: true });
    window.addEventListener('resize', schedule, { passive: true });

    var topBtn = document.getElementById('scroll-top');
    if (topBtn) {
        topBtn.addEventListener('click', function () {
            window.scrollTo({ top: 0, left: 0 });
            // Release focus so the button dims normally when it reappears
            // (mobile taps keep :focus on the DOM node even after it's hidden)
            topBtn.blur();
        });
    }

    // Header as reading-progress scrubber: tap/drag anywhere on its empty
    // area to seek. pointerdown on brand/nav/buttons is ignored so those
    // still fire normally. setPointerCapture makes the header receive every
    // pointermove until pointerup — the drag continues even if the finger
    // leaves the header vertically.
    //
    // Throttling: pointermove can fire 100+ times/sec on a fast mouse. We
    // coalesce all of them into one scrollTo per rAF (~60fps). We also write
    // --scroll-progress optimistically from the pointer X so the visual bar
    // tracks the cursor exactly, without waiting for scroll+repaint on long
    // pages. Rect and scroll max are cached at pointerdown so pump() never
    // triggers a forced layout during the drag.
    var scrubbing = false;
    var scrubX = 0;
    var scrubRAF = null;
    var scrubRect = null;
    var scrubMax = 0;
    var INTERACTIVE = 'a, button, input, select, textarea, [role="button"]';

    function pump() {
        scrubRAF = null;
        if (!scrubbing) return;
        var ratio = (scrubX - scrubRect.left) / scrubRect.width;
        if (ratio < 0) ratio = 0;
        else if (ratio > 1) ratio = 1;
        header.style.setProperty('--scroll-progress', ratio);
        // Force instant to override the site-wide `scroll-behavior: smooth`.
        // With smooth, the page interpolates toward target over ~300ms; if
        // the user releases mid-interpolation, subsequent scroll events fire
        // with `scrubbing = false` and overwrite the bar with the still-
        // catching-up scroll position, causing a visible dip-and-refill.
        window.scrollTo({ top: ratio * scrubMax, left: 0, behavior: 'instant' });
    }
    function schedulePump() {
        if (scrubRAF == null) scrubRAF = requestAnimationFrame(pump);
    }

    header.addEventListener('pointerdown', function (e) {
        // Let brand/nav/buttons handle their own clicks
        if (e.target.closest(INTERACTIVE)) return;
        scrubbing = true;
        scrubRect = header.getBoundingClientRect();
        scrubMax = root.scrollHeight - window.innerHeight;
        scrubX = e.clientX;
        try { header.setPointerCapture(e.pointerId); } catch (_) {}
        schedulePump();
    });

    header.addEventListener('pointermove', function (e) {
        if (!scrubbing) return;
        scrubX = e.clientX;
        schedulePump();
    });

    function endScrub(e) {
        if (!scrubbing) return;
        scrubbing = false;
        try { header.releasePointerCapture(e.pointerId); } catch (_) {}
    }
    header.addEventListener('pointerup', endScrub);
    header.addEventListener('pointercancel', endScrub);
})();
