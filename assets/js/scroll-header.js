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
        var scrolled = y > 4;
        var deep = y > DEEP_THRESHOLD;
        // During a drag pump() owns --scroll-progress; a real-scroll write
        // here would fight its optimistic one and flicker the bar.
        var p = null;
        if (!scrubbing) {
            var max = root.scrollHeight - window.innerHeight;
            p = max > 0 ? Math.min(1, Math.max(0, y / max)) : 0;
        }

        header.setAttribute('data-scrolled', scrolled ? 'true' : 'false');
        root.classList.toggle('is-scrolled-deep', deep);
        if (p !== null) header.style.setProperty('--scroll-progress', p);
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
            // Mobile taps keep :focus on the node even after it's hidden.
            topBtn.blur();
        });
    }

    // Rect + scroll max are cached at pointerdown so pump() never forces
    // layout during the drag; ratio is written optimistically so the bar
    // tracks the finger without waiting for scroll+repaint on long pages.
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
        // `instant` overrides the site-wide smooth scroll: without it, a
        // release mid-interpolation lets update() overwrite the bar with
        // the still-catching-up position and the bar dips then refills.
        window.scrollTo({ top: ratio * scrubMax, left: 0, behavior: 'instant' });
    }
    function schedulePump() {
        if (scrubRAF == null) scrubRAF = requestAnimationFrame(pump);
    }

    header.addEventListener('pointerdown', function (e) {
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
