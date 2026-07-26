(function () {
    var header = document.getElementById('site-header');
    if (!header) return;

    var DEEP_THRESHOLD = 1500;
    var IDLE_TIMEOUT = 1500;
    var root = document.documentElement;
    var raf = null;
    var idleTimer = null;
    var docMax = 0;
    function refreshDocMax() {
        docMax = root.scrollHeight - window.innerHeight;
    }

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
        var p = null;

        if (!scrubbing) {
            p = docMax > 0 ? Math.min(1, Math.max(0, y / docMax)) : 0;
        }

        header.setAttribute('data-scrolled', scrolled ? 'true' : 'false');
        root.classList.toggle('is-scrolled-deep', deep);
        if (p !== null) header.style.setProperty('--scroll-progress', p);
        markActive();
    }
    function schedule() { if (raf == null) raf = requestAnimationFrame(update); }

    refreshDocMax();
    update();

    window.addEventListener('scroll', schedule, { passive: true });
    window.addEventListener('resize', function () {
        refreshDocMax();
        schedule();
    }, { passive: true });

    window.addEventListener('load', refreshDocMax);

    if (typeof ResizeObserver === 'function') {
        new ResizeObserver(refreshDocMax).observe(document.body);
    }

    var topBtn = document.getElementById('scroll-top');
    if (topBtn) {
        topBtn.addEventListener('click', function () {
            window.scrollTo({ top: 0, left: 0 });
            topBtn.blur();
        });
    }

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
