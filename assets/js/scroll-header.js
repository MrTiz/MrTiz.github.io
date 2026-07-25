// Toggles data-scrolled on the header for the CSS border underline,
// writes --scroll-progress (0..1) used as the reading-progress fill,
// toggles is-scrolled-deep on <html> to reveal the scroll-to-top button,
// and toggles is-idle after IDLE_TIMEOUT ms of no scrolling to dim it.
(function () {
    var header = document.getElementById('site-header');
    if (!header) return;

    var DEEP_THRESHOLD = 1500;
    var IDLE_TIMEOUT = 2000;
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
        var max = root.scrollHeight - window.innerHeight;
        var p = max > 0 ? Math.min(1, Math.max(0, y / max)) : 0;
        header.style.setProperty('--scroll-progress', p);
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
        });
    }
})();
