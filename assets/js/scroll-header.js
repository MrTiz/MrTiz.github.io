// Toggles data-scrolled on the header for the CSS border underline.
(function () {
    var header = document.getElementById('site-header');
    if (!header) return;

    var raf = null;
    function update() {
        raf = null;
        header.setAttribute('data-scrolled', window.scrollY > 4 ? 'true' : 'false');
    }
    function onScroll() { if (raf == null) raf = requestAnimationFrame(update); }

    update();
    window.addEventListener('scroll', onScroll, { passive: true });
})();
