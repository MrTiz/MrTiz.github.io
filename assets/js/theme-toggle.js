// Light/dark toggle. Persists to localStorage. Dark is the default;
// the <head> boot script applies the saved theme before first paint.
(function () {
    var root = document.documentElement;
    var button = document.getElementById('theme-toggle');
    var meta = document.getElementById('theme-color-meta');
    if (!button) return;

    var META_COLORS = { dark: '#0f1218', light: '#ffffff' };

    function currentTheme() {
        return root.getAttribute('data-theme') === 'light' ? 'light' : 'dark';
    }

    function apply(next) {
        root.setAttribute('data-theme', next);
        if (meta && META_COLORS[next]) meta.setAttribute('content', META_COLORS[next]);
        button.setAttribute('aria-pressed', next === 'light' ? 'true' : 'false');
    }

    button.addEventListener('click', function () {
        var next = currentTheme() === 'dark' ? 'light' : 'dark';
        try { localStorage.setItem('theme', next); } catch (_) { }
        apply(next);
    });

    button.setAttribute('aria-pressed', currentTheme() === 'light' ? 'true' : 'false');
})();
