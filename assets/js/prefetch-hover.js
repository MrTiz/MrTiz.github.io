// Prefetches same-origin links on hover/focus so navigation feels instant.
// Skips external hosts, data-saver, 2G, and already-prefetched URLs.
(function () {
    var HOVER_DELAY_MS = 65;
    var siteHost = location.hostname;
    var prefetched = Object.create(null);
    var pendingTimer = null;

    var conn = navigator.connection || navigator.mozConnection || navigator.webkitConnection;
    if (conn) {
        if (conn.saveData) return;
        if (/2g/.test(conn.effectiveType || '')) return;
    }
    try {
        if (matchMedia('(prefers-reduced-data: reduce)').matches) return;
    } catch (_) { }

    function isPrefetchable(anchor) {
        if (!anchor || anchor.tagName !== 'A') return false;
        if (anchor.target && anchor.target !== '_self') return false;
        var href = anchor.getAttribute('href');
        if (!href) return false;
        if (/^(#|mailto:|tel:|javascript:|data:)/i.test(href)) return false;
        try {
            var url = new URL(anchor.href);
            if (url.hostname !== siteHost) return false;
            if (url.pathname === location.pathname && url.search === location.search) return false;
            if (prefetched[url.href]) return false;
            return url.href;
        } catch (_) { return false; }
    }

    function prefetch(url) {
        if (prefetched[url]) return;
        prefetched[url] = true;
        var link = document.createElement('link');
        link.rel = 'prefetch';
        link.href = url;
        link.as = 'document';
        document.head.appendChild(link);
    }

    function schedule(anchor) {
        var url = isPrefetchable(anchor);
        if (!url) return;
        cancel();
        pendingTimer = setTimeout(function () { prefetch(url); }, HOVER_DELAY_MS);
    }

    function cancel() {
        if (pendingTimer) { clearTimeout(pendingTimer); pendingTimer = null; }
    }

    document.addEventListener('pointerover', function (e) {
        var a = e.target.closest && e.target.closest('a');
        if (a) schedule(a);
    }, { passive: true, capture: true });
    document.addEventListener('pointerout', cancel, { passive: true, capture: true });

    document.addEventListener('focusin', function (e) {
        var a = e.target.closest && e.target.closest('a');
        if (a) schedule(a);
    }, { passive: true, capture: true });

    document.addEventListener('touchstart', function (e) {
        var a = e.target.closest && e.target.closest('a');
        if (a) {
            var url = isPrefetchable(a);
            if (url) prefetch(url);
        }
    }, { passive: true, capture: true });
})();
