// Opens external links inside post content in a new tab with noopener.
// Saves having to add {: target="_blank"} on every Markdown link.
(function () {
    var siteHost = location.hostname;

    // Same-origin resources that should still open in a new tab
    var SAME_ORIGIN_NEW_TAB = ['/feed.xml'];

    function shouldOpenInNewTab(anchor) {
        var href = anchor.getAttribute('href');
        if (!href) return false;
        if (/^(#|mailto:|tel:|javascript:)/i.test(href)) return false;
        try {
            var url = new URL(anchor.href);
            if (url.hostname !== siteHost) return true;
            return SAME_ORIGIN_NEW_TAB.indexOf(url.pathname) !== -1;
        } catch (_) { return false; }
    }

    function decorate(anchor) {
        if (anchor.dataset.externalDecorated === '1') return;
        anchor.setAttribute('target', '_blank');
        var rel = (anchor.getAttribute('rel') || '').split(/\s+/).filter(Boolean);
        ['noopener', 'noreferrer'].forEach(function (token) {
            if (rel.indexOf(token) === -1) rel.push(token);
        });
        anchor.setAttribute('rel', rel.join(' '));
        anchor.dataset.externalDecorated = '1';
    }

    // Only touches prose content; header/footer links are hand-authored
    function run() {
        var scopes = document.querySelectorAll('.post__content');
        scopes.forEach(function (scope) {
            scope.querySelectorAll('a[href]').forEach(function (a) {
                if (shouldOpenInNewTab(a)) decorate(a);
            });
        });
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', run, { once: true });
    } else {
        run();
    }
})();
