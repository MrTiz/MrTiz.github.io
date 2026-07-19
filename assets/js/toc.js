// Table of Contents: populates both the desktop sidebar (#toc-list) and the
// mobile dropdown panel (#toc-panel-list), with scrollspy highlighting.
(function () {
    var content = document.getElementById('post-content');
    var tocList = document.getElementById('toc-list');
    var panelList = document.getElementById('toc-panel-list');
    var tocEl = document.getElementById('toc');
    var details = document.getElementById('toc-details');
    var toggleBtn = document.getElementById('toc-toggle-btn');
    var panel = document.getElementById('toc-panel');
    var backdrop = document.getElementById('toc-panel-backdrop');
    if (!content) return;

    var SKIP_TITLES = ['table of contents', 'contents', 'toc'];

    function slugify(text) {
        return text
            .toLowerCase()
            .trim()
            .replace(/[^\w\s-]/g, '')
            .replace(/\s+/g, '-')
            .replace(/-+/g, '-');
    }

    var headings = Array.prototype.slice.call(
        content.querySelectorAll('h2, h3')
    ).filter(function (h) {
        var t = (h.textContent || '').trim().toLowerCase();
        return SKIP_TITLES.indexOf(t) === -1;
    });

    if (headings.length < 2) {
        if (tocEl) tocEl.style.display = 'none';
        if (toggleBtn) toggleBtn.hidden = true;
        return;
    }

    // Assign IDs and append # anchor links
    var usedIds = Object.create(null);
    headings.forEach(function (h) {
        if (!h.id) {
            var base = slugify(h.textContent || 'section');
            var candidate = base, i = 2;
            while (usedIds[candidate] || document.getElementById(candidate)) {
                candidate = base + '-' + i++;
            }
            h.id = candidate;
        }
        usedIds[h.id] = true;

        if (!h.querySelector('.heading-anchor')) {
            var a = document.createElement('a');
            a.className = 'heading-anchor';
            a.href = '#' + h.id;
            a.setAttribute('aria-label', 'Link to this section');
            a.textContent = '#';
            h.appendChild(a);
        }
    });

    function populate(root, itemClassPrefix, linkClass) {
        if (!root) return [];
        var frag = document.createDocumentFragment();
        var links = [];
        headings.forEach(function (h) {
            var li = document.createElement('li');
            li.className = itemClassPrefix + ' ' + itemClassPrefix + '--' + h.tagName.toLowerCase();
            var a = document.createElement('a');
            if (linkClass) a.className = linkClass;
            a.href = '#' + h.id;
            a.textContent = (h.textContent || '').replace(/#$/, '').trim();
            a.dataset.target = h.id;
            li.appendChild(a);
            frag.appendChild(li);
            links.push(a);
        });
        root.appendChild(frag);
        return links;
    }

    var sidebarLinks = populate(tocList, 'toc__item', 'toc__link');
    var panelLinks = populate(panelList, 'toc-panel__item', '');

    // Keep desktop <details> open
    var DESKTOP_QUERY = window.matchMedia('(min-width: 1080px)');
    function syncDetails() {
        if (details && DESKTOP_QUERY.matches) details.open = true;
    }
    syncDetails();
    if (DESKTOP_QUERY.addEventListener) {
        DESKTOP_QUERY.addEventListener('change', syncDetails);
    } else if (DESKTOP_QUERY.addListener) {
        DESKTOP_QUERY.addListener(syncDetails);
    }

    // --- Mobile panel toggle ---
    function openPanel() {
        if (!panel) return;
        document.body.setAttribute('data-toc-open', 'true');
        if (toggleBtn) toggleBtn.setAttribute('aria-expanded', 'true');
        panel.hidden = false;
        if (backdrop) backdrop.hidden = false;
    }
    function closePanel() {
        document.body.removeAttribute('data-toc-open');
        if (toggleBtn) toggleBtn.setAttribute('aria-expanded', 'false');
        if (panel) panel.hidden = true;
        if (backdrop) backdrop.hidden = true;
    }
    function togglePanel() {
        if (document.body.getAttribute('data-toc-open') === 'true') closePanel();
        else openPanel();
    }

    if (toggleBtn) {
        toggleBtn.hidden = false;
        toggleBtn.addEventListener('click', togglePanel);
    }
    if (backdrop) {
        backdrop.addEventListener('click', closePanel);
    }
    document.addEventListener('keydown', function (e) {
        if (e.key === 'Escape' && document.body.getAttribute('data-toc-open') === 'true') {
            closePanel();
        }
    });

    // Close panel on link tap
    if (panelList) {
        panelList.addEventListener('click', function (e) {
            var link = e.target.closest('a');
            if (link) closePanel();
        });
    }
    if (tocList) {
        tocList.addEventListener('click', function (e) {
            var link = e.target.closest('.toc__link');
            if (!link) return;
            if (details && !DESKTOP_QUERY.matches) details.open = false;
        });
    }

    // --- Scrollspy ---
    var linkById = Object.create(null);
    sidebarLinks.forEach(function (l) {
        linkById[l.dataset.target] = linkById[l.dataset.target] || [];
        linkById[l.dataset.target].push(l);
    });
    panelLinks.forEach(function (l) {
        linkById[l.dataset.target] = linkById[l.dataset.target] || [];
        linkById[l.dataset.target].push(l);
    });

    var allLinks = sidebarLinks.concat(panelLinks);

    var visible = new Map();
    var observer = new IntersectionObserver(function (entries) {
        entries.forEach(function (e) {
            if (e.isIntersecting) visible.set(e.target.id, e.intersectionRatio);
            else visible.delete(e.target.id);
        });

        var activeId = null;
        if (visible.size > 0) {
            var top = Infinity;
            visible.forEach(function (_, id) {
                var el = document.getElementById(id);
                if (!el) return;
                var t = el.getBoundingClientRect().top;
                if (t >= 0 && t < top) { top = t; activeId = id; }
            });
            if (!activeId) {
                var lastVisible = null, lastTop = -Infinity;
                visible.forEach(function (_, id) {
                    var el = document.getElementById(id);
                    if (!el) return;
                    var t = el.getBoundingClientRect().top;
                    if (t > lastTop) { lastTop = t; lastVisible = id; }
                });
                activeId = lastVisible;
            }
        }

        if (!activeId) {
            for (var i = headings.length - 1; i >= 0; i--) {
                if (headings[i].getBoundingClientRect().top < 100) {
                    activeId = headings[i].id;
                    break;
                }
            }
        }

        allLinks.forEach(function (l) {
            l.classList.remove('toc__link--active');
            l.classList.remove('is-active');
        });
        if (activeId && linkById[activeId]) {
            linkById[activeId].forEach(function (l) {
                if (l.classList.contains('toc__link')) l.classList.add('toc__link--active');
                else l.classList.add('is-active');
            });
            // Keep active link in view inside the sidebar
            if (DESKTOP_QUERY.matches && tocEl && tocEl.scrollHeight > tocEl.clientHeight) {
                var link = linkById[activeId].find(function (l) { return l.classList.contains('toc__link'); });
                if (link) {
                    var linkTop = link.offsetTop;
                    var viewTop = tocEl.scrollTop;
                    var viewBottom = viewTop + tocEl.clientHeight;
                    if (linkTop < viewTop || linkTop + link.offsetHeight > viewBottom) {
                        tocEl.scrollTop = linkTop - tocEl.clientHeight / 2;
                    }
                }
            }
        }
    }, {
        rootMargin: '-72px 0px -70% 0px',
        threshold: [0, 1],
    });

    headings.forEach(function (h) { observer.observe(h); });
})();
