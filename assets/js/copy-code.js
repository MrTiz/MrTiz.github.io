// Rewrites Rouge's <table> code blocks into a CSS grid and adds a
// header bar with language label, copy button, and wrap toggle.
(function () {
    var COPY_ICON =
        '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">' +
        '<rect x="9" y="9" width="13" height="13" rx="2"/>' +
        '<path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/>' +
        '</svg>';
    var CHECK_ICON =
        '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">' +
        '<polyline points="20 6 9 17 4 12"/>' +
        '</svg>';
    var WRAP_ICON =
        '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">' +
        '<line x1="3" y1="6" x2="21" y2="6"/>' +
        '<path d="M3 12h15a3 3 0 0 1 0 6h-4"/>' +
        '<polyline points="16 16 14 18 16 20"/>' +
        '<line x1="3" y1="18" x2="10" y2="18"/>' +
        '</svg>';

    function copyText(text) {
        if (navigator.clipboard && window.isSecureContext) {
            return navigator.clipboard.writeText(text);
        }
        // Fallback for non-secure contexts
        return new Promise(function (resolve, reject) {
            try {
                var ta = document.createElement('textarea');
                ta.value = text;
                ta.setAttribute('readonly', '');
                ta.style.position = 'fixed';
                ta.style.top = '-1000px';
                document.body.appendChild(ta);
                ta.select();
                document.execCommand('copy');
                document.body.removeChild(ta);
                resolve();
            } catch (e) { reject(e); }
        });
    }

    function detectLang(wrapper, codeEl) {
        var m = wrapper.className.match(/language-([\w+#.-]+)/);
        if (m) return m[1];
        if (codeEl) {
            var cm = (codeEl.className || '').match(/language-([\w+#.-]+)/);
            if (cm) return cm[1];
        }
        return 'code';
    }

    // Replaces Rouge's gutter/code <table> with a flat CSS grid.
    // Returns the plain-text source for the copy button.
    function restructureBlock(wrap) {
        var codePre = wrap.querySelector('td.rouge-code pre');
        if (!codePre) return null;
        var gutterPre = wrap.querySelector('td.rouge-gutter pre');

        var codeHTML = codePre.innerHTML.replace(/\n+$/, '');
        var lines = codeHTML.split('\n');

        // Drop trailing empty fragments left by Rouge's whitespace token
        var probe = document.createElement('div');
        while (lines.length > 1) {
            probe.innerHTML = lines[lines.length - 1];
            if ((probe.textContent || '').trim() === '') {
                lines.pop();
            } else {
                break;
            }
        }

        var nums;
        if (gutterPre) {
            nums = gutterPre.textContent.replace(/\n+$/, '').split('\n');
        } else {
            nums = lines.map(function (_, i) { return String(i + 1); });
        }

        var grid = document.createElement('div');
        grid.className = 'rouge-grid';

        var plainLines = [];
        for (var i = 0; i < lines.length; i++) {
            var numEl = document.createElement('span');
            numEl.className = 'rouge-num';
            numEl.textContent = nums[i] != null ? nums[i] : String(i + 1);
            numEl.setAttribute('aria-hidden', 'true');

            var lineEl = document.createElement('span');
            lineEl.className = 'rouge-line';
            // Zero-width space keeps empty lines at visible height
            lineEl.innerHTML = lines[i].length ? lines[i] : '\u200b';

            grid.appendChild(numEl);
            grid.appendChild(lineEl);

            var tmp = document.createElement('div');
            tmp.innerHTML = lines[i];
            plainLines.push(tmp.textContent || '');
        }

        var outerCode = wrap.querySelector('pre.highlight > code');
        if (outerCode) {
            outerCode.innerHTML = '';
            outerCode.appendChild(grid);
        }

        return plainLines.join('\n');
    }

    function extractText(wrap) {
        if (wrap._rougeText) return wrap._rougeText;
        var codeCell = wrap.querySelector('td.rouge-code');
        if (codeCell) {
            return (codeCell.innerText || codeCell.textContent || '').replace(/\n$/, '');
        }
        var pre = wrap.querySelector('pre');
        if (pre) return (pre.innerText || pre.textContent || '').replace(/\n$/, '');
        return '';
    }

    function decorateBlock(rougeWrap) {
        if (rougeWrap.dataset.decorated === '1') return;
        if (rougeWrap.closest('.code-block')) return;

        var savedText = restructureBlock(rougeWrap);
        if (savedText !== null) rougeWrap._rougeText = savedText;

        var lang = detectLang(rougeWrap, rougeWrap.querySelector('code'));

        var head = document.createElement('div');
        head.className = 'code-block__head';
        head.innerHTML =
            '<span class="code-block__lang">' + lang + '</span>' +
            '<div class="code-block__actions">' +
            '<button type="button" class="code-block__btn code-block__wrap"' +
            ' aria-label="Toggle line wrapping" aria-pressed="true" title="Toggle line wrapping">' +
            WRAP_ICON + '<span>Wrap</span>' +
            '</button>' +
            '<button type="button" class="code-block__btn code-block__copy" aria-label="Copy code">' +
            COPY_ICON + '<span>Copy</span>' +
            '</button>' +
            '</div>';

        rougeWrap.insertBefore(head, rougeWrap.firstChild);
        rougeWrap.classList.add('code-block');
        rougeWrap.dataset.decorated = '1';

        var copyBtn = head.querySelector('.code-block__copy');
        copyBtn.addEventListener('click', function () {
            var text = extractText(rougeWrap);
            copyText(text).then(function () {
                copyBtn.setAttribute('data-state', 'copied');
                copyBtn.innerHTML = CHECK_ICON + '<span>Copied</span>';
                setTimeout(function () {
                    copyBtn.removeAttribute('data-state');
                    copyBtn.innerHTML = COPY_ICON + '<span>Copy</span>';
                }, 1600);
            }).catch(function () {
                copyBtn.innerHTML = '<span>Failed</span>';
            });
        });

        // Wrap toggle: flips `is-nowrap` on the block container
        var wrapBtn = head.querySelector('.code-block__wrap');
        wrapBtn.addEventListener('click', function () {
            var wrapped = !rougeWrap.classList.contains('is-nowrap');
            rougeWrap.classList.toggle('is-nowrap', wrapped);
            wrapBtn.setAttribute('aria-pressed', wrapped ? 'false' : 'true');
        });
    }

    function run() {
        var wraps = document.querySelectorAll(
            'div.highlighter-rouge, figure.highlighter-rouge, ' +
            '.post__content div.highlight, .post__content figure.highlight'
        );
        wraps.forEach(decorateBlock);
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', run, { once: true });
    } else {
        run();
    }
})();
