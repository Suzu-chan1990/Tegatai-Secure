/* Tegatai Secure - 2FA box (Tegatai screen and user profile): actions, backup codes. */
(function () {
    'use strict';

    // Posts a 2FA action (verify, reset, backup_generate) as a normal form to admin-post.php.
    // URL, nonce and return URL are data attributes of the #tegatai-2fa-section element.
    function submitAction(section, subaction, instId) {
        var inpEl = instId ? document.getElementById(instId + '_input') : null;
        var f = document.createElement('form');
        f.method = 'POST';
        f.action = section.getAttribute('data-post-url');
        var fields = {
            action: 'tegatai_2fa_profile_action',
            _wpnonce: section.getAttribute('data-nonce'),
            tegatai_2fa_subaction: subaction,
            tegatai_test_code: inpEl ? inpEl.value : '',
            tegatai_return_to: section.getAttribute('data-return')
        };
        Object.keys(fields).forEach(function (k) {
            var inp = document.createElement('input');
            inp.type = 'hidden';
            inp.name = k;
            inp.value = fields[k];
            f.appendChild(inp);
        });
        document.body.appendChild(f);
        f.submit();
    }

    function codesText() {
        var t = document.getElementById('teg-2fa-bc-text');
        return t ? t.value : '';
    }

    document.addEventListener('click', function (e) {
        var btn = e.target.closest('[data-tegatai-2fa]');
        if (!btn) return;
        var section = btn.closest('#tegatai-2fa-section');
        if (!section) return;
        e.preventDefault();
        var action = btn.getAttribute('data-tegatai-2fa');
        var confirmText = btn.getAttribute('data-confirm');
        if (confirmText && !window.confirm(confirmText)) return;

        if (action === 'download') {
            var blob = new Blob([codesText()], { type: 'text/plain;charset=utf-8' });
            var a = document.createElement('a');
            a.href = URL.createObjectURL(blob);
            a.download = btn.getAttribute('data-filename') || 'backup-codes.txt';
            document.body.appendChild(a);
            a.click();
            setTimeout(function () { URL.revokeObjectURL(a.href); a.remove(); }, 1000);
        } else if (action === 'copy') {
            var txt = codesText();
            var done = function () { btn.textContent = btn.getAttribute('data-done'); };
            if (navigator.clipboard && window.isSecureContext) {
                navigator.clipboard.writeText(txt).then(done);
            } else {
                var t = document.getElementById('teg-2fa-bc-text');
                t.style.display = 'block'; t.select(); document.execCommand('copy'); t.style.display = 'none';
                done();
            }
        } else if (action === 'print') {
            var w = window.open('', '_blank', 'width=480,height=640');
            if (!w) return;
            var pre = w.document.createElement('pre');
            pre.style.fontSize = '15px';
            pre.textContent = codesText();
            w.document.body.appendChild(pre);
            w.focus();
            w.print();
        } else {
            submitAction(section, action, btn.getAttribute('data-instance'));
        }
    });
})();
