/* Tegatai Secure - Hive and API Guard screens. Data and texts from TegataiSub (wp_localize_script). */
(function () {
    'use strict';
    var cfg = window.TegataiSub || { i18n: {} };
    var t = function (key) { return (cfg.i18n && cfg.i18n[key]) || key; };

    function parseJson(text) {
        var start = text.indexOf('{');
        return JSON.parse(start > -1 ? text.substring(start) : text);
    }

    // Sudo actions: reveal a secret or show a newly generated one (never saved)
    function sudo(action, nonceId, field, mode, input, btnRev, btnCop) {
        var pin = window.prompt(t('pinPrompt'));
        if (!pin) return;
        var fd = new FormData();
        fd.append('action', action);
        fd.append('pin', pin);
        fd.append('mode', mode);
        fd.append('security', document.getElementById(nonceId).value);
        fetch(cfg.ajaxUrl, { method: 'POST', body: fd, credentials: 'same-origin' })
            .then(function (res) { return res.text(); })
            .then(parseJson)
            .then(function (data) {
                if (!data.success) {
                    alert(data.data === 'SUDO_NOT_CONFIGURED' ? t('pinMissing') : t('pinInvalid'));
                    return;
                }
                input.value = data.data[field];
                input.type = 'text';
                if (btnCop) btnCop.style.display = 'inline-block';
                if (mode === 'reveal' && btnRev) btnRev.style.display = 'none';
            })
            .catch(function (err) { alert(t('requestFailed') + ' ' + err.message); });
    }

    function copyButton(btnCop, input) {
        if (!btnCop) return;
        btnCop.addEventListener('click', function (e) {
            e.preventDefault();
            if (input.value === '') return;
            var done = function () {
                var orig = btnCop.innerText;
                btnCop.innerText = '✔ ' + t('copied');
                setTimeout(function () { btnCop.innerText = orig; }, 2000);
            };
            navigator.clipboard.writeText(input.value).then(done).catch(function () {
                input.type = 'text'; input.select(); document.execCommand('copy'); input.type = 'password';
                done();
            });
        });
    }

    function wire(prefix, action, nonceId, field) {
        var input = document.getElementById(prefix.input);
        if (!input) return;
        var btnGen = document.getElementById(prefix.gen);
        var btnRev = document.getElementById(prefix.rev);
        var btnCop = document.getElementById(prefix.copy);
        if (btnGen) btnGen.addEventListener('click', function (e) { e.preventDefault(); sudo(action, nonceId, field, 'generate', input, btnRev, btnCop); });
        if (btnRev) btnRev.addEventListener('click', function (e) { e.preventDefault(); sudo(action, nonceId, field, 'reveal', input, btnRev, btnCop); });
        copyButton(btnCop, input);
    }

    document.addEventListener('DOMContentLoaded', function () {
        // --- The Hive ---
        wire({ input: 'hive_secret_key', gen: 'generate_hive_key', rev: 'reveal_hive_key', copy: 'copy_hive_key' }, 'tegatai_sudo_hive', 'tegatai_hive_sudo_nonce', 'key');

        var btnTest = document.getElementById('test_hive_connections');
        var spinner = document.getElementById('test_spinner');
        var results = document.getElementById('test_results');
        if (btnTest && results) {
            btnTest.addEventListener('click', function (e) {
                e.preventDefault();
                if (spinner) spinner.classList.add('is-active');
                results.style.display = 'block';
                results.textContent = t('pinging');
                var fd = new FormData();
                fd.append('action', 'tegatai_hive_test');
                fd.append('security', cfg.hiveTestNonce);
                fetch(cfg.ajaxUrl, { method: 'POST', body: fd, credentials: 'same-origin' })
                    .then(function (res) { return res.text(); })
                    .then(function (text) {
                        try { return parseJson(text.trim()); } catch (err) { throw new Error(text.substring(0, 400)); }
                    })
                    .then(function (data) {
                        if (spinner) spinner.classList.remove('is-active');
                        results.textContent = '';
                        if (!data || !data.success) {
                            var err = document.createElement('span');
                            err.style.color = 'var(--teg-danger)';
                            err.style.fontWeight = '600';
                            err.textContent = '✖ ' + ((data && data.data) ? data.data : t('unknownError'));
                            results.appendChild(err);
                            return;
                        }
                        var head = document.createElement('strong');
                        head.textContent = t('results');
                        results.appendChild(head);
                        var ul = document.createElement('ul');
                        ul.style.margin = '8px 0 0';
                        data.data.forEach(function (item) {
                            var li = document.createElement('li');
                            li.style.color = item.status === 'success' ? 'var(--teg-success)' : 'var(--teg-danger)';
                            li.textContent = (item.status === 'success' ? '✔ ' : '✖ ') + item.url + ' → ' + item.msg;
                            ul.appendChild(li);
                        });
                        results.appendChild(ul);
                    })
                    .catch(function (err) {
                        if (spinner) spinner.classList.remove('is-active');
                        results.textContent = t('connectionError') + ' ' + err.message;
                    });
            });
        }

        // --- API Guard ---
        var modeSelector = document.getElementById('auth_mode_selector');
        if (modeSelector) {
            modeSelector.addEventListener('change', function () {
                document.getElementById('snippet_static').style.display = this.value === 'static' ? 'block' : 'none';
                document.getElementById('snippet_hmac').style.display = this.value === 'hmac' ? 'block' : 'none';
            });
        }
        wire({ input: 'api_secret_gen', gen: 'generate_api_btn', rev: 'reveal_api_btn', copy: 'copy_api_btn' }, 'tegatai_sudo_api', 'tegatai_api_sudo_nonce', 'secret');
    });
})();
