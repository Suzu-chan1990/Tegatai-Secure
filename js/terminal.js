/* Tegatai Secure - live terminal (log stream). Data from TegataiTerminal (wp_localize_script). */
(function () {
    'use strict';
    var cfg = window.TegataiTerminal || {};

    document.addEventListener('DOMContentLoaded', function () {
        var output = document.getElementById('terminal-output');
        var status = document.getElementById('status');
        var btnPause = document.getElementById('btn-pause');
        if (!output || !status || !btnPause) return;
        var isPaused = false;

        function setStatus(text, color) { status.innerText = text; status.style.color = color; }

        function fetchLogs() {
            if (isPaused) return;
            setStatus('[ FETCHING... ]', '#fbbf24');
            var fd = new FormData();
            fd.append('action', 'tegatai_terminal_fetch');
            fd.append('limit', '100');
            fd.append('security', cfg.nonce);
            fetch(cfg.ajaxUrl, { method: 'POST', body: fd, credentials: 'same-origin' })
                .then(function (res) { return res.status === 429 ? null : res.text(); })
                .then(function (data) {
                    if (isPaused) return; // paused while the request was running
                    if (data !== null) output.innerHTML = data; // server output is escaped HTML rows
                    setStatus('[ IDLE ]', '#34d399');
                })
                .catch(function () { setStatus('[ ERROR ]', '#ef4444'); });
        }

        function togglePause() {
            isPaused = !isPaused;
            if (isPaused) {
                setStatus('[ PAUSED ]', '#ef4444');
                btnPause.innerText = 'Resume (P)';
                btnPause.style.color = '#34d399';
                btnPause.style.borderColor = '#34d399';
            } else {
                status.innerText = '[ RESUMED ]';
                btnPause.innerText = 'Pause (P)';
                btnPause.style.color = '#cbd5e1';
                btnPause.style.borderColor = '#475569';
                fetchLogs();
            }
        }

        btnPause.addEventListener('click', function (e) { e.preventDefault(); togglePause(); });
        setTimeout(fetchLogs, 500);
        setInterval(fetchLogs, 5000);

        document.addEventListener('keydown', function (e) {
            if (e.target.tagName === 'INPUT' || e.target.tagName === 'TEXTAREA') return;
            if (e.key === 'r' || e.key === 'R') fetchLogs();
            if (e.key === 'p' || e.key === 'P') togglePause();
            if (e.key === 'c' || e.key === 'C') {
                output.innerHTML = '<div class="log-row info">[SYS] Console cleared. Waiting for new events...</div>';
            }
            if (e.key === 'Escape') window.location.href = cfg.backUrl;
        });
    });
})();
