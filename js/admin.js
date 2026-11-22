/* Tegatai Secure - main admin screen. Data and texts come from TegataiAdmin (wp_localize_script). */
(function () {
    'use strict';
    var cfg = window.TegataiAdmin || { i18n: {} };
    var t = function (key) { return (cfg.i18n && cfg.i18n[key]) || key; };

    function showToast(msg) {
        var x = document.getElementById('teg-toast');
        if (!x) return;
        x.innerText = msg;
        x.className = 'show';
        setTimeout(function () { x.className = x.className.replace('show', ''); }, 2000);
    }

    // On/off switches (AJAX, saved immediately)
    window.tegToggle = function (key, elem) {
        var val = elem.checked ? '1' : '0';
        var data = new FormData();
        data.append('action', 'tegatai_toggle_option');
        data.append('nonce', cfg.ajaxNonce);
        data.append('key', key);
        data.append('val', val);
        fetch(window.ajaxurl, { method: 'POST', body: data, credentials: 'same-origin' })
            .then(function (res) { return res.json(); })
            .then(function (res) {
                if (res.success) {
                    showToast(t('saved'));
                    ((res.data && res.data.switched_off) || []).forEach(function (k) {
                        document.querySelectorAll('input.teg-toggle-checkbox[data-teg-key="' + k + '"]').forEach(function (c) { c.checked = false; });
                    });
                } else {
                    alert(t('error'));
                    elem.checked = !elem.checked;
                }
            });
    };

    // Small settings forms (AJAX)
    window.tegSaveForm = function (form, event) {
        event.preventDefault();
        var btn = form.querySelector('input[type="submit"]');
        var old = btn.value;
        btn.value = '...';
        btn.disabled = true;
        var data = new FormData();
        data.append('action', 'tegatai_save_form');
        data.append('nonce', cfg.ajaxNonce);
        data.append('form_data', new URLSearchParams(new FormData(form)).toString());
        fetch(window.ajaxurl, { method: 'POST', body: data, credentials: 'same-origin' })
            .then(function (res) { return res.json(); })
            .then(function (res) {
                btn.value = old;
                btn.disabled = false;
                if (res.success) showToast(t('dataSaved')); else alert(t('error'));
            });
    };

    document.addEventListener('DOMContentLoaded', function () {
        var $ = window.jQuery;

        // Running malware scan: continue with the next chunk
        var next = document.querySelector('[data-tegatai-continue]');
        if (next) {
            setTimeout(function () { window.location.href = next.getAttribute('data-tegatai-continue'); }, 1500);
        }

        // Confirmation for buttons/links with data-tegatai-confirm
        document.querySelectorAll('[data-tegatai-confirm]').forEach(function (el) {
            el.addEventListener('click', function (e) {
                if (!window.confirm(el.getAttribute('data-tegatai-confirm'))) e.preventDefault();
            });
        });

        if (!$) return;

        // Deep clean
        $('#teg-run-clean').on('click', function (e) {
            e.preventDefault();
            var btn = $(this);
            if (!window.confirm(t('cleanConfirm'))) return;
            var label = btn.html();
            btn.prop('disabled', true).text(t('cleaning'));
            $('#teg-clean-results').slideUp();
            $.post(window.ajaxurl, { action: 'tegatai_deep_clean', _ajax_nonce: cfg.adminNonce }, function (r) {
                btn.prop('disabled', false).html(label);
                if (r.success) {
                    var box = $('#teg-clean-results').empty();
                    $('<strong>').text(t('cleanDone')).appendTo(box);
                    var ul = $('<ul>').css({ marginTop: '6px', marginBottom: 0 }).appendTo(box);
                    $.each(r.data.stats, function (i, stat) { $('<li>').text(stat).appendTo(ul); });
                    box.slideDown();
                } else {
                    alert(t('cleanError'));
                }
            });
        });

        // Settings import
        $('#teg-run-import').on('click', function (e) {
            e.preventDefault();
            var fileInput = document.getElementById('teg-import-file');
            if (!fileInput || fileInput.files.length === 0) { alert(t('importSelect')); return; }
            if (!window.confirm(t('importConfirm'))) return;
            var btn = $(this);
            var label = btn.html();
            btn.prop('disabled', true).text(t('importing'));
            var reader = new FileReader();
            reader.onload = function (ev) {
                $.post(window.ajaxurl, { action: 'tegatai_import_config', json: ev.target.result, _ajax_nonce: cfg.adminNonce }, function (r) {
                    if (r.success) {
                        alert(t('importDone'));
                        window.location.reload();
                    } else {
                        alert(t('importError') + ((r.data && r.data.msg) || 'Error'));
                        btn.prop('disabled', false).html(label);
                    }
                });
            };
            reader.readAsText(fileInput.files[0]);
        });

        // WP-Cron list: delete an event
        $('.teg-delete-cron').on('click', function (e) {
            e.preventDefault();
            if (!window.confirm(t('cronConfirm'))) return;
            var btn = $(this);
            btn.text(t('deleting'));
            $.post(window.ajaxurl, { action: 'tegatai_delete_cron', hook: btn.data('hook'), _ajax_nonce: cfg.adminNonce }, function (r) {
                if (r.success) { btn.closest('tr').fadeOut(); }
                else { alert(t('error') + ': ' + ((r.data && r.data.msg) || '')); btn.text(t('delete')); }
            });
        });
    });
})();
