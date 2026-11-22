/* Tegatai Secure - anti-spam: time from page load to form submit (checked on the server). */
(function () {
    'use strict';
    document.addEventListener('DOMContentLoaded', function () {
        var start = Date.now();
        document.querySelectorAll('form').forEach(function (form) {
            form.addEventListener('submit', function () {
                var input = form.querySelector('input[name="tegatai_js_time"]');
                if (input) input.value = Date.now() - start;
            });
        });
    });
})();
