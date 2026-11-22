<?php
if ( ! defined( 'ABSPATH' ) ) { exit; }
// phpcs:disable WordPress.Security.NonceVerification -- Public forms (login, comments) have no logged-in user; the captcha token is the protection

/**
 * Captcha providers for login and comments: Cloudflare Turnstile or Google reCAPTCHA (v2 checkbox / v3 score).
 *
 * Only one provider is active at a time. Switching reCAPTCHA on switches Turnstile off and the other
 * way round (see Tegatai_Admin::ajax_toggle_option). If both flags are set anyway (old settings,
 * config import), reCAPTCHA wins.
 */
class Tegatai_Captcha {

    const RECAPTCHA_API    = 'https://www.google.com/recaptcha/api.js';
    const RECAPTCHA_VERIFY = 'https://www.google.com/recaptcha/api/siteverify';

    /** Active provider: 'recaptcha', 'turnstile' or '' (none). */
    public static function provider($ops = null) {
        if (!is_array($ops)) $ops = tegatai_get_setting('tegatai_options');
        if (!is_array($ops)) return '';
        if (!empty($ops['enable_recaptcha'])) return 'recaptcha';
        if (!empty($ops['enable_turnstile'])) return 'turnstile';
        return '';
    }

    public static function label($provider) {
        return $provider === 'recaptcha' ? 'reCAPTCHA' : 'Turnstile';
    }

    /** 'v2' (checkbox) or 'v3' (invisible, score based). */
    public static function recaptcha_version($ops) {
        return (is_array($ops) && ($ops['recaptcha_version'] ?? '') === 'v3') ? 'v3' : 'v2';
    }

    /** Minimum v3 score (0.1 - 0.9, default 0.5). */
    public static function recaptcha_threshold($ops) {
        $t = (is_array($ops) && isset($ops['recaptcha_threshold']) && is_numeric($ops['recaptcha_threshold'])) ? (float) $ops['recaptcha_threshold'] : 0.5;
        return max(0.1, min(0.9, $t));
    }

    /** Is the provider usable (site key and secret key set)? */
    public static function is_configured($provider, $ops) {
        if ($provider === 'recaptcha') return !empty($ops['recaptcha_site_key']) && tegatai_secret('TEGATAI_RECAPTCHA_SECRET') !== '';
        if ($provider === 'turnstile') return !empty($ops['turnstile_site_key']) && tegatai_secret('TEGATAI_TURNSTILE_SECRET') !== '';
        return false;
    }

    // --- reCAPTCHA: script and field ---

    private static function recaptcha_script_url($ops) {
        if (self::recaptcha_version($ops) === 'v3') {
            return add_query_arg('render', rawurlencode((string) $ops['recaptcha_site_key']), self::RECAPTCHA_API);
        }
        return self::RECAPTCHA_API;
    }

    /** wp-login.php: enqueued in login_enqueue_scripts (async). */
    public static function recaptcha_login_script() {
        $ops = tegatai_get_setting('tegatai_options');
        if (empty($ops['recaptcha_site_key'])) return;
        // reCAPTCHA can only be loaded from Google (service script, no self-hosting possible)
        wp_enqueue_script('tegatai-recaptcha', self::recaptcha_script_url($ops), [], null, ['in_footer' => false, 'strategy' => 'async']); // phpcs:ignore WordPress.WP.EnqueuedResourceParameters.MissingVersion, PluginCheck.CodeAnalysis.EnqueuedResourceOffloading.OffloadedContent -- external service script (reCAPTCHA cannot be self-hosted)
    }

    /** Front end (comment forms): enqueued on single posts and pages only. */
    public static function recaptcha_enqueue_script() {
        if (!(is_single() || is_page())) return;
        $ops = tegatai_get_setting('tegatai_options');
        if (empty($ops['recaptcha_site_key'])) return;
        // reCAPTCHA can only be loaded from Google (no self-hosting possible)
        wp_enqueue_script('tegatai-recaptcha', self::recaptcha_script_url($ops), [], null, ['in_footer' => true, 'strategy' => 'defer']); // phpcs:ignore PluginCheck.CodeAnalysis.EnqueuedResourceOffloading.OffloadedContent, WordPress.WP.EnqueuedResourceParameters.MissingVersion
    }

    /**
     * Renders the reCAPTCHA field inside a form.
     * v2: the visible checkbox widget. v3: a hidden field that is filled with a fresh token on submit
     * (v3 tokens expire after two minutes, so it is requested at the last moment).
     */
    public static function recaptcha_field($action, $style = '') {
        $ops = tegatai_get_setting('tegatai_options');
        if (empty($ops['recaptcha_site_key'])) return;
        $key = (string) $ops['recaptcha_site_key'];

        if (self::recaptcha_version($ops) === 'v2') {
            echo '<div class="g-recaptcha" data-sitekey="' . esc_attr($key) . '" style="' . esc_attr($style) . '"></div>';
            return;
        }

        echo '<input type="hidden" name="g-recaptcha-response" class="teg-recaptcha-v3" value="">';
        $js = '(function(){var s=document.currentScript,f=s&&s.closest("form");if(!f)return;'
            . 'var i=f.querySelector("input.teg-recaptcha-v3"),busy=false;'
            . 'f.addEventListener("submit",function(e){if(i.value)return;e.preventDefault();if(busy)return;busy=true;'
            . 'if(typeof grecaptcha==="undefined"){busy=false;f.submit();return;}'
            . 'grecaptcha.ready(function(){grecaptcha.execute(' . wp_json_encode($key) . ',{action:' . wp_json_encode($action) . '}).then(function(t){i.value=t;'
            . 'if(f.requestSubmit)f.requestSubmit();else f.submit();},function(){busy=false;f.submit();});});});})();';
        wp_print_inline_script_tag($js);
    }

    // --- Verification ---

    /** Token of the active provider from the POST data. */
    public static function token_from_post($provider) {
        $field = $provider === 'recaptcha' ? 'g-recaptcha-response' : 'cf-turnstile-response';
        return isset($_POST[$field]) && is_string($_POST[$field]) ? wp_unslash($_POST[$field]) : ''; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- opaque token, only sent to the provider
    }

    /**
     * Checks the token of the active provider.
     * @return array{ok: bool, reason: string, detail: string} same shape as Tegatai_LoginGuard::turnstile_check()
     */
    public static function check($provider, $ops, $action) {
        $token = self::token_from_post($provider);
        if ($provider === 'recaptcha') return self::recaptcha_check($ops, $token, $action);
        return Tegatai_LoginGuard::turnstile_check(tegatai_secret('TEGATAI_TURNSTILE_SECRET'), $token);
    }

    /**
     * Checks a reCAPTCHA token with Google.
     *
     * reason: '' (ok) | 'missing' (no token: widget not loaded or not solved)
     *         | 'rejected' (Google refused the token/secret, v3 score too low or wrong action)
     *         | 'unreachable' (no usable answer from Google).
     */
    public static function recaptcha_check($ops, $token, $action) {
        $token = is_string($token) ? trim($token) : '';
        if ($token === '') {
            return ['ok' => false, 'reason' => 'missing', 'detail' => 'no token in the form (widget not loaded or not solved)'];
        }

        // Server-side token check against the reCAPTCHA API (not a loaded resource)
        $verify = wp_remote_post(self::RECAPTCHA_VERIFY, // phpcs:ignore PluginCheck.CodeAnalysis.Offloading.OffloadedContent
            ['timeout' => 10, 'body' => ['secret' => tegatai_secret('TEGATAI_RECAPTCHA_SECRET'), 'response' => $token]]);
        if (is_wp_error($verify)) {
            return ['ok' => false, 'reason' => 'unreachable', 'detail' => $verify->get_error_message()];
        }

        $body = json_decode(wp_remote_retrieve_body($verify), true);
        if (!is_array($body)) {
            return ['ok' => false, 'reason' => 'unreachable', 'detail' => 'HTTP ' . (int) wp_remote_retrieve_response_code($verify) . ', no JSON answer'];
        }
        if (empty($body['success'])) {
            $codes = isset($body['error-codes']) && is_array($body['error-codes']) ? array_map('sanitize_key', $body['error-codes']) : [];
            return ['ok' => false, 'reason' => 'rejected', 'detail' => $codes ? implode(', ', $codes) : 'no error code'];
        }

        if (self::recaptcha_version($ops) === 'v3') {
            // A v2 key answers without score: treat that as a configuration error, not as a pass
            if (!isset($body['score'])) {
                return ['ok' => false, 'reason' => 'rejected', 'detail' => 'no score in the answer (is the site key a v3 key?)'];
            }
            $score = (float) $body['score'];
            $min   = self::recaptcha_threshold($ops);
            if ($score < $min) {
                return ['ok' => false, 'reason' => 'rejected', 'detail' => sprintf('score %.1f below %.1f', $score, $min)];
            }
            if (isset($body['action']) && $body['action'] !== $action) {
                return ['ok' => false, 'reason' => 'rejected', 'detail' => 'action ' . sanitize_key((string) $body['action']) . ' instead of ' . $action];
            }
        }
        return ['ok' => true, 'reason' => '', 'detail' => ''];
    }
}
