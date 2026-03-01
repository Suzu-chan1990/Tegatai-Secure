<?php
if (!defined('ABSPATH')) { exit; }

class Tegatai_Honeypot {

    const FIELD = 'teg_hp_field';
    const OPT_ENABLED = 'teg_honeypot_enabled_v1';

    public static function init(): void {
        $en = get_option(self::OPT_ENABLED, null);
        if ($en === null) { update_option(self::OPT_ENABLED, 1, false); }

        add_action('login_form', [__CLASS__, 'render_field']);
        add_filter('authenticate', [__CLASS__, 'check_field'], 2, 3);
    }

    public static function render_field(): void {
        $en = (int)get_option(self::OPT_ENABLED, 1);
        if ($en !== 1) return;

        echo '<p style="position:absolute;left:-10000px;top:auto;width:1px;height:1px;overflow:hidden;">';
        echo '<label>' . esc_html__('Leave this field empty', 'tegatai-secure') . '</label>';
        echo '<input type="text" name="' . esc_attr(self::FIELD) . '" value="" autocomplete="off" tabindex="-1" />';
        echo '</p>';
    }

    public static function check_field($user, $username, $password) {
        $en = (int)get_option(self::OPT_ENABLED, 1);
        if ($en !== 1) return $user;

        $val = isset($_POST[self::FIELD]) ? (string)$_POST[self::FIELD] : '';
        if ($val !== '') {
            if (class_exists('Tegatai_Timeline')) {
                $ip = isset($_SERVER['REMOTE_ADDR']) ? (string)$_SERVER['REMOTE_ADDR'] : '';
                Tegatai_Timeline::add('honeypot', 'Login honeypot triggered from IP ' . $ip);
            }
            return new WP_Error('teg_hp', __('Login blocked (honeypot).', 'tegatai-secure'));
        }
        return $user;
    }
}
