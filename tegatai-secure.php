<?php


/* TEGATAI_I18N_DE_EN_V1 applied 2026-02-26 22:09:36 */
add_action('plugins_loaded', function () {
    load_plugin_textdomain('tegatai-secure', false, dirname(plugin_basename(__FILE__)) . '/languages');
});
/*
Plugin Name: Tegatai Security
Plugin URI: https://vtubes.tokyo
Description: Tegatai Security Suite - Custom Edition. Update: Traffic Inspector & Database Logging.
Version: 1.0.0 (Gold Master)
Author: すずちゃん
License: GPL2
*/

if ( ! defined( 'ABSPATH' ) ) { exit; }

define( 'TEGATAI_VERSION', '2.0.0' );
define( 'TEGATAI_PATH', plugin_dir_path( __FILE__ ) );
require_once TEGATAI_PATH . 'includes/honeypot.php';
require_once TEGATAI_PATH . 'includes/perm_monitor.php';
require_once TEGATAI_PATH . 'includes/uploads_monitor.php';
require_once TEGATAI_PATH . 'includes/cron_monitor.php';
require_once TEGATAI_PATH . 'includes/option_scanner.php';
require_once TEGATAI_PATH . 'includes/core_integrity.php';
require_once TEGATAI_PATH . 'includes/timeline.php';
require_once TEGATAI_PATH . 'includes/quarantine.php';
require_once TEGATAI_PATH . 'includes/cron.php';
require_once TEGATAI_PATH . 'includes/malware_scanner.php';
require_once TEGATAI_PATH . 'includes/fim.php';
require_once TEGATAI_PATH . 'includes/dbscan.php';
define( 'TEGATAI_URL', plugin_dir_url( __FILE__ ) );

// Module laden
require_once TEGATAI_PATH . 'includes/logger.php'; // UPDATED v0.28
require_once TEGATAI_PATH . 'includes/firewall.php';
require_once TEGATAI_PATH . 'includes/hardening.php';
require_once TEGATAI_PATH . 'includes/headers.php';
require_once TEGATAI_PATH . 'includes/login.php';
require_once TEGATAI_PATH . 'includes/server.php';
require_once TEGATAI_PATH . 'includes/spam.php';
require_once TEGATAI_PATH . 'includes/sessions.php';
require_once TEGATAI_PATH . 'includes/session_guard.php';
require_once TEGATAI_PATH . 'includes/user_history.php';
if (file_exists(TEGATAI_PATH . 'includes/backup.php')) {
    if (file_exists(TEGATAI_PATH . 'includes/backup.php')) {
    require_once TEGATAI_PATH . 'includes/backup.php';
}

}

require_once TEGATAI_PATH . 'includes/extras.php';
require_once TEGATAI_PATH . 'includes/twofa.php';
require_once TEGATAI_PATH . 'includes/scanner.php';
require_once TEGATAI_PATH . 'includes/admin.php'; // UPDATED v0.28

class Tegatai_Security_Core {
    public function __construct() {
        // Auto-Update DB Check
        if (is_admin()) {
            $this->check_db_schema();
        }

        new Tegatai_Logger();
        new Tegatai_Firewall();
        new Tegatai_Hardening();
        new Tegatai_Headers();
        new Tegatai_LoginGuard();
        new Tegatai_Server();
        new Tegatai_Spam();
        new Tegatai_SessionManager();
        new Tegatai_SessionGuard();
        new Tegatai_UserHistory();
        if (class_exists('Tegatai_Backup')) {
    if (class_exists('Tegatai_Backup')) {
    new Tegatai_Backup();
}

}

        new Tegatai_Extras();
        new Tegatai_TwoFactor();
        new Tegatai_Scanner();
        new Tegatai_Admin();
        add_action('tegatai_daily_maintenance', ['Tegatai_Logger', 'prune_logs']);

        register_activation_hook(__FILE__, array($this, 'activate'));
        register_deactivation_hook(__FILE__, array($this, 'deactivate'));
    }

    public function activate() {
        $this->install_db(); // DB Tabelle erstellen
        
        $upload = wp_upload_dir();
        
        // Logs Dir (Fallback)
        $log_dir = $upload['basedir'] . '/tegatai-logs';
        if (!file_exists($log_dir)) mkdir($log_dir, 0755, true);
        if (!file_exists($log_dir . '/.htaccess')) file_put_contents($log_dir . '/.htaccess', "Order Deny,Allow\nDeny from all
Require all denied");
        if (!file_exists($log_dir . '/index.php')) file_put_contents($log_dir . '/index.php', '<?php // Silence');

        // Backups
        $back_dir = $upload['basedir'] . '/tegatai-backups';
        if (!file_exists($back_dir)) mkdir($back_dir, 0755, true);
        if (!file_exists($back_dir . '/.htaccess')) file_put_contents($back_dir . '/.htaccess', "Order Deny,Allow\nDeny from all
Require all denied");
        if (!file_exists($back_dir . '/index.php')) file_put_contents($back_dir . '/index.php', '<?php // Silence');
        
        if (!get_option('tegatai_options')) update_option('tegatai_options', []);
        
        if (!wp_next_scheduled('tegatai_daily_backup_event')) {
            wp_schedule_event(time(), 'daily', 'tegatai_daily_backup_event');
        }

        if (!wp_next_scheduled('tegatai_daily_maintenance')) {
            wp_schedule_event(time(), 'daily', 'tegatai_daily_maintenance');
        }

        flush_rewrite_rules();
    }

    public function check_db_schema() {
        if (get_option('tegatai_db_version') !== '1.0') {
            $this->install_db();
        }
    }

    private function install_db() {
        global $wpdb;
        $table_name = $wpdb->prefix . 'tegatai_logs';
        $charset_collate = $wpdb->get_charset_collate();

        $sql = "CREATE TABLE $table_name (
            id mediumint(9) NOT NULL AUTO_INCREMENT,
            time datetime DEFAULT '0000-00-00 00:00:00' NOT NULL,
            type varchar(50) NOT NULL,
            ip varchar(45) NOT NULL,
            message text NOT NULL,
            user_agent text NOT NULL,
            PRIMARY KEY  (id)
        ) $charset_collate;";

        require_once(ABSPATH . 'wp-admin/includes/upgrade.php');
        dbDelta($sql);

        update_option('tegatai_db_version', '1.0');
    }

    public function deactivate() {
        if (class_exists('Tegatai_Server')) {
            Tegatai_Server::remove_rules();
        }
        wp_clear_scheduled_hook('tegatai_daily_backup_event');
        flush_rewrite_rules();
    }
}

add_action( 'plugins_loaded', function() {
    new Tegatai_Security_Core();
});

add_action('plugins_loaded', ['Tegatai_Cron', 'init']);

register_activation_hook(__FILE__, ['Tegatai_Cron', 'activate']);
register_deactivation_hook(__FILE__, ['Tegatai_Cron', 'deactivate']);

add_action('plugins_loaded', ['Tegatai_Timeline', 'init']);
add_action('plugins_loaded', ['Tegatai_Honeypot', 'init']);
add_action('plugins_loaded', ['Tegatai_Cron_Monitor', 'init']);
add_action('plugins_loaded', ['Tegatai_Uploads_Monitor', 'init']);
