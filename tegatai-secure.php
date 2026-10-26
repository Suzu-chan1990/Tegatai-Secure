<?php
/*
Plugin Name: Tegatai Security
Plugin URI: https://github.com/Suzu-chan1990/Tegatai-Secure
Description: Tegatai Security Suite - Custom Edition. Update: Traffic Inspector & Database Logging.
Version: 1.4.2
Author: すずちゃん
License: GPL2
Text Domain: tegatai-secure
Domain Path: /languages
*/

if ( ! defined( 'ABSPATH' ) ) { exit; }

// =================================================================
// HIGH-SPEED DATENBANK & RAM CACHE FÜR TEGATAI OPTIONS
// =================================================================
const TEGATAI_SETTINGS_DB_VERSION = '1';

/**
 * Whether the settings table exists. Decided once via an autoloaded option instead of
 * a SHOW TABLES query on every request. A missing table (e.g. after an update without
 * activation) is created on the fly; failures back off for an hour.
 */
function tegatai_settings_table_ready() {
    static $ready = null;
    if ( $ready !== null ) return $ready;

    if ( get_option( 'tegatai_settings_db_version' ) === TEGATAI_SETTINGS_DB_VERSION ) {
        return $ready = true;
    }
    if ( get_transient( 'tegatai_settings_db_failed' ) ) {
        return $ready = false;
    }
    tegatai_install_db();
    $ready = get_option( 'tegatai_settings_db_version' ) === TEGATAI_SETTINGS_DB_VERSION;
    if ( ! $ready ) {
        set_transient( 'tegatai_settings_db_failed', 1, HOUR_IN_SECONDS );
    }
    return $ready;
}

// Values are stored as JSON. Legacy serialized values are read without allowing objects,
// so a manipulated row cannot trigger PHP object injection.
function tegatai_encode_setting( $value ) {
    return 'json:' . wp_json_encode( $value );
}

function tegatai_decode_setting( $raw ) {
    if ( is_string( $raw ) && strncmp( $raw, 'json:', 5 ) === 0 ) {
        return json_decode( substr( $raw, 5 ), true );
    }
    if ( is_serialized( $raw ) ) {
        return @unserialize( trim( $raw ), [ 'allowed_classes' => false ] );
    }
    return $raw;
}

// Per-request copy of all settings. Kept in a global (not a function static) so that
// tegatai_update_setting() can refresh it; otherwise code running after a save in the
// same request (e.g. Tegatai_Server::force_update()) would still see the old values.
$GLOBALS['tegatai_settings_cache'] = null;

function tegatai_get_setting( $key, $default = false ) {
    $tegatai_cache = &$GLOBALS['tegatai_settings_cache'];
    
    if ( $tegatai_cache === null ) {
        $cached = wp_cache_get( 'tegatai_core_settings', 'tegatai' );
        if ( $cached !== false ) {
            $tegatai_cache = $cached;
        } else {
            global $wpdb;
            $table_name = $wpdb->prefix . 'tegatai_settings';
            
            if ( ! tegatai_settings_table_ready() ) {
                return get_option( $key, $default );
            }
            
            $results = $wpdb->get_results( "SELECT setting_key, setting_value FROM $table_name" );
            $tegatai_cache = [];
            foreach ( (array) $results as $row ) {
                $tegatai_cache[ $row->setting_key ] = tegatai_decode_setting( $row->setting_value );
            }
            wp_cache_set( 'tegatai_core_settings', $tegatai_cache, 'tegatai', 3600 );
        }
    }
    
    if ( isset( $tegatai_cache[ $key ] ) ) {
        return $tegatai_cache[ $key ];
    }
    
    $old_value = get_option( $key );
    if ( $old_value !== false ) {
        tegatai_update_setting( $key, $old_value );
        $tegatai_cache[ $key ] = $old_value;
        return $old_value;
    }
    
    return $default;
}

function tegatai_update_setting( $key, $value ) {
    global $wpdb;
    $table_name = $wpdb->prefix . 'tegatai_settings';
    
    if ( ! tegatai_settings_table_ready() ) {
        return update_option( $key, $value );
    }
    
    $wpdb->replace( 
        $table_name, 
        [ 'setting_key' => $key, 'setting_value' => tegatai_encode_setting( $value ) ], 
        [ '%s', '%s' ] 
    );
    
    wp_cache_delete( 'tegatai_core_settings', 'tegatai' );
    if ( is_array( $GLOBALS['tegatai_settings_cache'] ) ) {
        $GLOBALS['tegatai_settings_cache'][ $key ] = $value;
    }
    return true;
}

function tegatai_install_db() {
    global $wpdb;
    $table_name = $wpdb->prefix . 'tegatai_settings';
    $charset_collate = $wpdb->get_charset_collate();
    
    $sql = "CREATE TABLE $table_name (
        id mediumint(9) NOT NULL AUTO_INCREMENT,
        setting_key varchar(100) NOT NULL,
        setting_value longtext NOT NULL,
        PRIMARY KEY  (id),
        UNIQUE KEY setting_key (setting_key)
    ) $charset_collate;";
    
    require_once( ABSPATH . 'wp-admin/includes/upgrade.php' );
    dbDelta( $sql );

    if ( $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $table_name ) ) === $table_name ) {
        update_option( 'tegatai_settings_db_version', TEGATAI_SETTINGS_DB_VERSION, true );
        delete_transient( 'tegatai_settings_db_failed' );
    }
}
register_activation_hook( __FILE__, 'tegatai_install_db' );


define( 'TEGATAI_VERSION', '1.4.2' );
define( 'TEGATAI_FILE', __FILE__ );
define( 'TEGATAI_PATH', plugin_dir_path( __FILE__ ) );

add_action('init', function () {
    load_plugin_textdomain('tegatai-secure', false, dirname(plugin_basename(TEGATAI_FILE)) . '/languages');
}, 0);

/**
 * Locks a plugin data directory (logs, backups) against web access on Apache/LiteSpeed/IIS.
 * nginx ignores these files, see the deny rules generated by Tegatai_Server.
 */
function tegatai_protect_directory( $dir ) {
    $dir = trailingslashit( $dir );
    if ( ! is_dir( $dir ) && ! wp_mkdir_p( $dir ) ) {
        return false;
    }
    // Apache 2.4 (mod_authz_core) and 2.2 / mod_access_compat. A bare "Order" directive
    // causes a 500 on Apache 2.4 without mod_access_compat.
    $htaccess = "<IfModule mod_authz_core.c>\nRequire all denied\n</IfModule>\n<IfModule !mod_authz_core.c>\nOrder Deny,Allow\nDeny from all\n</IfModule>\n";
    if ( ! file_exists( $dir . '.htaccess' ) || file_get_contents( $dir . '.htaccess' ) !== $htaccess ) {
        @file_put_contents( $dir . '.htaccess', $htaccess );
    }
    if ( ! file_exists( $dir . 'index.php' ) ) {
        @file_put_contents( $dir . 'index.php', "<?php\n// Silence is golden." );
    }
    if ( ! file_exists( $dir . 'web.config' ) ) {
        @file_put_contents( $dir . 'web.config', '<?xml version="1.0" encoding="UTF-8"?><configuration><system.webServer><authorization><deny users="*" /></authorization></system.webServer></configuration>' );
    }
    return true;
}

/**
 * Atomically claims a one-time key (replay protection for signed requests).
 * Returns true only for the first caller within $ttl seconds, also under concurrent requests.
 */
function tegatai_claim_nonce( $key, $ttl ) {
    $ttl = max( 1, (int) $ttl );
    if ( function_exists( 'apcu_add' ) && function_exists( 'apcu_enabled' ) && apcu_enabled() ) {
        return apcu_add( 'tegatai_' . $key, 1, $ttl );
    }
    if ( function_exists( 'wp_using_ext_object_cache' ) && wp_using_ext_object_cache() ) {
        return wp_cache_add( $key, 1, 'tegatai_nonce', $ttl );
    }

    // DB fallback: INSERT IGNORE on the unique option_name is atomic. The rows use the
    // transient naming scheme, so core's delete_expired_transients() cleans them up.
    global $wpdb;
    $now     = time();
    $timeout = '_transient_timeout_' . $key;
    $claimed = $wpdb->query( $wpdb->prepare(
        "INSERT IGNORE INTO {$wpdb->options} (option_name, option_value, autoload) VALUES (%s, %s, 'off')",
        $timeout, (string) ( $now + $ttl )
    ) );
    if ( ! $claimed ) {
        // Row exists: take it over only if it has expired (single atomic UPDATE).
        $claimed = $wpdb->query( $wpdb->prepare(
            "UPDATE {$wpdb->options} SET option_value = %s WHERE option_name = %s AND CAST(option_value AS UNSIGNED) < %d",
            (string) ( $now + $ttl ), $timeout, $now
        ) );
    }
    if ( ! $claimed ) {
        return false;
    }
    $wpdb->query( $wpdb->prepare(
        "INSERT IGNORE INTO {$wpdb->options} (option_name, option_value, autoload) VALUES (%s, '1', 'off')",
        '_transient_' . $key
    ) );
    return true;
}
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
require_once TEGATAI_PATH . 'includes/logger.php';
require_once TEGATAI_PATH . 'includes/bans.php';
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
    require_once TEGATAI_PATH . 'includes/backup.php';
}

require_once TEGATAI_PATH . 'includes/extras.php';
require_once TEGATAI_PATH . 'includes/twofa.php';
require_once TEGATAI_PATH . 'includes/scanner.php';
require_once TEGATAI_PATH . 'includes/admin.php';
require_once TEGATAI_PATH . 'includes/terminal.php';
require_once TEGATAI_PATH . 'includes/api_guard.php';
require_once TEGATAI_PATH . 'includes/hive.php';

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
            new Tegatai_Backup();
        }

        new Tegatai_Extras();
        new Tegatai_TwoFactor();
        new Tegatai_Scanner();
        new Tegatai_Admin();
        new Tegatai_Terminal();
        new Tegatai_API_Guard();
        new Tegatai_Hive();
        add_action('tegatai_daily_maintenance', ['Tegatai_Logger', 'prune_logs']);

        // Existing installs never ran activate() (the hook used to be registered too late),
        // so directories and cron events are verified and repaired here as well.
        if (is_admin() || wp_doing_cron()) {
            add_action('init', [__CLASS__, 'ensure_environment'], 20);
        }
    }

    // Registered at top level below; runs in the activation request.
    public static function activate() {
        self::install_db();
        if (!tegatai_get_setting('tegatai_options')) tegatai_update_setting('tegatai_options', []);
        delete_option('tegatai_env_version');
        self::ensure_environment();
        flush_rewrite_rules();
    }

    const ENV_VERSION = '3';

    public static function ensure_environment() {
        if (get_option('tegatai_env_version') !== self::ENV_VERSION) {
            $upload = wp_upload_dir();
            tegatai_protect_directory($upload['basedir'] . '/tegatai-logs');
            tegatai_protect_directory($upload['basedir'] . '/tegatai-backups');
            // Leftover credentials of the never-implemented FTP feature.
            delete_option('tegatai_ftp_settings');
            // Bans now live in Tegatai_Bans. Old per-IP "permanent" transients from the admin
            // honeypot were autoloaded on every request; old Hive bans are migrated.
            global $wpdb;
            $wpdb->query("DELETE FROM {$wpdb->options} WHERE option_name LIKE '\\_transient\\_teg\\_404\\_%' AND option_name NOT IN (SELECT * FROM (SELECT CONCAT('_transient_', SUBSTRING(option_name, 20)) FROM {$wpdb->options} WHERE option_name LIKE '\\_transient\\_timeout\\_teg\\_404\\_%') AS t)");
            $legacy = get_option('tegatai_hive_bans', []);
            if (is_array($legacy)) {
                foreach ($legacy as $ip => $b) {
                    $left = (int)($b['until'] ?? 0) - time();
                    if ($left > 0) Tegatai_Bans::add($ip, $left, $b['reason'] ?? '', 'hive:' . ($b['node'] ?? ''), $b['level'] ?? 'critical');
                }
            }
            delete_option('tegatai_hive_bans');
            // Regenerate existing server rules once with the fixed generators (URL paths, .well-known).
            $ht = ABSPATH . '.htaccess';
            $has_rules = (file_exists($ht) && strpos((string)@file_get_contents($ht), '# BEGIN Tegatai-Secure') !== false)
                || file_exists(ABSPATH . 'tegatai-nginx.conf') || file_exists($upload['basedir'] . '/tegatai-nginx.conf');
            if ($has_rules && class_exists('Tegatai_Server')) {
                Tegatai_Server::force_update();
            }
            update_option('tegatai_env_version', self::ENV_VERSION, false);
        }
        self::ensure_cron_events();
    }

    public static function ensure_cron_events() {
        if (!wp_next_scheduled('tegatai_daily_backup_event')) {
            wp_schedule_event(time() + HOUR_IN_SECONDS, 'daily', 'tegatai_daily_backup_event');
        }
        if (!wp_next_scheduled('tegatai_daily_maintenance')) {
            wp_schedule_event(time() + 2 * HOUR_IN_SECONDS, 'daily', 'tegatai_daily_maintenance');
        }
        if (class_exists('Tegatai_Cron')) {
            Tegatai_Cron::schedule_events();
        }
    }

    const DB_VERSION = '1.1';

    public function check_db_schema() {
        if (get_option('tegatai_db_version') !== self::DB_VERSION) {
            self::install_db();
        }
    }

    private static function install_db() {
        global $wpdb;
        $table_name = $wpdb->prefix . 'tegatai_logs';
        $charset_collate = $wpdb->get_charset_collate();

        $sql = "CREATE TABLE $table_name (
            id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
            time datetime NOT NULL,
            type varchar(50) NOT NULL,
            ip varchar(45) NOT NULL,
            message text NOT NULL,
            user_agent text NOT NULL,
            PRIMARY KEY  (id),
            KEY time (time)
        ) $charset_collate;";

        require_once(ABSPATH . 'wp-admin/includes/upgrade.php');
        dbDelta($sql);

        // dbDelta never removes column defaults; drop the legacy zero-date default explicitly.
        $wpdb->query("ALTER TABLE $table_name ALTER COLUMN `time` DROP DEFAULT");

        update_option('tegatai_db_version', self::DB_VERSION);
    }

    public static function deactivate() {
        if (class_exists('Tegatai_Server')) {
            Tegatai_Server::remove_rules();
        }
        wp_clear_scheduled_hook('tegatai_daily_backup_event');
        wp_clear_scheduled_hook('tegatai_daily_maintenance');
        wp_clear_scheduled_hook('tegatai_hive_retry_cron');
        wp_clear_scheduled_hook('tegatai_hive_flush');
        wp_unschedule_hook('tegatai_bg_scan_chunk');
        delete_option('tegatai_env_version');
        flush_rewrite_rules();
    }
}

add_action( 'plugins_loaded', function() {
    new Tegatai_Security_Core();
});

add_action('plugins_loaded', ['Tegatai_Cron', 'init']);

// Activation/deactivation hooks must be registered while the main file is included,
// not inside plugins_loaded, which has already fired during the activation request.
register_activation_hook(__FILE__, ['Tegatai_Security_Core', 'activate']);
register_deactivation_hook(__FILE__, ['Tegatai_Security_Core', 'deactivate']);
register_activation_hook(__FILE__, ['Tegatai_Cron', 'activate']);
register_deactivation_hook(__FILE__, ['Tegatai_Cron', 'deactivate']);

add_action('plugins_loaded', ['Tegatai_Timeline', 'init']);
add_action('plugins_loaded', ['Tegatai_Honeypot', 'init']);
add_action('plugins_loaded', ['Tegatai_Cron_Monitor', 'init']);
add_action('plugins_loaded', ['Tegatai_Uploads_Monitor', 'init']);

// --- GitHub Updater (Plugin Update Checker) ---
add_action('init', function () {
    // Nur im Admin wirklich nötig, aber init ist ok
    if ( ! is_admin() ) {
        return;
    }

    $puc_path = TEGATAI_PATH . 'lib/plugin-update-checker/plugin-update-checker.php';
    if ( ! file_exists($puc_path) ) {
        return; // Library fehlt
    }

    require_once $puc_path;

    // Build checker
    $updateChecker = \YahnisElsts\PluginUpdateChecker\v5\PucFactory::buildUpdateChecker(
        'https://github.com/Suzu-chan1990/Tegatai-Secure/',
        __FILE__,
        'tegatai-secure' // Plugin-Slug (sollte stabil sein)
    );

    // Wenn du Releases/Tags nutzt:
    $updateChecker->getVcsApi()->enableReleaseAssets();

    // Falls du (statt Releases) direkt den main-Branch “auslieferst”:
    // $updateChecker->setBranch('main');

    // Optional: falls dein Hauptplugin nicht im Repo-Root läge (bei dir liegt es im Root -> passt)
    // $updateChecker->setPluginFileName('tegatai-secure.php');
});
