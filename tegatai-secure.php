<?php
/*
 * Plugin Name: Tegatai Secure
 * Plugin URI: https://github.com/Suzu-chan1990/Tegatai-Secure
 * Description: Firewall, login protection with 2FA, anti-spam, scanners, server rules, encrypted database backups and IP ban sharing between your own sites.
 * Version: 2.2.8
 * Author: Saguya
 * License: GPLv2 or later
 * Text Domain: tegatai-secure
 * Domain Path: /languages
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 * Requires at least: 7.1
 * Requires PHP: 8.4
 * Update URI: https://github.com/Suzu-chan1990/Tegatai-Secure
*/

if ( ! defined( 'ABSPATH' ) ) { exit; }
// phpcs:disable WordPress.DB.DirectDatabaseQuery -- Tegatai uses its own tables (logs, settings) and live security data; queries are prepared and caching would serve stale data

// Allowed markup for hidden form fields (nonce fields, anti-spam fields) when output through wp_kses()
const TEGATAI_KSES_INPUT = [ 'input' => [ 'type' => true, 'id' => true, 'name' => true, 'value' => true ] ];

// =================================================================
// REQUEST DATA
// =================================================================

/**
 * A $_SERVER value as plain text (sanitize_text_field), for storing, logging and output.
 */
function tegatai_server( $key, $max = 1024 ) {
    if ( ! isset( $_SERVER[ $key ] ) || ! is_scalar( $_SERVER[ $key ] ) ) return '';
    return substr( sanitize_text_field( wp_unslash( (string) $_SERVER[ $key ] ) ), 0, $max );
}

/**
 * A $_SERVER value for pattern matching by the firewall (request URI, user agent).
 * sanitize_text_field() would remove percent-encoded octets and tags, i.e. exactly the parts an
 * attack is detected by. This keeps the characters but removes control characters and invalid
 * UTF-8 and limits the length. The value is never output or stored without tegatai_server().
 */
function tegatai_server_raw( $key, $max = 8192 ) {
    if ( ! isset( $_SERVER[ $key ] ) || ! is_scalar( $_SERVER[ $key ] ) ) return '';
    $v = wp_check_invalid_utf8( wp_unslash( (string) $_SERVER[ $key ] ) ); // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- sanitized right below (control characters, invalid UTF-8, length), see the function comment
    $v = preg_replace( '/[\x00-\x1F\x7F]/', '', $v );
    return substr( (string) $v, 0, $max );
}

// A $_SERVER value that must be an IP address ('' otherwise).
function tegatai_server_ip( $key ) {
    $v = isset( $_SERVER[ $key ] ) && is_scalar( $_SERVER[ $key ] ) ? trim( sanitize_text_field( wp_unslash( (string) $_SERVER[ $key ] ) ) ) : '';
    return filter_var( $v, FILTER_VALIDATE_IP ) ? $v : '';
}

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
            
            $results = $wpdb->get_results( $wpdb->prepare( "SELECT setting_key, setting_value FROM %i", $table_name ) );
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
        $ok = update_option( $key, $value );
        do_action( 'tegatai_setting_updated', $key, $value );
        return $ok;
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
    do_action( 'tegatai_setting_updated', $key, $value );
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

    if ( $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $wpdb->esc_like( $table_name ) ) ) === $table_name ) {
        update_option( 'tegatai_settings_db_version', TEGATAI_SETTINGS_DB_VERSION, true );
        delete_transient( 'tegatai_settings_db_failed' );
    }
}
register_activation_hook( __FILE__, 'tegatai_install_db' );


define( 'TEGATAI_VERSION', '2.2.8' );
define( 'TEGATAI_FILE', __FILE__ );
define( 'TEGATAI_PATH', plugin_dir_path( __FILE__ ) );
define( 'TEGATAI_URL', plugin_dir_url( __FILE__ ) );

// =================================================================
// GITHUB UPDATES (GitHub edition; the WordPress.org edition gets its updates from WordPress.org)
// =================================================================
add_action( 'init', 'tegatai_github_updater' );

/**
 * Checks GitHub releases of Suzu-chan1990/Tegatai-Secure for new versions (Plugin Update Checker 5.6).
 * Only in the admin, WP-Cron and WP-CLI, so normal page views never contact GitHub.
 */
function tegatai_github_updater() {
    // Build the checker only once: a second instance with the same slug is a fatal error in PUC.
    static $built = false;
    if ( $built ) {
        return;
    }
    if ( ! is_admin() && ! wp_doing_cron() && ! ( defined( 'WP_CLI' ) && WP_CLI ) ) {
        return;
    }
    $puc = TEGATAI_PATH . 'lib/plugin-update-checker/plugin-update-checker.php';
    if ( ! file_exists( $puc ) ) {
        return; // Library missing: the plugin keeps working, just without update notices.
    }
    require_once $puc;
    $built = true;

    $checker = \YahnisElsts\PluginUpdateChecker\v5\PucFactory::buildUpdateChecker(
        'https://github.com/Suzu-chan1990/Tegatai-Secure/',
        TEGATAI_FILE,
        'tegatai-secure'
    );
    // Use the ZIP attached to a GitHub release (falls back to the tag's source ZIP).
    $checker->getVcsApi()->enableReleaseAssets();
}

/**
 * Plugins directory and URL, derived from this plugin's own location (plugin_dir_path() /
 * plugin_dir_url() of the main file) instead of WordPress' internal constants.
 */
function tegatai_plugins_dir() {
    return untrailingslashit( dirname( TEGATAI_PATH ) );
}

function tegatai_plugins_url() {
    return untrailingslashit( dirname( TEGATAI_URL ) );
}

/**
 * Name of Tegatai's data folder in the uploads directory: "tegatai-secure", like the plugin.
 * Sites whose uploads folder is also the plugins folder would get the plugin folder itself,
 * which WordPress replaces on every update (and the deny rules would block the plugin's
 * assets); there the data folder is named "tegatai-secure-data".
 */
function tegatai_data_dir_name() {
    static $name = null;
    if ( $name !== null ) return $name;
    $name = 'tegatai-secure';
    $ud   = wp_upload_dir( null, false );
    $data = untrailingslashit( wp_normalize_path( trailingslashit( $ud['basedir'] ) . $name ) );
    $self = untrailingslashit( wp_normalize_path( TEGATAI_PATH ) );
    $real_data = is_dir( $data ) ? realpath( $data ) : false;
    $real_self = realpath( $self );
    if ( $data === $self || ( $real_data && $real_self && $real_data === $real_self ) ) {
        $name = 'tegatai-secure-data';
    }
    return $name;
}

/**
 * Tegatai's only folder in the uploads directory: uploads/tegatai-secure/ with the subfolders
 * logs, backups, server (nginx rules file) and geoip. Nothing else is written next to it.
 * The whole folder is protected against web access (tegatai_protect_directory(), server rules).
 */
function tegatai_data_dir( $sub = '' ) {
    $ud   = wp_upload_dir( null, false );
    $base = trailingslashit( $ud['basedir'] ) . tegatai_data_dir_name();
    return $sub === '' ? $base : $base . '/' . $sub;
}

// URL path of the data folder (e.g. /wp-content/uploads/tegatai-secure/), for messages.
function tegatai_data_dir_url_path() {
    $path = (string) wp_parse_url( wp_upload_dir( null, false )['baseurl'], PHP_URL_PATH );
    return trailingslashit( untrailingslashit( $path ) . '/' . tegatai_data_dir_name() );
}

// Folder for the nginx include file.
function tegatai_server_dir() {
    return tegatai_data_dir( 'server' );
}

/**
 * Path of a private data file (snapshots, file lists) in the logs folder. The name carries a
 * random suffix created once per site, so the files cannot be guessed even where the deny
 * rules do not apply.
 */
function tegatai_private_file( $name ) {
    $suffix = get_option( 'tegatai_file_suffix', '' );
    if ( ! is_string( $suffix ) || ! preg_match( '/^[a-f0-9]{16}$/', $suffix ) ) {
        $suffix = bin2hex( random_bytes( 8 ) );
        update_option( 'tegatai_file_suffix', $suffix, false );
    }
    $info = pathinfo( $name );
    return tegatai_data_dir( 'logs' ) . '/' . $info['filename'] . '-' . $suffix . ( isset( $info['extension'] ) ? '.' . $info['extension'] : '' );
}

/**
 * Secrets file outside the web root.
 *
 * Default location: one level above the WordPress directory, secrets/tegatai-secrets.php
 * (e.g. /var/www/example.com/htdocs -> /var/www/example.com/secrets/tegatai-secrets.php).
 * Another location can be set in wp-config.php with the path only:
 *   define('TEGATAI_SECRETS_FILE', '/path/outside/webroot/tegatai-secrets.php');
 *
 * The file returns an array, e.g.:
 *   <?php return ['TEGATAI_HIVE_SECRET' => '...', 'TEGATAI_API_SECRET' => '...'];
 *
 * Only the names below are accepted. A constant that is already defined (wp-config.php) is kept.
 */
function tegatai_secrets_file() {
    $file = defined( 'TEGATAI_SECRETS_FILE' ) ? (string) TEGATAI_SECRETS_FILE : dirname( rtrim( ABSPATH, '/\\' ) ) . '/secrets/tegatai-secrets.php';
    return $file;
}

// Names accepted from the secrets file (or as constants in wp-config.php).
function tegatai_secret_names() {
    return [
        'TEGATAI_API_SECRET', 'TEGATAI_HIVE_SECRET', 'TEGATAI_SUDO_PIN', 'TEGATAI_BACKUP_SECRET', 'TEGATAI_ABUSEIPDB_KEY',
        'TEGATAI_RECAPTCHA_SECRET', 'TEGATAI_TURNSTILE_SECRET', 'TEGATAI_ALERT_WEBHOOK',
    ];
}

/**
 * Reads the secrets file; returns the accepted, non-empty values (or [] when missing or invalid).
 * Tegatai only reads this file. It never creates or changes it: the administrator creates it
 * with the command shown in the Secrets tab (outside the web root, folder 0700, file 0600).
 */
function tegatai_read_secrets_file() {
    static $cache = null;
    if ( $cache !== null ) return $cache;
    $cache = [];
    $file = tegatai_secrets_file();
    if ( $file === '' || ! @is_file( $file ) || ! @is_readable( $file ) ) return $cache;
    $data = include $file;
    if ( ! is_array( $data ) ) return $cache;
    foreach ( tegatai_secret_names() as $name ) {
        if ( isset( $data[ $name ] ) && is_string( $data[ $name ] ) && $data[ $name ] !== '' ) $cache[ $name ] = $data[ $name ];
    }
    return $cache;
}

function tegatai_load_secrets() {
    static $loaded = null;
    if ( $loaded !== null ) return $loaded;
    $loaded = [];
    $data = tegatai_read_secrets_file();
    foreach ( tegatai_secret_names() as $name ) {
        if ( defined( $name ) || ! isset( $data[ $name ] ) ) continue;
        define( $name, $data[ $name ] ); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.VariableConstantNameFound -- names come from the fixed list above
        $loaded[] = $name;
    }
    return $loaded;
}
tegatai_load_secrets();

/**
 * Secrets that older versions kept in the database. They are only read (so nothing breaks
 * after an update) until the same secret exists in the secrets file or wp-config.php; then the
 * database copy is deleted (tegatai_purge_legacy_db_secrets()). Tegatai never writes a secret
 * to the database anymore.
 */
function tegatai_legacy_db_secrets() {
    $ops  = tegatai_get_setting( 'tegatai_options', [] );
    $ops  = is_array( $ops ) ? $ops : [];
    $hive = get_option( 'tegatai_hive_options', [] );
    $hive = is_array( $hive ) ? $hive : [];
    return array_filter( [
        'TEGATAI_API_SECRET'       => (string) get_option( 'tegatai_api_sync_secret', '' ),
        'TEGATAI_BACKUP_SECRET'    => (string) get_option( 'tegatai_backup_secret', '' ),
        'TEGATAI_HIVE_SECRET'      => (string) ( $hive['shared_secret'] ?? '' ),
        'TEGATAI_RECAPTCHA_SECRET' => (string) ( $ops['recaptcha_secret_key'] ?? '' ),
        'TEGATAI_TURNSTILE_SECRET' => (string) ( $ops['turnstile_secret_key'] ?? '' ),
        'TEGATAI_ALERT_WEBHOOK'    => (string) ( $ops['alert_webhook_url'] ?? '' ),
    ], 'strlen' );
}

/**
 * Value of a secret: constant (secrets file or wp-config.php) first, then a legacy database copy.
 */
function tegatai_secret( $name ) {
    if ( defined( $name ) && is_string( constant( $name ) ) && constant( $name ) !== '' ) return (string) constant( $name );
    $legacy = tegatai_legacy_db_secrets();
    return isset( $legacy[ $name ] ) ? $legacy[ $name ] : '';
}

/**
 * Deletes database copies of secrets that now exist in the secrets file or wp-config.php.
 * The backup secret is only removed when both values are equal, so older backups stay readable.
 */
function tegatai_purge_legacy_db_secrets() {
    $legacy = tegatai_legacy_db_secrets();
    if ( ! $legacy ) return;
    $done = [];
    foreach ( $legacy as $name => $value ) {
        if ( ! defined( $name ) || ! is_string( constant( $name ) ) || constant( $name ) === '' ) continue;
        if ( $name === 'TEGATAI_BACKUP_SECRET' && ! hash_equals( (string) constant( $name ), $value ) ) continue;
        $done[] = $name;
    }
    if ( ! $done ) return;
    if ( in_array( 'TEGATAI_API_SECRET', $done, true ) ) delete_option( 'tegatai_api_sync_secret' );
    if ( in_array( 'TEGATAI_BACKUP_SECRET', $done, true ) ) delete_option( 'tegatai_backup_secret' );
    if ( in_array( 'TEGATAI_HIVE_SECRET', $done, true ) ) {
        $hive = get_option( 'tegatai_hive_options', [] );
        if ( is_array( $hive ) ) { unset( $hive['shared_secret'] ); update_option( 'tegatai_hive_options', $hive ); }
    }
    $map = [ 'TEGATAI_RECAPTCHA_SECRET' => 'recaptcha_secret_key', 'TEGATAI_TURNSTILE_SECRET' => 'turnstile_secret_key', 'TEGATAI_ALERT_WEBHOOK' => 'alert_webhook_url' ];
    $ops = tegatai_get_setting( 'tegatai_options', [] );
    if ( is_array( $ops ) ) {
        $changed = false;
        foreach ( $map as $name => $key ) {
            if ( in_array( $name, $done, true ) && isset( $ops[ $key ] ) ) { unset( $ops[ $key ] ); $changed = true; }
        }
        if ( $changed ) tegatai_update_setting( 'tegatai_options', $ops );
    }
    if ( class_exists( 'Tegatai_Logger' ) ) Tegatai_Logger::log( 'INFO', 'Secrets removed from the database (now in secrets file / wp-config.php): ' . implode( ', ', $done ) );
}
add_action( 'admin_init', 'tegatai_purge_legacy_db_secrets' );

// Reminder on the Tegatai screens while secrets of an older version are still in the database.
add_action( 'admin_notices', function () {
    if ( ! current_user_can( 'manage_options' ) ) return;
    $page = isset( $_GET['page'] ) ? sanitize_key( wp_unslash( $_GET['page'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- display only
    if ( strpos( $page, 'tegatai' ) !== 0 ) return;
    $legacy = tegatai_legacy_db_secrets();
    if ( ! $legacy ) return;
    echo '<div class="notice notice-warning"><p><strong>Tegatai Secure:</strong> '
        . esc_html( sprintf( /* translators: %s: list of secret names */ __( 'These secrets are still stored in the database by an older version: %s. Move them into the secrets file with the command in the Secrets tab; the database copies are then deleted automatically.', 'tegatai-secure' ), implode( ', ', array_keys( $legacy ) ) ) )
        . ' <a href="' . esc_url( admin_url( 'admin.php?page=tegatai-Secure&tab=secrets' ) ) . '">' . esc_html__( 'Open Secrets tab', 'tegatai-secure' ) . '</a></p></div>';
} );

/**
 * Where each secret currently comes from: 'file', 'wp-config', 'database' (legacy, read only) or ''.
 * 'in_file' is true when the secrets file contains the name (also when wp-config.php wins).
 */
function tegatai_secrets_status() {
    $loaded  = tegatai_load_secrets();
    $in_file = tegatai_read_secrets_file();
    $legacy  = tegatai_legacy_db_secrets();
    $out = [];
    foreach ( tegatai_secret_names() as $name ) {
        if ( in_array( $name, $loaded, true ) ) $src = 'file';
        elseif ( defined( $name ) ) $src = 'wp-config';
        elseif ( isset( $legacy[ $name ] ) ) $src = 'database';
        else $src = '';
        $out[ $name ] = [ 'source' => $src, 'in_file' => isset( $in_file[ $name ] ) ];
    }
    return $out;
}

/**
 * Shell command (run as the PHP-FPM user, never as root) that creates a PHP key/secrets file
 * with safe permissions. Tegatai shows this command instead of writing the file itself.
 *
 * @param string $file    Target path.
 * @param array  $entries name => value pairs for the returned array.
 * @param array  $comment Lines written as comments into the file.
 */
function tegatai_key_file_command( $file, array $entries, array $comment = [] ) {
    $q = static function ( $v ) { return "'" . addcslashes( (string) $v, "\\'" ) . "'"; };
    $body = "<?php\n";
    foreach ( $comment as $line ) $body .= '// ' . $line . "\n";
    $body .= "if ( ! defined( 'ABSPATH' ) ) { exit; }\n\nreturn [\n";
    foreach ( $entries as $name => $value ) {
        $body .= ( $value === null ? '    // ' . $q( $name ) . " => '',\n" : '    ' . $q( $name ) . ' => ' . $q( $value ) . ",\n" );
    }
    $body .= "];\n";
    $sh  = static function ( $v ) { return "'" . str_replace( "'", "'\\''", (string) $v ) . "'"; };
    $dir = dirname( $file );
    return 'umask 077 && mkdir -p ' . $sh( $dir ) . ' && chmod 700 ' . $sh( $dir ) . " && cat > " . $sh( $file ) . " <<'TEGATAI_EOF'\n" . $body . "TEGATAI_EOF\nchmod 600 " . $sh( $file );
}

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
    $files = [
        '.htaccess'  => $htaccess,
        // Empty index.html against directory listings (no PHP file is ever written)
        'index.html' => '',
        'web.config' => '<?xml version="1.0" encoding="UTF-8"?><configuration><system.webServer><authorization><deny users="*" /></authorization></system.webServer></configuration>',
    ];
    $ok = true;
    foreach ( $files as $name => $content ) {
        $path = $dir . $name;
        if ( file_exists( $path ) && ( $name === 'index.html' || file_get_contents( $path ) === $content ) ) continue;
        if ( @file_put_contents( $path, $content ) === false ) $ok = false;
    }
    // Only Apache/LiteSpeed/IIS read these files; on nginx the folder is protected by the
    // generated rules. tegatai_data_dir_exposed() checks what actually happens.
    return $ok;
}

/**
 * Checks over HTTP whether the data folder is reachable from the web (cached for 12 hours).
 * Returns true when a request for uploads/tegatai-secure/index.html is answered with 200,
 * i.e. the deny rules are not effective (e.g. nginx without the Tegatai include).
 */
function tegatai_data_dir_exposed() {
    $cached = get_transient( 'tegatai_dir_check' );
    if ( $cached !== false ) return $cached === 'exposed';
    $url = trailingslashit( wp_upload_dir( null, false )['baseurl'] ) . tegatai_data_dir_name() . '/index.html';
    $r = wp_remote_head( $url, [ 'timeout' => 5, 'redirection' => 0, 'sslverify' => false ] );
    if ( is_wp_error( $r ) ) {
        // Loopback not possible (firewall, DNS): no result, try again in an hour
        set_transient( 'tegatai_dir_check', 'unknown', HOUR_IN_SECONDS );
        return false;
    }
    $exposed = (int) wp_remote_retrieve_response_code( $r ) === 200;
    set_transient( 'tegatai_dir_check', $exposed ? 'exposed' : 'ok', 12 * HOUR_IN_SECONDS );
    return $exposed;
}

// Warning on the Tegatai screens when the data folder (logs, backups) is reachable from the web.
add_action( 'admin_notices', function () {
    if ( ! current_user_can( 'manage_options' ) ) return;
    $page = isset( $_GET['page'] ) ? sanitize_key( wp_unslash( $_GET['page'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- display only
    if ( strpos( $page, 'tegatai' ) !== 0 || ! tegatai_data_dir_exposed() ) return;
    $recheck = wp_nonce_url( admin_url( 'admin-post.php?action=tegatai_dir_recheck' ), 'tegatai_dir_recheck' );
    echo '<div class="notice notice-error"><p><strong>Tegatai Secure:</strong> '
        /* translators: %s: URL path of the data folder */
        . esc_html( sprintf( __( 'The data folder %s (logs, backups) can be reached from the web. The block is already part of the Tegatai nginx file: make sure the include line in the server block points to the file shown in the Server tab and reload nginx. On Apache, make sure .htaccess files are allowed (AllowOverride).', 'tegatai-secure' ), tegatai_data_dir_url_path() ) )
        . ' <a href="' . esc_url( $recheck ) . '">' . esc_html__( 'Check again', 'tegatai-secure' ) . '</a></p></div>';
} );

// "Check again" link of the notice above: drops the cached result.
add_action( 'admin_post_tegatai_dir_recheck', function () {
    check_admin_referer( 'tegatai_dir_recheck' );
    if ( ! current_user_can( 'manage_options' ) ) wp_die( esc_html__( 'Access Denied', 'tegatai-secure' ) );
    delete_transient( 'tegatai_dir_check' );
    delete_transient( 'tegatai_include_check' );
    wp_safe_redirect( wp_get_referer() ?: admin_url( 'admin.php?page=tegatai-Secure' ) );
    exit;
} );

// Error on the Tegatai screens when the data folder or one of its subfolders could not be set up.
add_action( 'admin_notices', function () {
    if ( ! current_user_can( 'manage_options' ) ) return;
    $page = isset( $_GET['page'] ) ? sanitize_key( wp_unslash( $_GET['page'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- display only
    if ( strpos( $page, 'tegatai' ) !== 0 ) return;
    $error = get_option( 'tegatai_data_dir_error', '' );
    if ( ! is_string( $error ) || $error === '' ) return;
    echo '<div class="notice notice-error"><p><strong>Tegatai Secure:</strong> '
        /* translators: %s: folder paths and reasons */
        . esc_html( sprintf( __( 'The data folder could not be set up: %s. Tegatai tries again every ten minutes.', 'tegatai-secure' ), $error ) )
        . '</p></div>';
} );

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

// Module laden
require_once TEGATAI_PATH . 'includes/logger.php';
// WP Masking maps the request URI of its new paths before the firewall reads it
require_once TEGATAI_PATH . 'includes/mask.php';
require_once TEGATAI_PATH . 'includes/bans.php';
require_once TEGATAI_PATH . 'includes/geoip.php';
require_once TEGATAI_PATH . 'includes/firewall.php';
require_once TEGATAI_PATH . 'includes/hardening.php';
require_once TEGATAI_PATH . 'includes/headers.php';
require_once TEGATAI_PATH . 'includes/captcha.php';
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
require_once TEGATAI_PATH . 'includes/abuseipdb.php';

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
        if (is_admin() || wp_doing_cron() || (defined('WP_CLI') && WP_CLI)) {
            add_action('init', [__CLASS__, 'ensure_environment'], 20);
        }
        // The rename of the stored names must happen before the first login or 2FA check,
        // so it runs once on any request (front end and wp-login.php included).
        if (get_option('tegatai_prefix_migrated') !== '1') {
            self::migrate_prefix();
            update_option('tegatai_prefix_migrated', '1', true);
        }
    }

    // Registered at top level below; runs in the activation request.
    public static function activate() {
        self::install_db();
        if (!tegatai_get_setting('tegatai_options')) tegatai_update_setting('tegatai_options', []);
        delete_option('tegatai_env_version');
        self::ensure_environment();
        // Restore the server rules that were removed on deactivation (plugin update, folder rename).
        // Installs deactivated by older versions have no flag; enabled server_* options count as well.
        $ops = tegatai_get_setting('tegatai_options', []);
        $server_opts = is_array($ops) ? array_filter($ops, static function ($v, $k) { return strpos((string) $k, 'server_') === 0 && !empty($v); }, ARRAY_FILTER_USE_BOTH) : [];
        if (class_exists('Tegatai_Server') && (get_option('tegatai_restore_rules') || $server_opts || Tegatai_Server::has_rules() || Tegatai_Server::detect_server() === 'nginx')) {
            Tegatai_Server::force_update();
        }
        delete_option('tegatai_restore_rules');
        flush_rewrite_rules();
    }

    const ENV_VERSION = '12';

    // Subfolders of the data folder.
    const DATA_SUBDIRS = ['logs', 'backups', 'server', 'geoip'];

    // Folders of 2.2.1 and older that move into the data folder. "tegatai-server" (nginx file of
    // 2.2.1) is not moved: an nginx include may still point to it, and nginx does not start when
    // an included file is missing. It is removed with a button in the Server tab
    // (Tegatai_Server::remove_old_server_dir()) once nginx uses the new file.
    const OLD_DATA_DIRS = ['tegatai-logs' => 'logs', 'tegatai-backups' => 'backups', 'tegatai-geoip' => 'geoip'];

    public static function ensure_environment() {
        $upgrade = get_option('tegatai_env_version') !== self::ENV_VERSION;

        // The data folder is checked on every request (a few stat calls), not only once after an
        // update: a missing folder is created again, folders of older versions are moved in. A
        // failed attempt is reported on the Tegatai screens and retried after ten minutes.
        $ready = self::data_dirs_ready();
        if (!$ready && ($upgrade || !get_transient('tegatai_dirs_retry'))) {
            $ready = self::setup_data_dirs();
        } elseif ($ready && get_option('tegatai_data_dir_error', '') !== '') {
            delete_option('tegatai_data_dir_error'); // fixed in the meantime (e.g. by the admin)
        }
        // nginx file missing at its place or last written somewhere else (folder just created,
        // file deleted, uploads folder moved): written again right away, so an include pointing
        // there finds it.
        $nginx_status = get_option('tegatai_rules_status', []);
        $rules_file = class_exists('Tegatai_Server') ? Tegatai_Server::get_rules_file_path() : '';
        $rules_stale = $rules_file !== '' && (!file_exists($rules_file) || (is_array($nginx_status) && !empty($nginx_status['path']) && $nginx_status['path'] !== $rules_file));
        if ($ready && !$upgrade && $rules_stale
            && (Tegatai_Server::has_rules() || Tegatai_Server::detect_server() === 'nginx') && !get_transient('tegatai_rules_retry')) {
            $status = Tegatai_Server::force_update();
            if (empty($status['ok'])) set_transient('tegatai_rules_retry', 1, 10 * MINUTE_IN_SECONDS);
        }

        if ($upgrade) {
            // Leftover credentials of the never-implemented FTP feature.
            delete_option('tegatai_ftp_settings');
            // Bans now live in Tegatai_Bans. Old per-IP "permanent" transients from the admin
            // honeypot were autoloaded on every request; old Hive bans are migrated.
            global $wpdb;
            // Old per-IP transients of older versions are removed by migrate_prefix().
            $legacy = get_option('tegatai_hive_bans', []);
            if (is_array($legacy)) {
                foreach ($legacy as $ip => $b) {
                    $left = (int)($b['until'] ?? 0) - time();
                    if ($left > 0) Tegatai_Bans::add($ip, $left, $b['reason'] ?? '', 'hive:' . ($b['node'] ?? ''), $b['level'] ?? 'critical');
                }
            }
            delete_option('tegatai_hive_bans');
            // Regenerate existing server rules once (2.2.2: nginx file moved to uploads/tegatai-secure/server/;
            // 2.2.3: full .htaccess rule set for Apache / LiteSpeed, placed in front of the WordPress block;
            // 2.2.4: exception list for direct PHP requests in plugins and themes;
            // 2.2.5: security headers in the server rules; 2.2.6: X-XSS-Protection "0", COOP, CORP;
            // 2.2.7: include check location, data folder name; 2.2.8: CSP upgrade-insecure-requests).
            // On nginx the rules file is always written: it carries the block for the data folder.
            if (class_exists('Tegatai_Server') && (Tegatai_Server::has_rules() || Tegatai_Server::detect_server() === 'nginx')) {
                Tegatai_Server::force_update();
            }
            update_option('tegatai_env_version', self::ENV_VERSION, false);
        }

        self::ensure_cron_events();
    }

    // True when the data folder and all subfolders exist and no folder of an older version is left.
    public static function data_dirs_ready() {
        foreach (array_merge([''], self::DATA_SUBDIRS) as $sub) {
            if (!is_dir(tegatai_data_dir($sub))) return false;
        }
        $base = trailingslashit(wp_upload_dir(null, false)['basedir']);
        foreach (array_keys(self::OLD_DATA_DIRS) as $old) {
            if (is_dir($base . $old)) return false;
        }
        return true;
    }

    /**
     * Creates and protects the data folder and its subfolders, then moves the folders of older
     * versions in. Every failure is stored with its reason (shown on the Tegatai screens and in
     * the log); nothing is marked as done while a folder is missing.
     */
    public static function setup_data_dirs() {
        $errors = [];
        foreach (array_merge([''], self::DATA_SUBDIRS) as $sub) {
            $dir = tegatai_data_dir($sub);
            if (function_exists('error_clear_last')) error_clear_last();
            tegatai_protect_directory($dir);
            if (!is_dir($dir)) {
                $errors[] = $dir . ': ' . self::dir_error_reason($dir);
                if ($sub === '') break; // without the main folder the subfolders fail for the same reason
            }
        }
        if (!$errors) {
            self::migrate_data_dirs();
            $base = trailingslashit(wp_upload_dir(null, false)['basedir']);
            foreach (array_keys(self::OLD_DATA_DIRS) as $old) {
                if (is_dir($base . $old)) {
                    $errors[] = $base . $old . ': ' . self::dir_error_reason($base . $old, true);
                }
            }
        }
        if (!$errors) {
            delete_option('tegatai_data_dir_error');
            delete_transient('tegatai_dirs_retry');
            return true;
        }
        $msg = implode(' | ', $errors);
        if (get_option('tegatai_data_dir_error') !== $msg && class_exists('Tegatai_Logger')) {
            Tegatai_Logger::log('ERROR', 'Data folder could not be set up: ' . $msg);
        }
        update_option('tegatai_data_dir_error', $msg, false);
        set_transient('tegatai_dirs_retry', 1, 10 * MINUTE_IN_SECONDS);
        return false;
    }

    // Why a folder could not be created ($is_old: why an old folder could not be moved/emptied).
    private static function dir_error_reason($dir, $is_old = false) {
        if ($is_old) {
            $left = array_diff((array) @scandir($dir), ['.', '..']);
            if (!wp_is_writable($dir) || !wp_is_writable(dirname($dir))) {
                return 'old folder could not be moved (owner ' . @fileowner($dir) . ', mode ' . substr(sprintf('%o', @fileperms($dir)), -4) . ')';
            }
            return 'old folder could not be emptied, left: ' . implode(', ', array_slice($left, 0, 5));
        }
        $last = error_get_last();
        $parent = dirname($dir);
        while ($parent !== '' && $parent !== '.' && !is_dir($parent) && dirname($parent) !== $parent) {
            $parent = dirname($parent);
        }
        if (is_dir($parent) && !wp_is_writable($parent)) {
            return 'folder ' . $parent . ' is not writable for PHP (owner ' . @fileowner($parent) . ', mode ' . substr(sprintf('%o', @fileperms($parent)), -4) . ', PHP runs as ' . (function_exists('posix_geteuid') ? posix_geteuid() : '?') . ')';
        }
        if (file_exists($dir) && !is_dir($dir)) return 'a file with this name exists';
        return ($last['message'] ?? '') !== '' ? (string) $last['message'] : 'could not be created';
    }

    /**
     * 2.2.2: all stored names use the prefix "tegatai_" (older versions used the short "tegatai_").
     * Options and user meta are renamed (values kept); short-lived transients of the old names
     * are deleted. The old prefix is built at runtime, it is not used anywhere else.
     */
    public static function migrate_prefix() {
        global $wpdb;
        $old = 'te' . 'g_';
        $like = $wpdb->esc_like($old) . '%';
        // Options
        $names = $wpdb->get_col($wpdb->prepare("SELECT option_name FROM {$wpdb->options} WHERE option_name LIKE %s", $like));
        foreach ((array) $names as $name) {
            $new = 'tegatai_' . substr((string) $name, strlen($old));
            $exists = $wpdb->get_var($wpdb->prepare("SELECT COUNT(*) FROM {$wpdb->options} WHERE option_name = %s", $new));
            if ((int) $exists === 0) {
                $wpdb->update($wpdb->options, ['option_name' => $new], ['option_name' => $name]);
            } else {
                $wpdb->delete($wpdb->options, ['option_name' => $name]);
            }
        }
        // Transients (rate limits, pending 2FA logins, cached scan data): dropped, they are rebuilt
        foreach (['_transient_', '_transient_timeout_', '_site_transient_', '_site_transient_timeout_'] as $pre) {
            $wpdb->query($wpdb->prepare("DELETE FROM {$wpdb->options} WHERE option_name LIKE %s", $wpdb->esc_like($pre . $old) . '%'));
        }
        // User meta (2FA secrets and status, known devices, activity). An old key whose new name
        // already exists for the same user is dropped first, so no duplicates are created.
        $wpdb->query($wpdb->prepare(
            "DELETE o FROM {$wpdb->usermeta} o INNER JOIN {$wpdb->usermeta} n ON n.user_id = o.user_id AND n.meta_key = CONCAT('tegatai_', SUBSTRING(o.meta_key, %d)) WHERE o.meta_key LIKE %s",
            strlen($old) + 1,
            $like
        ));
        // User meta (2FA secrets and status, known devices, activity)
        $wpdb->query($wpdb->prepare(
            "UPDATE {$wpdb->usermeta} SET meta_key = CONCAT('tegatai_', SUBSTRING(meta_key, %d)) WHERE meta_key LIKE %s",
            strlen($old) + 1,
            $like
        ));
        wp_cache_flush();
    }

    /**
     * Moves the folders of older versions (uploads/tegatai-logs, -backups, -geoip) into the data
     * folder. The target subfolders exist already (setup_data_dirs()), so the contents are merged.
     */
    private static function migrate_data_dirs() {
        $base = trailingslashit(wp_upload_dir(null, false)['basedir']);
        foreach (self::OLD_DATA_DIRS as $old => $new) {
            $from = $base . $old;
            if (is_dir($from) && !is_link($from)) self::merge_dir($from, tegatai_data_dir($new));
        }
        // Private files get unguessable names
        foreach (['snapshot.json', 'scan_files.json', 'fim_snapshot.json'] as $f) {
            $old = tegatai_data_dir('logs') . '/' . $f;
            if (is_file($old)) @rename($old, tegatai_private_file($f)); // phpcs:ignore WordPress.WP.AlternativeFunctions.rename_rename -- same folder, new name
        }
    }

    /**
     * Moves everything from $from into $to and removes $from. Protection files of the old folder
     * are dropped (the target has its own), subfolders are merged, identical files are dropped and
     * a different file with a name that is taken keeps both (old one renamed to "<name>-old").
     */
    private static function merge_dir($from, $to) {
        foreach ((array) @scandir($from) as $entry) {
            if ($entry === '.' || $entry === '..' || $entry === false) continue;
            $src = $from . '/' . $entry;
            $dst = $to . '/' . $entry;
            if (is_file($src) && in_array($entry, ['.htaccess', 'index.php', 'index.html', 'web.config'], true)) {
                wp_delete_file($src);
                continue;
            }
            if (!file_exists($dst)) {
                @rename($src, $dst); // phpcs:ignore WordPress.WP.AlternativeFunctions.rename_rename -- moves the plugin's own data inside uploads
                continue;
            }
            if (is_dir($src) && is_dir($dst) && !is_link($src)) {
                self::merge_dir($src, $dst);
                continue;
            }
            if (is_file($src) && is_file($dst) && md5_file($src) === md5_file($dst)) {
                wp_delete_file($src);
                continue;
            }
            $ext  = pathinfo($entry, PATHINFO_EXTENSION);
            $stem = $ext === '' ? $entry : substr($entry, 0, -strlen($ext) - 1);
            $i = 1;
            do {
                $alt = $to . '/' . $stem . '-old' . ($i > 1 ? $i : '') . ($ext === '' ? '' : '.' . $ext);
                $i++;
            } while (file_exists($alt) && $i < 100);
            if (!file_exists($alt)) @rename($src, $alt); // phpcs:ignore WordPress.WP.AlternativeFunctions.rename_rename -- same as above
        }
        @rmdir($from); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_rmdir -- only succeeds when the old folder is empty
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

        // Only record the schema version when the table really exists. If dbDelta() failed
        // (missing privileges, storage engine issue), the version stays unset so the next
        // admin request retries the installation instead of logging into a missing table.
        if ($wpdb->get_var($wpdb->prepare('SHOW TABLES LIKE %s', $wpdb->esc_like($table_name))) !== $table_name) {
            return false;
        }

        // dbDelta never removes column defaults; drop the legacy zero-date default explicitly,
        // but only when such a default is actually present (avoids a needless ALTER on every install).
        $default = $wpdb->get_var($wpdb->prepare(
            'SELECT COLUMN_DEFAULT FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = %s AND COLUMN_NAME = %s',
            $table_name,
            'time'
        ));
        if ($default !== null && strtoupper((string) $default) !== 'NULL') {
            $wpdb->query($wpdb->prepare("ALTER TABLE %i ALTER COLUMN `time` DROP DEFAULT", $table_name));
        }

        update_option('tegatai_db_version', self::DB_VERSION);
        return true;
    }

    public static function deactivate() {
        if (class_exists('Tegatai_Server')) {
            Tegatai_Server::remove_rules();
        }
        wp_clear_scheduled_hook('tegatai_daily_backup_event');
        wp_clear_scheduled_hook('tegatai_daily_maintenance');
        wp_clear_scheduled_hook('tegatai_hive_retry_cron');
        wp_clear_scheduled_hook('tegatai_hive_flush');
        wp_clear_scheduled_hook('tegatai_abuseipdb_send');
        wp_clear_scheduled_hook('tegatai_mask_files_check');
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
