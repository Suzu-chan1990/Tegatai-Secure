<?php
/**
 * Tegatai Secure - Fallback 404 Page
 * Shown for blocked wp-admin requests (Hide wp-admin).
 */
if ( ! defined( 'ABSPATH' ) ) { exit; }
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Page Not Found - 404</title>
    <?php
    // Own stylesheet through the WordPress API (no inline styles)
    wp_register_style('tegatai-404', TEGATAI_URL . 'css/404.css', [], TEGATAI_VERSION);
    wp_print_styles('tegatai-404');
    ?>
</head>
<body>
    <div class="container">
        <h1>404</h1>
        <h2>Page Not Found</h2>
        <p>The page you are looking for might have been removed, had its name changed, or is temporarily unavailable.</p>
        <a href="<?php echo esc_url( home_url( '/' ) ); ?>">Back to Homepage</a>
    </div>
</body>
</html>
