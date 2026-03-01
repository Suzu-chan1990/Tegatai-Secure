<?php
/**
 * Tegatai Secure - Fallback 404 Page
 * Wird genutzt, wenn das aktive Theme keine 404.php besitzt.
 */
if ( ! defined( 'ABSPATH' ) ) { exit; }
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Page Not Found - 404</title>
    <style>
        body { margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; background-color: #f3f4f6; color: #1f2937; display: flex; align-items: center; justify-content: center; height: 100vh; text-align: center; }
        .container { background: white; padding: 40px; border-radius: 12px; box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.1), 0 8px 10px -6px rgba(0, 0, 0, 0.1); max-width: 400px; width: 90%; }
        h1 { font-size: 80px; margin: 0; font-weight: 900; color: #4f46e5; line-height: 1; letter-spacing: -2px; }
        h2 { margin: 20px 0 10px; font-size: 24px; font-weight: 700; }
        p { color: #6b7280; margin-bottom: 30px; line-height: 1.5; }
        a { display: inline-block; background-color: #4f46e5; color: white; text-decoration: none; padding: 12px 24px; border-radius: 6px; font-weight: 600; transition: background-color 0.2s; }
        a:hover { background-color: #4338ca; }
        .icon { font-size: 40px; margin-bottom: 10px; display: block; }
    </style>
</head>
<body>
    <div class="container">
        <h1>404</h1>
        <h2>Page Not Found</h2>
        <p>The page you are looking for might have been removed, had its name changed, or is temporarily unavailable.</p>
        <a href="/">Back to Homepage</a>
    </div>
</body>
</html>
