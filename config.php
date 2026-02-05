<?php
// Configuration file for Secure FTP Web Application

// Database configuration
// IMPORTANT: Change these values for production!
define('DB_HOST', 'localhost');
define('DB_NAME', 'secure_ftp');
define('DB_USER', 'secure_ftp_user');  // Create a dedicated database user
define('DB_PASS', 'CHANGE_THIS_PASSWORD');  // Set a strong password

// Application settings
define('SITE_NAME', 'Secure File Transfer');
define('MAX_FILE_SIZE', 10737418240); // 10 GB in bytes
define('UPLOAD_DIR', __DIR__ . '/uploads/');
define('SESSION_TIMEOUT', 3600); // 1 hour

// Rate limiting settings
define('MAX_LOGIN_ATTEMPTS', 5);
define('LOCKOUT_DURATION', 900); // 15 minutes in seconds

// Hashing algorithms available
define('HASH_ALGORITHMS', ['sha256', 'sha512', 'sha1']);
define('DEFAULT_HASH_ALGORITHM', 'sha256');

// Timezone
date_default_timezone_set('UTC');

// Session configuration for security and Nginx compatibility
ini_set('session.cookie_httponly', 1);  // Prevent JavaScript access to session cookies
ini_set('session.use_only_cookies', 1); // Only use cookies for session management
ini_set('session.cookie_secure', 0);    // Set to 1 if using HTTPS
ini_set('session.cookie_samesite', 'Strict'); // CSRF protection

// Start session if not already started
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}
?>
