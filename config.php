<?php
// Configuration file for Secure FTP Web Application

// Database configuration
define('DB_HOST', 'localhost');
define('DB_NAME', 'secure_ftp');
define('DB_USER', 'root');
define('DB_PASS', '');

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

// Start session
session_start();
?>
