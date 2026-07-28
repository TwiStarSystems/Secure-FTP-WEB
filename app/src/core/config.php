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
define('UPLOAD_DIR', APP_BASE . '/app/storage/uploads/');
define('SESSION_TIMEOUT', 3600); // 1 hour

// If a file has been stuck at processing_status 'pending'/'processing' longer than this
// (background worker crashed, was never spawned, or never finished), it gets marked 'failed'
// instead of polling forever with no resolution. See FileManager::spawnProcessor().
define('PROCESSING_STUCK_TIMEOUT_SECONDS', 1800); // 30 minutes

// Rate limiting settings
define('MAX_LOGIN_ATTEMPTS', 5);
define('LOCKOUT_DURATION', 900); // 15 minutes in seconds

// Download and share abuse protection settings
define('MAX_DOWNLOAD_REQUESTS_WINDOW', 120); // requests per window
define('DOWNLOAD_REQUEST_WINDOW_SECONDS', 300); // 5 minutes
define('DOWNLOAD_REQUEST_LOCKOUT_SECONDS', 600); // 10 minutes

define('MAX_DOWNLOAD_FAILURE_ATTEMPTS', 12); // invalid/forbidden attempts per window
define('DOWNLOAD_FAILURE_WINDOW_SECONDS', 600); // 10 minutes
define('DOWNLOAD_FAILURE_LOCKOUT_SECONDS', 900); // 15 minutes

define('MAX_SHARE_TOKEN_FAILURE_ATTEMPTS', 15); // invalid token attempts per window
define('SHARE_TOKEN_FAILURE_WINDOW_SECONDS', 600); // 10 minutes
define('SHARE_TOKEN_FAILURE_LOCKOUT_SECONDS', 1800); // 30 minutes

define('MAX_SHARE_PASSWORD_FAILURE_ATTEMPTS', 8); // wrong password attempts per window
define('SHARE_PASSWORD_FAILURE_WINDOW_SECONDS', 600); // 10 minutes
define('SHARE_PASSWORD_FAILURE_LOCKOUT_SECONDS', 1200); // 20 minutes

define('MAX_SHARE_REQUESTS_WINDOW', 120); // requests per window
define('SHARE_REQUEST_WINDOW_SECONDS', 600); // 10 minutes
define('SHARE_REQUEST_LOCKOUT_SECONDS', 900); // 15 minutes

// Hashing algorithms available
define('HASH_ALGORITHMS', ['sha256', 'sha512', 'sha1']);
define('DEFAULT_HASH_ALGORITHM', 'sha256');

// File encryption at rest (AES-256-GCM)
// IMPORTANT: Generated during installation. Do NOT change after files are uploaded!
// 64 hex characters = 32 bytes = 256-bit key
define('FILE_ENCRYPTION_KEY', 'CHANGE_THIS_KEY');

// Publicly accessible routes (no authentication required)
define('PUBLIC_ENTRYPOINTS', ['login.php', 'public.php', 'shared.php', 'logout.php', 'forgot_password.php', 'reset_password.php']);

// Timezone
date_default_timezone_set('UTC');

// Session configuration for security and Nginx compatibility
ini_set('session.cookie_httponly', 1);  // Prevent JavaScript access to session cookies
ini_set('session.use_only_cookies', 1); // Only use cookies for session management

// Dynamically set secure flag when behind a reverse proxy that terminates SSL
$isSecure = (!empty($_SERVER['HTTP_X_FORWARDED_PROTO']) && $_SERVER['HTTP_X_FORWARDED_PROTO'] === 'https')
    || (!empty($_SERVER['HTTP_X_FORWARDED_SSL']) && $_SERVER['HTTP_X_FORWARDED_SSL'] === 'on');
ini_set('session.cookie_secure', $isSecure ? 1 : 0);

ini_set('session.cookie_samesite', 'Strict'); // CSRF protection

// Start session if not already started
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

// Central access guard for direct web requests.
// Only explicitly public pages are reachable without authentication.
if (PHP_SAPI !== 'cli' && isset($_SERVER['SCRIPT_NAME'])) {
    $entryScript = basename((string)$_SERVER['SCRIPT_NAME']);
    $isPhpEntrypoint = substr($entryScript, -4) === '.php';

    if ($isPhpEntrypoint) {
        $isPublicScript = in_array($entryScript, PUBLIC_ENTRYPOINTS, true);
        $isAuthenticatedSession = isset($_SESSION['user_id']) || isset($_SESSION['access_code_id']);

        if (!$isPublicScript && !$isAuthenticatedSession) {
            header('Location: login.php');
            exit;
        }
    }
}

/**
 * Helper Functions for Reverse Proxy Support
 * These functions detect the correct protocol and host when behind a reverse proxy
 */

/**
 * Get the current protocol (http or https)
 * Detects HTTPS when behind a reverse proxy that terminates SSL
 */
function getProtocol() {
    // Check X-Forwarded-Proto header (set by reverse proxy)
    if (!empty($_SERVER['HTTP_X_FORWARDED_PROTO'])) {
        return strtolower($_SERVER['HTTP_X_FORWARDED_PROTO']) === 'https' ? 'https' : 'http';
    }
    
    // Check X-Forwarded-SSL header
    if (!empty($_SERVER['HTTP_X_FORWARDED_SSL']) && $_SERVER['HTTP_X_FORWARDED_SSL'] === 'on') {
        return 'https';
    }
    
    return 'http';
}

/**
 * Get the current host
 * Respects X-Forwarded-Host header from reverse proxy
 */
function getHost() {
    // Check X-Forwarded-Host header (set by reverse proxy)
    if (!empty($_SERVER['HTTP_X_FORWARDED_HOST'])) {
        // Take the first host if multiple are listed
        $hosts = explode(',', $_SERVER['HTTP_X_FORWARDED_HOST']);
        return trim($hosts[0]);
    }
    
    // Fall back to HTTP_HOST
    if (!empty($_SERVER['HTTP_HOST'])) {
        return $_SERVER['HTTP_HOST'];
    }
    
    // Fall back to SERVER_NAME
    if (!empty($_SERVER['SERVER_NAME'])) {
        return $_SERVER['SERVER_NAME'];
    }
    
    return 'localhost';
}

/**
 * Get the base URL of the application
 * Checks for custom base URL setting first, then falls back to auto-detection
 * Works correctly behind reverse proxy
 */
function getBaseUrl() {
    // Check for custom base URL in database settings
    static $customBaseUrl = null;
    static $checked = false;
    
    if (!$checked) {
        $checked = true;
        try {
            // Safely check for custom base URL without causing circular dependencies
            if (class_exists('Database')) {
                $db = new Database();
                $sql = "SELECT setting_value FROM app_settings WHERE setting_key = ? LIMIT 1";
                $result = $db->fetch($sql, ['base_url']);
                if ($result && !empty($result['setting_value'])) {
                    $customBaseUrl = rtrim($result['setting_value'], '/');
                }
            }
        } catch (Exception $e) {
            // If database is not ready or table doesn't exist yet, fall back to auto-detection
        }
    }
    
    // Return custom URL if configured
    if ($customBaseUrl) {
        return $customBaseUrl;
    }
    
    // Fall back to auto-detection
    $protocol = getProtocol();
    $host = getHost();
    $basePath = dirname($_SERVER['SCRIPT_NAME']);
    $basePath = rtrim($basePath, '/');
    return "{$protocol}://{$host}{$basePath}";
}
?>
