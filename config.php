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

// Dynamically set secure flag based on HTTPS (including behind proxy)
$isSecure = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') 
    || (!empty($_SERVER['HTTP_X_FORWARDED_PROTO']) && $_SERVER['HTTP_X_FORWARDED_PROTO'] === 'https')
    || (!empty($_SERVER['HTTP_X_FORWARDED_SSL']) && $_SERVER['HTTP_X_FORWARDED_SSL'] === 'on');
ini_set('session.cookie_secure', $isSecure ? 1 : 0);

ini_set('session.cookie_samesite', 'Strict'); // CSRF protection

// Start session if not already started
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

/**
 * Helper Functions for Reverse Proxy Support
 * These functions detect the correct protocol and host when behind a reverse proxy
 */

/**
 * Get the current protocol (http or https)
 * Respects X-Forwarded-Proto and X-Forwarded-SSL headers from reverse proxy
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
    
    // Fall back to standard HTTPS detection
    if (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') {
        return 'https';
    }
    
    // Check if on standard HTTPS port
    if (!empty($_SERVER['SERVER_PORT']) && $_SERVER['SERVER_PORT'] == 443) {
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
