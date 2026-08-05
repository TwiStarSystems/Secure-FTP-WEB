<?php
// Bootstrap file for Secure FTP Web Application
// Defines base path constants used throughout the application

if (!defined('APP_BASE')) {
    define('APP_BASE', dirname(__DIR__));
}

if (!defined('APP_DIR')) {
    define('APP_DIR', __DIR__);
}

require_once APP_DIR . '/src/core/config.php';

// Re-validate user-backed sessions against the database on every web request,
// so demoting, disabling, or deleting a user takes effect immediately instead
// of only after their cached session state expires (up to SESSION_TIMEOUT).
// This lives here rather than in config.php because install.sh --update
// preserves the existing config.php and would never ship guard changes.
if (PHP_SAPI !== 'cli' && isset($_SERVER['SCRIPT_NAME']) && isset($_SESSION['user_id'])) {
    require_once APP_DIR . '/src/core/db.php';

    $guardDb = new Database();
    $guardUser = $guardDb->fetch(
        "SELECT role, is_admin, is_active FROM users WHERE id = ? LIMIT 1",
        [$_SESSION['user_id']]
    );

    if (!$guardUser || empty($guardUser['is_active'])) {
        // Account deleted or disabled (or DB unreachable — fail closed).
        session_unset();
        session_destroy();

        $entryScript = basename((string)$_SERVER['SCRIPT_NAME']);
        if (!in_array($entryScript, PUBLIC_ENTRYPOINTS, true)) {
            header('Location: login.php');
            exit;
        }
    } else {
        // Refresh cached role in case an admin changed it mid-session.
        $_SESSION['user_role'] = !empty($guardUser['role'])
            ? $guardUser['role']
            : (!empty($guardUser['is_admin']) ? 'admin' : 'user');
        $_SESSION['is_admin'] = $guardUser['is_admin'];
    }

    unset($guardDb, $guardUser);
}
