<?php
// Legacy admin entrypoint retained for compatibility.
require_once APP_DIR . '/src/core/config.php';
require_once APP_DIR . '/src/core/db.php';
require_once APP_DIR . '/src/services/auth.php';
require_once APP_DIR . '/src/services/rbac.php';

$db = new Database();
$auth = new Auth($db);

if (!$auth->isLoggedIn() || !RBAC::isAdmin()) {
    header('Location: login.php');
    exit;
}

header('Location: settings.php?settings_tab=site-settings');
exit;
?>