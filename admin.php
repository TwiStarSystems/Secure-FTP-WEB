<?php
// Legacy admin entrypoint retained for compatibility.
require_once 'config.php';
require_once 'db.php';
require_once 'auth.php';
require_once 'rbac.php';

$db = new Database();
$auth = new Auth($db);

if (!$auth->isLoggedIn() || !RBAC::isAdmin()) {
    header('Location: login.php');
    exit;
}

header('Location: settings.php?settings_tab=site-settings');
exit;
?>