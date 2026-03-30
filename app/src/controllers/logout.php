<?php
require_once APP_DIR . '/src/core/db.php';
require_once APP_DIR . '/src/services/auth.php';

$db = new Database();
$auth = new Auth($db);
$auth->logout();

header('Location: login.php');
exit;
