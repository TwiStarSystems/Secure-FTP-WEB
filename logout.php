<?php
require_once 'db.php';
require_once 'auth.php';

$db = new Database();
$auth = new Auth($db);
$auth->logout();

header('Location: login.php');
exit;
