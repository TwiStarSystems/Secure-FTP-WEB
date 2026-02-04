<?php
// Login handler
require_once 'config.php';
require_once 'db.php';
require_once 'auth.php';

$db = new Database();
$auth = new Auth($db);

// Redirect if already logged in
if ($auth->isLoggedIn()) {
    header('Location: index.php');
    exit;
}

// Handle form submission
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Verify CSRF token
    if (!isset($_POST['csrf_token']) || !$auth->verifyCSRFToken($_POST['csrf_token'])) {
        $error = 'Invalid request. Please try again.';
    } else {
        $loginType = $_POST['login_type'] ?? 'user';
        
        if ($loginType === 'user') {
            $username = $_POST['username'] ?? '';
            $password = $_POST['password'] ?? '';
            
            $result = $auth->login($username, $password);
            
            if ($result['success']) {
                header('Location: index.php');
                exit;
            } else {
                $error = $result['error'];
            }
        } elseif ($loginType === 'code') {
            $accessCode = $_POST['access_code'] ?? '';
            
            $result = $auth->loginWithAccessCode($accessCode);
            
            if ($result['success']) {
                header('Location: index.php');
                exit;
            } else {
                $error = $result['error'];
            }
        }
    }
}

// Generate CSRF token
$csrfToken = $auth->generateCSRFToken();

// Include login form
include 'login_form.php';
?>
