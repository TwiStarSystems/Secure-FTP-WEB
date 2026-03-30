<?php
/**
 * Password Reset Handler
 * Validates reset tokens and allows users to set a new password.
 */
require_once APP_DIR . '/src/core/config.php';
require_once APP_DIR . '/src/core/db.php';
require_once APP_DIR . '/src/services/auth.php';
require_once APP_DIR . '/src/services/users.php';
require_once APP_DIR . '/src/services/security_monitor.php';

$db = new Database();
$auth = new Auth($db);
$userManager = new UserManager($db);
$securityMonitor = new SecurityMonitor($db);

// Ensure table exists for installs that predate this feature
$db->query("CREATE TABLE IF NOT EXISTS password_reset_tokens (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    token_hash CHAR(64) NOT NULL UNIQUE,
    expires_at DATETIME NOT NULL,
    used_at DATETIME NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_reset_token_hash (token_hash),
    INDEX idx_reset_expires_at (expires_at)
)");

if ($auth->isLoggedIn()) {
    header('Location: index.php');
    exit;
}

// Purge expired / already-used tokens
$db->query("DELETE FROM password_reset_tokens WHERE expires_at < NOW() OR used_at IS NOT NULL");

// Token is in the query string for both GET and POST (form posts to same URL)
$rawToken = trim($_GET['token'] ?? '');
$error = null;
$message = null;
$tokenData = null;
$validToken = false;

if ($rawToken !== '' && preg_match('/^[a-f0-9]{64}$/', $rawToken)) {
    $tokenHash = hash('sha256', $rawToken);
    $tokenData = $db->fetch(
        "SELECT prt.id, prt.user_id, u.username
         FROM password_reset_tokens prt
         JOIN users u ON u.id = prt.user_id
         WHERE prt.token_hash = ?
           AND prt.used_at IS NULL
           AND prt.expires_at > NOW()
           AND u.is_active = TRUE
         LIMIT 1",
        [$tokenHash]
    );
    if ($tokenData) {
        $validToken = true;
    }
}

if (!$validToken && $_SERVER['REQUEST_METHOD'] !== 'POST') {
    $error = 'This password reset link is invalid or has expired. Please request a new one.';
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!$auth->verifyCSRFToken($_POST['csrf_token'] ?? '')) {
        $error = 'Invalid request. Please try again.';
    } elseif (!$validToken) {
        $error = 'This password reset link is invalid or has expired.';
    } else {
        $clientIp = $securityMonitor->getClientIp();
        $rateLimitId = 'pw_reset_submit:' . $clientIp;
        $rate = $securityMonitor->registerRequest('pw_reset_submit', $rateLimitId, 10, 300, 600);

        if (!$rate['allowed']) {
            $error = 'Too many attempts. Please try again later.';
        } else {
            $newPassword = $_POST['new_password'] ?? '';
            $confirmPassword = $_POST['confirm_password'] ?? '';

            if (strlen($newPassword) < 8) {
                $error = 'Password must be at least 8 characters long.';
            } elseif ($newPassword !== $confirmPassword) {
                $error = 'Passwords do not match.';
            } else {
                $result = $userManager->updateUser((int)$tokenData['user_id'], ['password' => $newPassword]);

                if ($result['success']) {
                    // Mark token as used (cleanup will remove it on next request)
                    $db->query(
                        "UPDATE password_reset_tokens SET used_at = NOW() WHERE token_hash = ?",
                        [hash('sha256', $rawToken)]
                    );

                    $securityMonitor->logEvent(
                        'password_reset_success',
                        'info',
                        (int)$tokenData['user_id'],
                        'pw_reset:' . $clientIp,
                        ['username' => $tokenData['username']]
                    );

                    $message = 'Your password has been reset. You can now log in with your new password.';
                    $validToken = false;
                    $tokenData = null;
                } else {
                    $error = 'Failed to reset your password. Please try again.';
                }
            }
        }
    }
}

$csrfToken = $auth->generateCSRFToken();
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?php echo SITE_NAME; ?> - Reset Password</title>
    <link rel="stylesheet" href="assets/css/style.css">
</head>
<body class="login-page">
    <div class="login-container white-bg">
        <div class="logo">
            <h1>🔒 <?php echo SITE_NAME; ?></h1>
            <p>Set New Password</p>
        </div>

        <?php if ($error): ?>
            <div class="alert alert-error"><?php echo htmlspecialchars($error); ?></div>
            <div class="back-link">
                <a href="forgot_password.php">← Request a new reset link</a>
            </div>
        <?php endif; ?>

        <?php if ($message): ?>
            <div class="alert alert-success"><?php echo htmlspecialchars($message); ?></div>
            <a href="login.php" class="btn" style="display: block; text-align: center; margin-top: 1.25rem;">Go to Login</a>
        <?php elseif ($validToken): ?>
            <p style="color: var(--color-muted); margin-bottom: 1.25rem; font-size: 0.9rem;">
                Resetting password for: <strong><?php echo htmlspecialchars($tokenData['username']); ?></strong>
            </p>
            <form method="POST">
                <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($csrfToken); ?>">
                <div class="form-group">
                    <label for="new_password">New Password</label>
                    <input type="password" id="new_password" name="new_password" required minlength="8" autofocus>
                    <small style="color: var(--color-muted);">Must be at least 8 characters long.</small>
                </div>
                <div class="form-group">
                    <label for="confirm_password">Confirm New Password</label>
                    <input type="password" id="confirm_password" name="confirm_password" required minlength="8">
                </div>
                <button type="submit" class="btn">Reset Password</button>
            </form>
            <div class="back-link" style="margin-top: 1rem;">
                <a href="login.php">← Back to Login</a>
            </div>
        <?php endif; ?>
    </div>

    <?php include APP_DIR . '/src/views/footer.php'; ?>
</body>
</html>
