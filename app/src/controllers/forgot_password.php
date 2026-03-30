<?php
/**
 * Forgot Password Page
 * Allows registered users to request a password reset link via email.
 */
require_once APP_DIR . '/src/core/config.php';
require_once APP_DIR . '/src/core/db.php';
require_once APP_DIR . '/src/services/auth.php';
require_once APP_DIR . '/src/support/smtp_mailer.php';
require_once APP_DIR . '/src/services/security_monitor.php';

$db = new Database();
$auth = new Auth($db);
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

$smtpMailer = new SMTPMailer($db);
$smtpAvailable = $smtpMailer->isConfigured();

$message = null;
$error = null;

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!$auth->verifyCSRFToken($_POST['csrf_token'] ?? '')) {
        $error = 'Invalid request. Please try again.';
    } elseif (!$smtpAvailable) {
        $error = 'Password reset via email is not available. Please contact your administrator.';
    } else {
        $clientIp = $securityMonitor->getClientIp();
        $rateLimitId = 'pw_reset:' . $clientIp;
        $rate = $securityMonitor->registerRequest('pw_reset', $rateLimitId, 5, 600, 900);

        if (!$rate['allowed']) {
            $error = 'Too many password reset requests. Please try again later.';
        } else {
            $emailInput = strtolower(trim($_POST['email'] ?? ''));

            // Always show success to prevent email enumeration
            $message = 'If that email address is associated with an account, a reset link has been sent.';

            if ($emailInput !== '' && filter_var($emailInput, FILTER_VALIDATE_EMAIL)) {
                // Purge expired tokens globally before inserting a new one
                $db->query("DELETE FROM password_reset_tokens WHERE expires_at < NOW()");

                $user = $db->fetch(
                    "SELECT id, username, email FROM users WHERE LOWER(email) = ? AND is_active = TRUE LIMIT 1",
                    [$emailInput]
                );

                if ($user && filter_var($user['email'], FILTER_VALIDATE_EMAIL)) {
                    // Invalidate any existing tokens for this user
                    $db->query("DELETE FROM password_reset_tokens WHERE user_id = ?", [$user['id']]);

                    $token = bin2hex(random_bytes(32));
                    $tokenHash = hash('sha256', $token);
                    $expiresAt = date('Y-m-d H:i:s', time() + 3600);

                    $saved = $db->query(
                        "INSERT INTO password_reset_tokens (user_id, token_hash, expires_at) VALUES (?, ?, ?)",
                        [$user['id'], $tokenHash, $expiresAt]
                    );

                    if ($saved) {
                        $resetUrl = getBaseUrl() . '/reset_password.php?token=' . urlencode($token);
                        $subject = 'Password Reset — ' . SITE_NAME;
                        $safeSiteName = htmlspecialchars(SITE_NAME);
                        $safeUsername = htmlspecialchars($user['username']);
                        $safeResetUrl = htmlspecialchars($resetUrl);

                        $htmlBody = '<p>Hi <strong>' . $safeUsername . '</strong>,</p>'
                            . '<p>A password reset was requested for your account on <strong>' . $safeSiteName . '</strong>.</p>'
                            . '<p><a href="' . $safeResetUrl . '">Click here to reset your password</a></p>'
                            . '<p>This link expires in 1 hour. If you did not request this, you can safely ignore this email — your password will not change.</p>';

                        $textBody = "Hi {$user['username']},\n\n"
                            . 'A password reset was requested for your account on ' . SITE_NAME . ".\n\n"
                            . "Reset link: {$resetUrl}\n\n"
                            . "This link expires in 1 hour. If you did not request this, you can safely ignore this email.";

                        // Result intentionally not checked to prevent email enumeration
                        $smtpMailer->send($user['email'], $subject, $htmlBody, $textBody);
                    }
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
    <title><?php echo SITE_NAME; ?> - Forgot Password</title>
    <link rel="stylesheet" href="assets/css/style.css">
</head>
<body class="login-page">
    <div class="login-container white-bg">
        <div class="logo">
            <h1>🔒 <?php echo SITE_NAME; ?></h1>
            <p>Password Reset</p>
        </div>

        <?php if ($error): ?>
            <div class="alert alert-error"><?php echo htmlspecialchars($error); ?></div>
        <?php endif; ?>

        <?php if ($message): ?>
            <div class="alert alert-success"><?php echo htmlspecialchars($message); ?></div>
            <div class="back-link">
                <a href="login.php">← Back to Login</a>
            </div>
        <?php elseif (!$smtpAvailable): ?>
            <div class="alert alert-error">
                Password reset via email is not currently available. Please contact your administrator to reset your password.
            </div>
            <div class="back-link">
                <a href="login.php">← Back to Login</a>
            </div>
        <?php else: ?>
            <p style="color: var(--color-muted); margin-bottom: 1.25rem; font-size: 0.9rem;">
                Enter your account email address and we'll send you a link to reset your password.
            </p>
            <form method="POST">
                <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($csrfToken); ?>">
                <div class="form-group">
                    <label for="email">Email Address</label>
                    <input type="email" id="email" name="email" required autofocus>
                </div>
                <button type="submit" class="btn">Send Reset Link</button>
            </form>
            <div class="back-link" style="margin-top: 1rem;">
                <a href="login.php">← Back to Login</a>
            </div>
        <?php endif; ?>
    </div>

    <?php include APP_DIR . '/src/views/footer.php'; ?>
</body>
</html>
