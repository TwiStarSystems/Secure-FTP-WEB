<?php
/**
 * Shared File Download Handler
 * Handles downloads via share tokens (public access)
 */
require_once 'config.php';
require_once 'db.php';
require_once 'share.php';
require_once 'security_monitor.php';

$db = new Database();
$shareManager = new ShareManager($db);
$securityMonitor = new SecurityMonitor($db);
$securityMonitor->cleanupOldData();

$clientIp = $securityMonitor->getClientIp();
$baseIdentifier = 'share:' . $clientIp;

$shareRequestRate = $securityMonitor->registerRequest(
    'share_request',
    $baseIdentifier,
    MAX_SHARE_REQUESTS_WINDOW,
    SHARE_REQUEST_WINDOW_SECONDS,
    SHARE_REQUEST_LOCKOUT_SECONDS
);

if (!$shareRequestRate['allowed']) {
    $securityMonitor->logEvent('share_rate_limited', 'warning', null, $baseIdentifier, [
        'retry_after' => $shareRequestRate['retry_after']
    ]);
    http_response_code(429);
    die('Too many share requests. Please try again later.');
}

$tokenFailureLock = $securityMonitor->getLockStatus('share_token_failure', $baseIdentifier);
if ($tokenFailureLock['locked']) {
    $securityMonitor->logEvent('share_token_lockout_active', 'warning', null, $baseIdentifier, [
        'retry_after' => $tokenFailureLock['retry_after']
    ]);
    http_response_code(429);
    die('Too many invalid share token attempts. Please try again later.');
}

// Get share token from URL
$token = $_GET['token'] ?? null;

if (!$token) {
    $securityMonitor->registerFailure(
        'share_token_failure',
        $baseIdentifier,
        MAX_SHARE_TOKEN_FAILURE_ATTEMPTS,
        SHARE_TOKEN_FAILURE_WINDOW_SECONDS,
        SHARE_TOKEN_FAILURE_LOCKOUT_SECONDS
    );
    $securityMonitor->logEvent('share_missing_token', 'warning', null, $baseIdentifier, []);
    die('Invalid share link.');
}

if (!preg_match('/^[a-f0-9]{64}$/', $token)) {
    $lockState = $securityMonitor->registerFailure(
        'share_token_failure',
        $baseIdentifier,
        MAX_SHARE_TOKEN_FAILURE_ATTEMPTS,
        SHARE_TOKEN_FAILURE_WINDOW_SECONDS,
        SHARE_TOKEN_FAILURE_LOCKOUT_SECONDS
    );
    $securityMonitor->logEvent('share_invalid_token_format', 'warning', null, $baseIdentifier, [
        'token_prefix' => substr($token, 0, 12),
        'locked' => $lockState['locked']
    ]);

    if ($lockState['locked']) {
        http_response_code(429);
        die('Too many invalid share token attempts. Please try again later.');
    }

    die('Invalid share link.');
}

$tokenIdentifier = $baseIdentifier . ':' . substr($token, 0, 16);

$passwordFailureLock = $securityMonitor->getLockStatus('share_password_failure', $tokenIdentifier);
if ($passwordFailureLock['locked']) {
    $securityMonitor->logEvent('share_password_lockout_active', 'warning', null, $tokenIdentifier, [
        'retry_after' => $passwordFailureLock['retry_after']
    ]);
    http_response_code(429);
    die('Too many failed password attempts for this share link. Please try again later.');
}

// Get share details
$share = $shareManager->getShareByToken($token);

if (!$share) {
    $lockState = $securityMonitor->registerFailure(
        'share_token_failure',
        $baseIdentifier,
        MAX_SHARE_TOKEN_FAILURE_ATTEMPTS,
        SHARE_TOKEN_FAILURE_WINDOW_SECONDS,
        SHARE_TOKEN_FAILURE_LOCKOUT_SECONDS
    );
    $securityMonitor->logEvent('share_token_not_found', 'warning', null, $tokenIdentifier, [
        'token_prefix' => substr($token, 0, 16),
        'locked' => $lockState['locked']
    ]);

    if ($lockState['locked']) {
        http_response_code(429);
        die('Too many invalid share token attempts. Please try again later.');
    }

    die('Share link not found or has been removed.');
}

$securityMonitor->clearCounter('share_token_failure', $baseIdentifier);

// Handle password submission
$password = $_POST['password'] ?? null;
$error = null;

// Validate share
$validation = $shareManager->validateShare($share, $password);

// If password required and not provided, show password form
if (!$validation['valid'] && isset($validation['requires_password'])) {
    // Show password form
    ?>
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title><?php echo SITE_NAME; ?> - Password Protected</title>
        <link rel="stylesheet" href="style.css">
    </head>
    <body class="login-page">
        <div class="login-container white-bg">
            <div class="logo">
                <h1>🔒 <?php echo SITE_NAME; ?></h1>
                <p>Password Protected File</p>
            </div>
            
            <?php if ($error): ?>
                <div class="alert alert-error"><?php echo htmlspecialchars($error); ?></div>
            <?php endif; ?>
            
            <div class="file-info-card">
                <h3><?php echo htmlspecialchars($share['original_filename']); ?></h3>
                <p>Size: <?php echo $shareManager->formatBytes($share['file_size']); ?></p>
                <p>Shared by: <?php echo htmlspecialchars($share['shared_by_username']); ?></p>
            </div>
            
            <form method="POST">
                <div class="form-group">
                    <label for="password">Enter Password</label>
                    <input type="password" id="password" name="password" required autofocus>
                </div>
                
                <button type="submit" class="btn">Download</button>
            </form>
            
            <div class="back-link">
                <a href="index.php">Back to Home</a>
            </div>
        </div>
    </body>
    </html>
    <?php
    exit;
}

// If invalid for other reasons, show error
if (!$validation['valid']) {
    if (!empty($validation['error']) && $validation['error'] === 'Invalid password.') {
        $lockState = $securityMonitor->registerFailure(
            'share_password_failure',
            $tokenIdentifier,
            MAX_SHARE_PASSWORD_FAILURE_ATTEMPTS,
            SHARE_PASSWORD_FAILURE_WINDOW_SECONDS,
            SHARE_PASSWORD_FAILURE_LOCKOUT_SECONDS
        );

        $securityMonitor->logEvent('share_password_failed', 'warning', null, $tokenIdentifier, [
            'share_id' => intval($share['id']),
            'locked' => $lockState['locked']
        ]);

        if ($lockState['locked']) {
            http_response_code(429);
            die('Too many failed password attempts for this share link. Please try again later.');
        }
    }

    ?>
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title><?php echo SITE_NAME; ?> - Share Error</title>
        <link rel="stylesheet" href="style.css">
    </head>
    <body class="login-page">
        <div class="login-container white-bg">
            <div class="logo">
                <h1>🔒 <?php echo SITE_NAME; ?></h1>
                <p>Share Link Error</p>
            </div>
            
            <div class="alert alert-error"><?php echo htmlspecialchars($validation['error']); ?></div>
            
            <div class="back-link">
                <a href="index.php">Back to Home</a>
            </div>
        </div>
    </body>
    </html>
    <?php
    exit;
}

// If we get here, share is valid - check if download requested
if (isset($_GET['download']) && $_GET['download'] === '1') {
    $downloadRequestRate = $securityMonitor->registerRequest(
        'share_download_request',
        $tokenIdentifier,
        MAX_DOWNLOAD_REQUESTS_WINDOW,
        DOWNLOAD_REQUEST_WINDOW_SECONDS,
        DOWNLOAD_REQUEST_LOCKOUT_SECONDS
    );

    if (!$downloadRequestRate['allowed']) {
        $securityMonitor->logEvent('share_download_rate_limited', 'warning', null, $tokenIdentifier, [
            'share_id' => intval($share['id']),
            'retry_after' => $downloadRequestRate['retry_after']
        ]);
        http_response_code(429);
        die('Too many download requests for this share link. Please try again later.');
    }

    // Validate filename to prevent path traversal
    if (strpos($share['filename'], '..') !== false || strpos($share['filename'], '/') !== false || strpos($share['filename'], '\\') !== false) {
        $securityMonitor->logEvent('share_download_invalid_filename', 'critical', null, $tokenIdentifier, [
            'share_id' => intval($share['id'])
        ]);
        die('Invalid filename.');
    }
    
    $filepath = UPLOAD_DIR . $share['filename'];
    
    if (!file_exists($filepath) || !is_file($filepath)) {
        $securityMonitor->logEvent('share_download_missing_file', 'warning', null, $tokenIdentifier, [
            'share_id' => intval($share['id']),
            'file_id' => intval($share['file_id'])
        ]);
        die('File not found on disk.');
    }
    
    // Record download for share and file
    $shareManager->recordDownload($share['id']);

    $securityMonitor->clearCounter('share_password_failure', $tokenIdentifier);
    $securityMonitor->logEvent('share_download_success', 'info', null, $tokenIdentifier, [
        'share_id' => intval($share['id']),
        'file_id' => intval($share['file_id'])
    ]);
    
    // Update file download count
    $sql = "UPDATE files SET download_count = download_count + 1 WHERE id = ?";
    $db->query($sql, [$share['file_id']]);
    
    // Sanitize filename to prevent header injection - replace spaces with underscores
    $safeFilename = str_replace(' ', '_', $share['original_filename']);
    $safeFilename = preg_replace('/[^\w\-\.]/', '_', $safeFilename);
    $safeFilename = str_replace(["\r", "\n", "\0"], '', $safeFilename);
    
    // Set headers for file download
    header('Content-Type: ' . $share['mime_type']);
    header('Content-Disposition: attachment; filename="' . $safeFilename . '"');
    header('Content-Length: ' . filesize($filepath));
    header('Cache-Control: no-cache, must-revalidate');
    header('Pragma: public');
    
    // Output file
    readfile($filepath);
    exit;
}

// Show file info and download button
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?php echo SITE_NAME; ?> - Shared File</title>
    <link rel="stylesheet" href="style.css">
</head>
<body class="login-page">
    <div class="login-container white-bg shared-file-page">
        <div class="logo">
            <h1>🔒 <?php echo SITE_NAME; ?></h1>
            <p>Shared File Download</p>
        </div>
        
        <div class="file-info-card">
            <div class="file-icon">📄</div>
            <h3><?php echo htmlspecialchars($share['original_filename']); ?></h3>
            
            <div class="file-details">
                <div class="detail-row">
                    <span class="label">Size:</span>
                    <span class="value"><?php echo $shareManager->formatBytes($share['file_size']); ?></span>
                </div>
                <div class="detail-row">
                    <span class="label">Shared by:</span>
                    <span class="value"><?php echo htmlspecialchars($share['shared_by_username']); ?></span>
                </div>
                <div class="detail-row">
                    <span class="label">Type:</span>
                    <span class="value"><?php echo htmlspecialchars($share['mime_type']); ?></span>
                </div>
                <?php if ($share['file_hash']): ?>
                <div class="detail-row">
                    <span class="label"><?php echo strtoupper($share['hash_algorithm']); ?> Hash:</span>
                    <span class="value hash-value" title="<?php echo htmlspecialchars($share['file_hash']); ?>">
                        <?php echo substr($share['file_hash'], 0, 16); ?>...
                        <button type="button" onclick="copyToClipboard('<?php echo htmlspecialchars($share['file_hash'], ENT_QUOTES); ?>')" class="btn btn-mini" title="Copy full hash">📋</button>
                    </span>
                </div>
                <?php endif; ?>
                <?php if ($share['expires_at']): ?>
                <div class="detail-row">
                    <span class="label">Expires:</span>
                    <span class="value"><?php echo date('M j, Y H:i', strtotime($share['expires_at'])); ?></span>
                </div>
                <?php endif; ?>
                <?php if ($share['max_downloads']): ?>
                <div class="detail-row">
                    <span class="label">Downloads:</span>
                    <span class="value"><?php echo $share['download_count']; ?> / <?php echo $share['max_downloads']; ?></span>
                </div>
                <?php endif; ?>
            </div>
        </div>
        
        <a href="?token=<?php echo htmlspecialchars($token); ?>&download=1" class="btn btn-download">
            ⬇️ Download File
        </a>
        
        <div class="back-link">
            <a href="index.php">Back to Home</a>
        </div>
    </div>
    
    <script>
        function copyToClipboard(text) {
            const textarea = document.createElement('textarea');
            textarea.value = text;
            textarea.style.position = 'fixed';
            textarea.style.opacity = '0';
            document.body.appendChild(textarea);
            textarea.select();
            
            try {
                document.execCommand('copy');
                alert('Hash copied to clipboard!');
            } catch (err) {
                alert('Failed to copy hash');
            }
            
            document.body.removeChild(textarea);
        }
    </script>
    
    <?php include 'footer.php'; ?>
</body>
</html>
