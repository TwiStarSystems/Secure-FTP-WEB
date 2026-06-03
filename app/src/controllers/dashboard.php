<?php
// Main dashboard
require_once APP_DIR . '/src/core/config.php';
require_once APP_DIR . '/src/core/db.php';
require_once APP_DIR . '/src/services/auth.php';
require_once APP_DIR . '/src/services/files.php';
require_once APP_DIR . '/src/services/users.php';
require_once APP_DIR . '/src/services/share.php';
require_once APP_DIR . '/src/support/smtp_mailer.php';
require_once APP_DIR . '/src/services/rbac.php';

$db = new Database();
$auth = new Auth($db);
$fileManager = new FileManager($db, $auth);
$userManager = new UserManager($db);
$shareManager = new ShareManager($db);

/**
 * Validate recipient email format and length for email share flow.
 */
function isValidShareRecipientEmail($email) {
    if (!is_string($email)) {
        return false;
    }

    $email = strtolower(trim($email));
    if ($email === '' || strlen($email) > 191) {
        return false;
    }

    if (preg_match('/[\x00-\x1F\x7F\s]/', $email)) {
        return false;
    }

    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        return false;
    }

    return preg_match('/^[a-z0-9._%+\-]+@[a-z0-9.-]+\.[a-z]{2,63}$/i', $email) === 1;
}

/**
 * Best-effort security audit logging for email share delivery events.
 */
function logEmailShareAudit($db, $eventType, $severity, $userId, $identifier, $context = []) {
    $contextJson = json_encode($context);
    if ($contextJson === false) {
        $contextJson = '{}';
    }

    $db->query(
        "INSERT INTO security_audit_events (event_type, severity, user_id, ip_address, identifier, context_json)
         VALUES (?, ?, ?, ?, ?, ?)",
        [
            $eventType,
            $severity,
            $userId,
            $_SERVER['REMOTE_ADDR'] ?? 'unknown',
            $identifier,
            $contextJson
        ]
    );
}

// Check if logged in - redirect anonymous users to public page
if (!$auth->isLoggedIn()) {
    header('Location: public.php');
    exit;
}

// Handle file processing status check (AJAX polling)
if ($_SERVER['REQUEST_METHOD'] === 'GET' && isset($_GET['action']) && $_GET['action'] === 'processing_status' && isset($_GET['file_id'])) {
    if (!empty($_SERVER['HTTP_X_REQUESTED_WITH']) && strtolower($_SERVER['HTTP_X_REQUESTED_WITH']) === 'xmlhttprequest') {
        header('Content-Type: application/json; charset=utf-8');
        $statusFileId = (int)$_GET['file_id'];
        $status = $fileManager->getFileProcessingStatus($statusFileId);
        if ($status) {
            echo json_encode([
                'file_id'           => (int)$status['id'],
                'processing_status' => $status['processing_status'],
                'processing_error'  => $status['processing_error'],
                'file_hash'         => $status['file_hash'],
                'hash_algorithm'    => $status['hash_algorithm']
            ], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        } else {
            echo json_encode(['error' => 'File not found.']);
        }
        exit;
    }
}

// Handle file upload
$uploadMessage = null;
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'upload') {
    // Verify CSRF token
    if (!$auth->verifyCSRFToken($_POST['csrf_token'])) {
        $uploadMessage = ['type' => 'error', 'message' => 'Invalid request.'];
    } elseif (isset($_FILES['file'])) {
        $hashAlgorithm = $_POST['hash_algorithm'] ?? DEFAULT_HASH_ALGORITHM;
        $result = $fileManager->uploadFile($_FILES['file'], $hashAlgorithm);
        
        if ($result['success']) {
            $uploadMessage = ['type' => 'success', 'message' => 'File uploaded! Processing hash & encryption in background…', 'data' => $result];
        } else {
            $uploadMessage = ['type' => 'error', 'message' => $result['error']];
        }
    }
}

// Handle file deletion
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'delete') {
    // Verify CSRF token
    if (!$auth->verifyCSRFToken($_POST['csrf_token'])) {
        $uploadMessage = ['type' => 'error', 'message' => 'Invalid request.'];
    } elseif (isset($_POST['file_id'])) {
        $result = $fileManager->deleteFile($_POST['file_id']);
        if ($result['success']) {
            header('Location: index.php?deleted=1');
            exit;
        } else {
            $uploadMessage = ['type' => 'error', 'message' => $result['error']];
        }
    }
}

// Handle quick share creation
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'quick_share') {
    // Verify CSRF token
    if (!$auth->verifyCSRFToken($_POST['csrf_token'])) {
        $uploadMessage = ['type' => 'error', 'message' => 'Invalid request.'];
    } elseif (isset($_POST['file_id'])) {
        $currentUser = $auth->getCurrentUser();
        $result = $shareManager->createShare($_POST['file_id'], $currentUser['id'], ['is_public' => false]);
        if ($result['success']) {
            $uploadMessage = ['type' => 'success', 'message' => 'Private share link created!', 'share_url' => $result['share_url']];
        } else {
            $uploadMessage = ['type' => 'error', 'message' => $result['error']];
        }
    }
}

// Handle unshare (delete active share)
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'unshare') {
    // Verify CSRF token
    if (!$auth->verifyCSRFToken($_POST['csrf_token'])) {
        $uploadMessage = ['type' => 'error', 'message' => 'Invalid request.'];
    } elseif (isset($_POST['file_id'])) {
        $currentUser = $auth->getCurrentUser();
        $result = $shareManager->deleteFileShares($_POST['file_id'], $currentUser['id']);
        if ($result['success']) {
            $uploadMessage = ['type' => 'success', 'message' => 'File unshared successfully!'];
        } else {
            $uploadMessage = ['type' => 'error', 'message' => $result['error']];
        }
    }
}

// Handle email share creation and delivery
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'email_share') {
    // Verify CSRF token
    if (!$auth->verifyCSRFToken($_POST['csrf_token'])) {
        $uploadMessage = ['type' => 'error', 'message' => 'Invalid request.'];
    } elseif (isset($_POST['file_id'])) {
        $currentUser = $auth->getCurrentUser();
        $recipientEmailsRaw = trim($_POST['recipient_emails'] ?? '');
        $emailNote = trim($_POST['email_note'] ?? '');

        $recipientParts = preg_split('/[\s,;]+/', $recipientEmailsRaw, -1, PREG_SPLIT_NO_EMPTY);
        $normalizedRecipients = [];
        foreach ($recipientParts as $recipientPart) {
            $email = strtolower(trim($recipientPart));
            if ($email !== '') {
                $normalizedRecipients[] = $email;
            }
        }
        $normalizedRecipients = array_values(array_unique($normalizedRecipients));

        if (empty($normalizedRecipients)) {
            $uploadMessage = ['type' => 'error', 'message' => 'Please provide at least one recipient email address.'];
        } elseif (count($normalizedRecipients) > 10) {
            $uploadMessage = ['type' => 'error', 'message' => 'You can send to up to 10 recipients at once.'];
        } else {
            foreach ($normalizedRecipients as $recipientEmailToValidate) {
                if (!isValidShareRecipientEmail($recipientEmailToValidate)) {
                    $uploadMessage = ['type' => 'error', 'message' => 'Invalid recipient email: ' . $recipientEmailToValidate];
                    break;
                }
            }
        }

        if (!$uploadMessage) {
            $smtpMailer = new SMTPMailer($db);
            if (!$smtpMailer->isConfigured()) {
                $uploadMessage = ['type' => 'error', 'message' => 'SMTP is not configured. Please configure SMTP in Settings before sending email shares.'];
            }
        }

        if (!$uploadMessage) {
            $file = $fileManager->getFile($_POST['file_id']);
            if (!$file || !RBAC::canShareFile($file, $currentUser)) {
                $uploadMessage = ['type' => 'error', 'message' => 'Permission denied or file not found.'];
            }
        }

        if (!$uploadMessage) {
            $sentRecipients = [];
            $failedRecipients = [];
            $firstShareUrl = null;

            foreach ($normalizedRecipients as $recipientEmail) {
                $shareResult = $shareManager->createShare($_POST['file_id'], $currentUser['id'], [
                    'is_public' => false,
                    'recipient_email' => $recipientEmail
                ]);

                if (!$shareResult['success']) {
                    logEmailShareAudit(
                        $db,
                        'email_share_create_failed',
                        'warning',
                        $currentUser['id'] ?? null,
                        'email-share:' . ($currentUser['id'] ?? 'unknown'),
                        [
                            'recipient_email' => $recipientEmail,
                            'file_id' => (int)$_POST['file_id'],
                            'error' => $shareResult['error']
                        ]
                    );
                    $failedRecipients[] = $recipientEmail . ' (' . $shareResult['error'] . ')';
                    continue;
                }

                $shareUrl = $shareResult['recipient_share_url'] ?? $shareResult['share_url'];
                if ($firstShareUrl === null) {
                    $firstShareUrl = $shareUrl;
                }

                $subject = 'Secure file shared with you: ' . $file['original_filename'];

                $safeFilename = htmlspecialchars($file['original_filename']);
                $safeSender = htmlspecialchars($currentUser['username']);
                $safeLink = htmlspecialchars($shareUrl);

                $htmlBody = '<p><strong>' . $safeSender . '</strong> shared a secure file with you.</p>'
                    . '<p><strong>File:</strong> ' . $safeFilename . '</p>'
                    . '<p>This is a recipient-restricted one-time link. It can be used once and should not be forwarded.</p>'
                    . '<p><a href="' . $safeLink . '">Open secure download link</a></p>';

                if ($emailNote !== '') {
                    $htmlBody .= '<p><strong>Message:</strong><br>' . nl2br(htmlspecialchars($emailNote)) . '</p>';
                }

                $textBody = $currentUser['username'] . ' shared a secure file with you.' . "\n"
                    . 'File: ' . $file['original_filename'] . "\n"
                    . 'Recipient-restricted one-time link: ' . $shareUrl;
                if ($emailNote !== '') {
                    $textBody .= "\n\nMessage:\n" . $emailNote;
                }

                $mailResult = $smtpMailer->send($recipientEmail, $subject, $htmlBody, $textBody);
                if (!$mailResult['success']) {
                    // Roll back share if email send fails so stale links are not left behind.
                    $shareManager->deleteShare($shareResult['share_id'], $currentUser['id']);
                    logEmailShareAudit(
                        $db,
                        'email_share_send_failed',
                        'warning',
                        $currentUser['id'] ?? null,
                        'email-share:' . ($currentUser['id'] ?? 'unknown'),
                        [
                            'recipient_email' => $recipientEmail,
                            'file_id' => (int)$_POST['file_id'],
                            'share_id' => (int)$shareResult['share_id'],
                            'error' => $mailResult['error']
                        ]
                    );
                    $failedRecipients[] = $recipientEmail . ' (' . $mailResult['error'] . ')';
                    continue;
                }

                logEmailShareAudit(
                    $db,
                    'email_share_sent',
                    'info',
                    $currentUser['id'] ?? null,
                    'email-share:' . ($currentUser['id'] ?? 'unknown'),
                    [
                        'recipient_email' => $recipientEmail,
                        'file_id' => (int)$_POST['file_id'],
                        'share_id' => (int)$shareResult['share_id']
                    ]
                );

                $sentRecipients[] = $recipientEmail;
            }

            if (!empty($sentRecipients) && empty($failedRecipients)) {
                $uploadMessage = [
                    'type' => 'success',
                    'message' => 'Recipient-restricted share links emailed to ' . count($sentRecipients) . ' recipient(s).',
                    'share_url' => count($sentRecipients) === 1 ? $firstShareUrl : null
                ];
            } elseif (!empty($sentRecipients) && !empty($failedRecipients)) {
                $uploadMessage = [
                    'type' => 'error',
                    'message' => 'Sent to ' . count($sentRecipients) . ' recipient(s), but failed for: ' . implode(', ', $failedRecipients) . '.'
                ];
            } else {
                $uploadMessage = [
                    'type' => 'error',
                    'message' => 'Failed to send email share(s): ' . implode(', ', $failedRecipients)
                ];
            }
        }
    }
}

// Get current user info
$currentUser = $auth->getCurrentUser();
$currentAccessCode = $auth->getCurrentAccessCode();
$isAdmin = RBAC::isAdmin();

// Get files
$files = $fileManager->getFiles();

// Admin: get all files with share status for the overview section
$allFilesWithShares = [];
if ($isAdmin) {
    $allFilesWithShares = $fileManager->getAllFilesWithShareStatus();
}

// Get active shares for each file to show correct button
$fileShares = [];
if ($currentUser) {
    foreach ($files as $file) {
        $shares = $shareManager->getFileShares($file['id']);
        $activeShare = null;
        foreach ($shares as $share) {
            if ($share['is_active'] && 
                (!$share['expires_at'] || strtotime($share['expires_at']) > time()) &&
                ($share['max_downloads'] === null || $share['download_count'] < $share['max_downloads'])) {
                $activeShare = $share;
                break;
            }
        }
        $fileShares[$file['id']] = $activeShare;
    }
}

// Calculate quota info
if ($currentUser) {
    $quotaUsed = $currentUser['used_quota'];
    $quotaTotal = $currentUser['upload_quota'];
    $quotaPercent = $quotaTotal > 0 ? ($quotaUsed / $quotaTotal) * 100 : 0;
} elseif ($currentAccessCode) {
    $quotaUsed = $currentAccessCode['used_quota'];
    $quotaTotal = $currentAccessCode['upload_quota'];
    $quotaPercent = $quotaTotal > 0 ? ($quotaUsed / $quotaTotal) * 100 : 0;
}

$csrfToken = $auth->generateCSRFToken();

// AJAX upload: return JSON instead of rendering the full page
if (
    $uploadMessage !== null
    && !empty($_SERVER['HTTP_X_REQUESTED_WITH'])
    && strtolower($_SERVER['HTTP_X_REQUESTED_WITH']) === 'xmlhttprequest'
) {
    // Include a fresh CSRF token so the client can update the hidden field
    $uploadMessage['csrf_token'] = $auth->generateCSRFToken();
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode($uploadMessage, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    exit;
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?php echo SITE_NAME; ?> - Dashboard</title>
    <link rel="stylesheet" href="assets/css/style.css">
</head>
<body class="simple-page">
    <?php include APP_DIR . '/src/views/header.php'; ?>
    
    <div class="container">
        <?php if (isset($_GET['deleted'])): ?>
            <div class="alert alert-success">File deleted successfully!</div>
        <?php endif; ?>
        
        <?php if ($uploadMessage): ?>
            <div class="alert alert-<?php echo $uploadMessage['type'] === 'success' ? 'success' : 'error'; ?>">
                <?php echo htmlspecialchars($uploadMessage['message']); ?>
                <?php if ($uploadMessage['type'] === 'success' && isset($uploadMessage['data'])): ?>
                    <?php if (!empty($uploadMessage['data']['processing'])): ?>
                        <div class="hash-info" id="processing-info-<?php echo (int)$uploadMessage['data']['file_id']; ?>">
                            <em>Hashing &amp; encryption in progress…</em>
                        </div>
                    <?php elseif (!empty($uploadMessage['data']['file_hash'])): ?>
                        <div class="hash-info">
                            <strong>File Hash (<?php echo strtoupper($uploadMessage['data']['hash_algorithm']); ?>):</strong><br>
                            <span id="upload-hash"><?php echo htmlspecialchars($uploadMessage['data']['file_hash']); ?></span>
                            <button type="button" onclick="copyHash('upload-hash')" class="btn btn-small" style="margin-left: 10px;">Copy</button>
                        </div>
                    <?php endif; ?>
                <?php endif; ?>
                <?php if (!empty($uploadMessage['duplicate']) && isset($uploadMessage['existing_file_id'])): ?>
                    <div style="margin-top:0.5rem;">
                        <a href="download.php?id=<?php echo (int)$uploadMessage['existing_file_id']; ?>" class="btn btn-small">Download existing file</a>
                    </div>
                <?php endif; ?>
                <?php if (isset($uploadMessage['share_url'])): ?>
                    <div class="share-url-display">
                        <strong>Share URL:</strong>
                        <input type="text" value="<?php echo htmlspecialchars($uploadMessage['share_url']); ?>" readonly onclick="this.select();" class="share-url-input">
                        <button type="button" onclick="copyShareUrl(this)" class="btn btn-small">Copy</button>
                    </div>
                <?php endif; ?>
            </div>
        <?php endif; ?>
        
        <div class="card">
            <h2>Storage Quota</h2>
            <div class="quota-info">
                <strong><?php echo $fileManager->formatBytes($quotaUsed); ?></strong> of 
                <strong><?php echo $fileManager->formatBytes($quotaTotal); ?></strong> used 
                (<?php echo number_format($quotaPercent, 1); ?>%)
            </div>
            <div class="quota-bar">
                <div class="quota-bar-fill" style="width: <?php echo min($quotaPercent, 100); ?>%"></div>
            </div>
        </div>
        
        <div class="card">
            <h2>Upload File</h2>
            <form method="POST" enctype="multipart/form-data" class="upload-form">
                <input type="hidden" name="action" value="upload">
                <input type="hidden" name="csrf_token" value="<?php echo $csrfToken; ?>">
                
                <div class="form-group">
                    <label for="file">Select File (Max <?php echo $fileManager->formatBytes(MAX_FILE_SIZE); ?>)</label>
                    <input type="file" id="file" name="file" required>
                </div>
                
                <div class="form-group">
                    <label for="hash_algorithm">Hash Algorithm for Integrity Verification</label>
                    <select id="hash_algorithm" name="hash_algorithm">
                        <?php foreach (HASH_ALGORITHMS as $algo): ?>
                            <option value="<?php echo $algo; ?>" <?php echo $algo === DEFAULT_HASH_ALGORITHM ? 'selected' : ''; ?>>
                                <?php echo strtoupper($algo); ?>
                            </option>
                        <?php endforeach; ?>
                    </select>
                </div>
                
                <button type="submit" class="btn" id="upload-submit-btn">Upload File</button>
                <div id="upload-progress-wrapper" style="display:none; margin-top:1rem;">
                    <div style="background:var(--color-border,#333); border-radius:4px; overflow:hidden; height:1.25rem;">
                        <div id="upload-progress-fill" style="height:100%; width:0%; background:var(--color-accent,#00bcd4); transition:width 0.2s ease;"></div>
                    </div>
                    <small id="upload-progress-label" style="display:block; margin-top:0.4rem; color:var(--color-muted);">Uploading…</small>
                </div>
            </form>
        </div>
        
        <div class="card">
            <h2>My Files</h2>
            <?php if (empty($files)): ?>
                <p>No files uploaded yet.</p>
            <?php else: ?>
                <div class="table-container">
                    <table>
                        <thead>
                            <tr>
                                <th>Filename</th>
                                <?php if ($isAdmin): ?><th>Owner</th><?php endif; ?>
                                <th>Size</th>
                                <th>Hash</th>
                                <th>Uploaded</th>
                                <th>Downloads</th>
                                <th>Actions</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php foreach ($files as $file): ?>
                                <?php $isProcessing = isset($file['processing_status']) && in_array($file['processing_status'], ['pending', 'processing']); ?>
                                <?php $isFailed = isset($file['processing_status']) && $file['processing_status'] === 'failed'; ?>
                                <tr data-file-id="<?php echo (int)$file['id']; ?>" data-processing="<?php echo $isProcessing ? '1' : '0'; ?>">
                                    <td><?php echo htmlspecialchars($file['original_filename']); ?></td>
                                    <?php if ($isAdmin): ?>
                                        <td><?php echo isset($file['uploaded_by_username']) ? htmlspecialchars($file['uploaded_by_username']) : 'N/A'; ?></td>
                                    <?php endif; ?>
                                    <td><?php echo $fileManager->formatBytes($file['file_size']); ?></td>
                                    <td class="file-hash" title="<?php echo htmlspecialchars($file['file_hash'] ?? ''); ?>">
                                        <?php if ($isProcessing): ?>
                                            <span class="processing-badge" style="color:var(--color-accent,#00bcd4);">⏳ Processing…</span>
                                        <?php elseif ($isFailed): ?>
                                            <span class="processing-badge" style="color:var(--color-wine-red,#c00);" title="<?php echo htmlspecialchars($file['processing_error'] ?? ''); ?>">⚠ Failed</span>
                                        <?php else: ?>
                                            <span class="hash-short"><small class="text-muted"><?php echo strtoupper($file['hash_algorithm'] ?? DEFAULT_HASH_ALGORITHM); ?>:</small> <?php echo substr($file['file_hash'], 0, 16); ?>...</span>
                                            <button type="button" onclick="copyToClipboard('<?php echo htmlspecialchars($file['file_hash'], ENT_QUOTES); ?>')" class="btn btn-mini" title="Copy full hash">📋</button>
                                        <?php endif; ?>
                                    </td>
                                    <td><?php echo date('Y-m-d H:i', strtotime($file['upload_date'])); ?></td>
                                    <td><?php echo $file['download_count']; ?></td>
                                    <td class="actions">
                                        <a href="download.php?id=<?php echo $file['id']; ?>" class="btn btn-small">Download</a>
                                        <?php if ($currentUser && RBAC::canShareFile($file, $currentUser)): ?>
                                            <?php if (isset($fileShares[$file['id']]) && $fileShares[$file['id']]): ?>
                                                <form method="POST" style="display: inline;" onsubmit="return confirm('Are you sure you want to remove all share links for this file?')">
                                                    <input type="hidden" name="action" value="unshare">
                                                    <input type="hidden" name="file_id" value="<?php echo $file['id']; ?>">
                                                    <input type="hidden" name="csrf_token" value="<?php echo $csrfToken; ?>">
                                                    <button type="submit" class="btn btn-small btn-warning" title="Remove share links">Unshare</button>
                                                </form>
                                            <?php else: ?>
                                                <form method="POST" style="display: inline;">
                                                    <input type="hidden" name="action" value="quick_share">
                                                    <input type="hidden" name="file_id" value="<?php echo $file['id']; ?>">
                                                    <input type="hidden" name="csrf_token" value="<?php echo $csrfToken; ?>">
                                                    <button type="submit" class="btn btn-small btn-share" title="Create share link">Share</button>
                                                </form>
                                            <?php endif; ?>
                                            <button
                                                type="button"
                                                class="btn btn-small"
                                                title="Email recipient-restricted link"
                                                onclick="openEmailShareModal(<?php echo (int)$file['id']; ?>, '<?php echo htmlspecialchars($file['original_filename'], ENT_QUOTES); ?>')"
                                            >Email</button>
                                        <?php endif; ?>
                                        <?php if ($currentUser && RBAC::canDeleteFile($file, $currentUser)): ?>
                                            <form method="POST" style="display: inline;" onsubmit="return confirm('Are you sure you want to delete this file?')">
                                                <input type="hidden" name="action" value="delete">
                                                <input type="hidden" name="file_id" value="<?php echo $file['id']; ?>">
                                                <input type="hidden" name="csrf_token" value="<?php echo $csrfToken; ?>">
                                                <button type="submit" class="btn btn-small btn-danger">Delete</button>
                                            </form>
                                        <?php endif; ?>
                                    </td>
                                </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                </div>
            <?php endif; ?>
        </div>

        <?php if ($isAdmin): ?>
        <div class="card">
            <h2>All Uploaded Files</h2>
            <?php if (empty($allFilesWithShares)): ?>
                <p>No files uploaded yet.</p>
            <?php else: ?>
            <div class="table-container">
                <table>
                    <thead>
                        <tr>
                            <th>Filename</th>
                            <th>Owner</th>
                            <th>Size</th>
                            <th>Hash</th>
                            <th>Uploaded</th>
                            <th>Downloads</th>
                            <th>Share Status</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($allFilesWithShares as $af): ?>
                            <?php $afProcessing = isset($af['processing_status']) && in_array($af['processing_status'], ['pending', 'processing']); ?>
                            <?php $afFailed = isset($af['processing_status']) && $af['processing_status'] === 'failed'; ?>
                            <tr data-file-id="<?php echo (int)$af['id']; ?>" data-processing="<?php echo $afProcessing ? '1' : '0'; ?>">
                                <td><?php echo htmlspecialchars($af['original_filename']); ?></td>
                                <td><?php echo isset($af['uploaded_by_username']) ? htmlspecialchars($af['uploaded_by_username']) : 'Access Code'; ?></td>
                                <td><?php echo $fileManager->formatBytes($af['file_size']); ?></td>
                                <td class="file-hash" title="<?php echo htmlspecialchars($af['file_hash'] ?? ''); ?>">
                                    <?php if ($afProcessing): ?>
                                        <span class="processing-badge" style="color:var(--color-accent,#00bcd4);">⏳ Processing…</span>
                                    <?php elseif ($afFailed): ?>
                                        <span class="processing-badge" style="color:var(--color-wine-red,#c00);" title="<?php echo htmlspecialchars($af['processing_error'] ?? ''); ?>">⚠ Failed</span>
                                    <?php elseif ($af['file_hash']): ?>
                                        <span class="hash-short"><small class="text-muted"><?php echo strtoupper($af['hash_algorithm'] ?? DEFAULT_HASH_ALGORITHM); ?>:</small> <?php echo substr($af['file_hash'], 0, 16); ?>…</span>
                                        <button type="button" onclick="copyToClipboard('<?php echo htmlspecialchars($af['file_hash'], ENT_QUOTES); ?>')" class="btn btn-mini" title="Copy full hash">📋</button>
                                    <?php else: ?>
                                        <span class="text-muted">—</span>
                                    <?php endif; ?>
                                </td>
                                <td><?php echo date('Y-m-d H:i', strtotime($af['upload_date'])); ?></td>
                                <td><?php echo $af['download_count']; ?></td>
                                <td>
                                    <?php
                                        $activeShares = (int)$af['active_shares'];
                                        $publicShares = (int)$af['public_shares'];
                                        $privateShares = $activeShares - $publicShares;
                                    ?>
                                    <?php if ($activeShares === 0): ?>
                                        <span class="text-muted">Not shared</span>
                                    <?php else: ?>
                                        <?php if ($publicShares > 0): ?>
                                            <span style="color:var(--color-accent,#00bcd4);">🌐 <?php echo $publicShares; ?> public</span>
                                        <?php endif; ?>
                                        <?php if ($privateShares > 0): ?>
                                            <span style="color:var(--color-sparkle-purple,#9600e1);">🔒 <?php echo $privateShares; ?> private</span>
                                        <?php endif; ?>
                                    <?php endif; ?>
                                </td>
                                <td class="actions">
                                    <a href="download.php?id=<?php echo $af['id']; ?>" class="btn btn-small">Download</a>
                                    <?php if (RBAC::canDeleteFile($af, $currentUser)): ?>
                                        <form method="POST" style="display: inline;" onsubmit="return confirm('Are you sure you want to delete this file?')">
                                            <input type="hidden" name="action" value="delete">
                                            <input type="hidden" name="file_id" value="<?php echo $af['id']; ?>">
                                            <input type="hidden" name="csrf_token" value="<?php echo $csrfToken; ?>">
                                            <button type="submit" class="btn btn-small btn-danger">Delete</button>
                                        </form>
                                    <?php endif; ?>
                                </td>
                            </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            </div>
            <?php endif; ?>
        </div>
        <?php endif; ?>

    </div>

    <div id="emailShareModal" class="modal" style="display: none;">
        <div class="modal-content">
            <div class="modal-header">
                <h3>📧 Email Secure Share Link</h3>
                <button type="button" onclick="closeEmailShareModal()" class="btn-close">&times;</button>
            </div>
            <form method="POST">
                <input type="hidden" name="action" value="email_share">
                <input type="hidden" name="csrf_token" value="<?php echo $csrfToken; ?>">
                <input type="hidden" name="file_id" id="emailShareFileId" value="">

                <div class="form-group">
                    <label>File</label>
                    <div id="emailShareFilename" class="hash-display"></div>
                </div>

                <div class="form-group">
                    <label for="recipient_emails">Recipient Emails</label>
                    <textarea id="recipient_emails" name="recipient_emails" rows="3" required placeholder="recipient1@example.com, recipient2@example.com"></textarea>
                    <small class="text-muted">Use commas, spaces, or new lines. Up to 10 recipients.</small>
                </div>

                <div class="form-group">
                    <label for="email_note">Message (optional)</label>
                    <textarea id="email_note" name="email_note" rows="3" placeholder="Add a short message..."></textarea>
                </div>

                <small class="text-muted">This sends a recipient-restricted one-time link that is not listed publicly.</small>

                <div class="modal-actions">
                    <button type="button" onclick="closeEmailShareModal()" class="btn btn-secondary">Cancel</button>
                    <button type="submit" class="btn">Send Email</button>
                </div>
            </form>
        </div>
    </div>
    
    <script>
        function copyShareUrl(btn) {
            const input = btn.previousElementSibling;
            input.select();
            document.execCommand('copy');
            btn.textContent = 'Copied!';
            setTimeout(() => btn.textContent = 'Copy', 2000);
        }
        
        function copyToClipboard(text) {
            if (navigator.clipboard && window.isSecureContext) {
                navigator.clipboard.writeText(text).then(function() {
                    const btn = document.activeElement;
                    if (btn && btn !== document.body) {
                        const orig = btn.textContent;
                        btn.textContent = 'Copied!';
                        setTimeout(function() { btn.textContent = orig; }, 1500);
                    }
                }).catch(function() { _clipboardFallback(text); });
            } else {
                _clipboardFallback(text);
            }
        }

        function _clipboardFallback(text) {
            const ta = document.createElement('textarea');
            ta.value = text;
            ta.style.cssText = 'position:fixed;opacity:0;';
            document.body.appendChild(ta);
            ta.select();
            try { document.execCommand('copy'); } catch(e) {}
            document.body.removeChild(ta);
        }
        
        function copyHash(elementId) {
            const element = document.getElementById(elementId);
            if (element) {
                copyToClipboard(element.textContent);
            }
        }

        function openEmailShareModal(fileId, filename) {
            const modal = document.getElementById('emailShareModal');
            const fileIdInput = document.getElementById('emailShareFileId');
            const fileNameDisplay = document.getElementById('emailShareFilename');
            const recipientInput = document.getElementById('recipient_emails');
            const noteInput = document.getElementById('email_note');

            fileIdInput.value = fileId;
            fileNameDisplay.textContent = filename;
            recipientInput.value = '';
            noteInput.value = '';

            modal.style.display = 'flex';
            recipientInput.focus();
        }

        function closeEmailShareModal() {
            const modal = document.getElementById('emailShareModal');
            modal.style.display = 'none';
        }

        window.addEventListener('click', function(event) {
            const modal = document.getElementById('emailShareModal');
            if (event.target === modal) {
                closeEmailShareModal();
            }
        });

        // XHR upload with progress bar
        (function() {
            var form = document.querySelector('.upload-form');
            if (!form) return;

            form.addEventListener('submit', function(e) {
                e.preventDefault();

                var wrapper = document.getElementById('upload-progress-wrapper');
                var fill    = document.getElementById('upload-progress-fill');
                var label   = document.getElementById('upload-progress-label');
                var btn     = document.getElementById('upload-submit-btn');

                wrapper.style.display = 'block';
                btn.disabled = true;
                fill.style.width = '0%';
                label.textContent = 'Starting upload\u2026';

                var xhr = new XMLHttpRequest();

                xhr.upload.addEventListener('progress', function(e) {
                    if (e.lengthComputable) {
                        var pct = Math.round(e.loaded / e.total * 100);
                        fill.style.width = pct + '%';
                        if (pct >= 100) {
                            label.textContent = 'Saving file\u2026';
                        } else {
                            label.textContent = 'Uploading\u2026 ' + pct + '%  (' + fmtBytes(e.loaded) + ' / ' + fmtBytes(e.total) + ')';
                        }
                    }
                });

                xhr.addEventListener('load', function() {
                    wrapper.style.display = 'none';
                    btn.disabled = false;
                    if (xhr.status === 200) {
                        try {
                            var res = JSON.parse(xhr.responseText);
                            // Refresh CSRF token in all forms on the page
                            if (res.csrf_token) {
                                document.querySelectorAll('input[name="csrf_token"]').forEach(function(el) {
                                    el.value = res.csrf_token;
                                });
                            }
                            showUploadAlert(res);
                        } catch(err) {
                            location.reload();
                        }
                    } else {
                        showUploadAlert({type:'error', message:'Upload failed (HTTP ' + xhr.status + '). Please try again.'});
                    }
                });

                xhr.addEventListener('error', function() {
                    wrapper.style.display = 'none';
                    btn.disabled = false;
                    showUploadAlert({type:'error', message:'Network error during upload. Please try again.'});
                });

                xhr.addEventListener('abort', function() {
                    wrapper.style.display = 'none';
                    btn.disabled = false;
                });

                xhr.open('POST', 'index.php');
                xhr.setRequestHeader('X-Requested-With', 'XMLHttpRequest');
                xhr.send(new FormData(form));
            });

            function showUploadAlert(res) {
                var existing = document.getElementById('xhr-upload-alert');
                if (existing) existing.remove();

                var div = document.createElement('div');
                div.id = 'xhr-upload-alert';
                div.className = 'alert alert-' + (res.type === 'success' ? 'success' : 'error');

                var html = esc(res.message || '');

                if (res.type === 'success' && res.data && res.data.processing) {
                    html += '<div class="hash-info" id="xhr-processing-info"><em>\u23F3 Hashing &amp; encryption in progress\u2026</em></div>';
                } else if (res.type === 'success' && res.data && res.data.file_hash) {
                    html += '<div class="hash-info"><strong>File Hash (' + esc(res.data.hash_algorithm.toUpperCase()) + '):</strong><br>'
                        + '<span id="xhr-upload-hash">' + esc(res.data.file_hash) + '</span>'
                        + '<button type="button" onclick="copyHash(\'xhr-upload-hash\')" class="btn btn-small" style="margin-left:10px">Copy</button></div>';
                }

                if (res.share_url) {
                    html += '<div class="share-url-display"><strong>Share URL:</strong>'
                        + '<input type="text" value="' + esc(res.share_url) + '" readonly onclick="this.select();" class="share-url-input">'
                        + '<button type="button" onclick="copyShareUrl(this)" class="btn btn-small">Copy</button></div>';
                }

                if (res.duplicate && res.existing_file_id) {
                    html += '<div style="margin-top:0.5rem;"><a href="download.php?id=' + encodeURIComponent(res.existing_file_id) + '" class="btn btn-small">Download existing file</a></div>';
                }

                div.innerHTML = html;

                var container = document.querySelector('.container');
                var firstCard = container && container.querySelector('.card');
                if (firstCard) {
                    container.insertBefore(div, firstCard);
                } else if (container) {
                    container.prepend(div);
                }

                div.scrollIntoView({behavior:'smooth', block:'nearest'});

                if (res.type === 'success' && res.data && res.data.processing && res.data.file_id) {
                    pollProcessingStatus(res.data.file_id);
                } else if (res.type === 'success') {
                    setTimeout(function() { location.reload(); }, 1800);
                }
            }

            function fmtBytes(b) {
                if (b < 1024) return b + ' B';
                if (b < 1048576) return (b/1024).toFixed(1) + ' KB';
                if (b < 1073741824) return (b/1048576).toFixed(1) + ' MB';
                return (b/1073741824).toFixed(2) + ' GB';
            }

            function esc(s) {
                return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
            }

            /**
             * Poll the server for a file's processing status.
             * When finished (ready or failed), update the alert and reload the file table.
             */
            function pollProcessingStatus(fileId) {
                var interval = setInterval(function() {
                    var req = new XMLHttpRequest();
                    req.open('GET', 'index.php?action=processing_status&file_id=' + encodeURIComponent(fileId));
                    req.setRequestHeader('X-Requested-With', 'XMLHttpRequest');
                    req.onload = function() {
                        if (req.status !== 200) return;
                        try {
                            var data = JSON.parse(req.responseText);
                        } catch(e) { return; }

                        if (data.processing_status === 'ready') {
                            clearInterval(interval);
                            // Update the alert with the hash
                            var info = document.getElementById('xhr-processing-info');
                            if (info) {
                                info.innerHTML = '<strong>File Hash (' + esc((data.hash_algorithm || '').toUpperCase()) + '):</strong><br>'
                                    + '<span id="xhr-upload-hash">' + esc(data.file_hash || '') + '</span>'
                                    + '<button type="button" onclick="copyHash(\'xhr-upload-hash\')" class="btn btn-small" style="margin-left:10px">Copy</button>';
                            }
                            // Refresh table rows
                            setTimeout(function() { location.reload(); }, 1200);
                        } else if (data.processing_status === 'failed') {
                            clearInterval(interval);
                            var info = document.getElementById('xhr-processing-info');
                            if (info) {
                                info.innerHTML = '<span style="color:var(--color-wine-red,#c00);">\u26A0 ' + esc(data.processing_error || 'Processing failed.') + '</span>';
                            }
                            setTimeout(function() { location.reload(); }, 2500);
                        }
                    };
                    req.send();
                }, 2000);
            }

            // Auto-poll for any files currently shown as processing in the table
            (function() {
                var rows = document.querySelectorAll('tr[data-processing="1"]');
                rows.forEach(function(row) {
                    var fileId = row.getAttribute('data-file-id');
                    if (fileId) {
                        var interval = setInterval(function() {
                            var req = new XMLHttpRequest();
                            req.open('GET', 'index.php?action=processing_status&file_id=' + encodeURIComponent(fileId));
                            req.setRequestHeader('X-Requested-With', 'XMLHttpRequest');
                            req.onload = function() {
                                if (req.status !== 200) return;
                                try { var data = JSON.parse(req.responseText); } catch(e) { return; }
                                if (data.processing_status === 'ready' || data.processing_status === 'failed') {
                                    clearInterval(interval);
                                    location.reload();
                                }
                            };
                            req.send();
                        }, 3000);
                    }
                });
            }());
        }());
    </script>
    
    <?php include APP_DIR . '/src/views/footer.php'; ?>
</body>
</html>
