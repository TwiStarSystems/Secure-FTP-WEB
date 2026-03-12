<?php
// Main dashboard
require_once 'config.php';
require_once 'db.php';
require_once 'auth.php';
require_once 'files.php';
require_once 'users.php';
require_once 'share.php';
require_once 'smtp_mailer.php';
require_once 'rbac.php';

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
            $uploadMessage = ['type' => 'success', 'message' => 'File uploaded successfully!', 'data' => $result];
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
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?php echo SITE_NAME; ?> - Dashboard</title>
    <link rel="stylesheet" href="style.css">
</head>
<body class="simple-page">
    <?php include 'header.php'; ?>
    
    <div class="container">
        <?php if (isset($_GET['deleted'])): ?>
            <div class="alert alert-success">File deleted successfully!</div>
        <?php endif; ?>
        
        <?php if ($uploadMessage): ?>
            <div class="alert alert-<?php echo $uploadMessage['type'] === 'success' ? 'success' : 'error'; ?>">
                <?php echo htmlspecialchars($uploadMessage['message']); ?>
                <?php if ($uploadMessage['type'] === 'success' && isset($uploadMessage['data'])): ?>
                    <div class="hash-info">
                        <strong>File Hash (<?php echo strtoupper($uploadMessage['data']['hash_algorithm']); ?>):</strong><br>
                        <span id="upload-hash"><?php echo htmlspecialchars($uploadMessage['data']['file_hash']); ?></span>
                        <button type="button" onclick="copyHash('upload-hash')" class="btn btn-small" style="margin-left: 10px;">Copy</button>
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
                
                <button type="submit" class="btn">Upload File</button>
            </form>
        </div>
        
        <div class="card">
            <h2>My Files</h2>
            <?php if (empty($files)): ?>
                <p>No files uploaded yet.</p>
            <?php else: ?>
                <table>
                    <thead>
                        <tr>
                            <th>Filename</th>
                            <?php if ($isAdmin): ?><th>Owner</th><?php endif; ?>
                            <th>Size</th>
                            <th>Hash (<?php echo strtoupper(DEFAULT_HASH_ALGORITHM); ?>)</th>
                            <th>Uploaded</th>
                            <th>Downloads</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($files as $file): ?>
                            <tr>
                                <td><?php echo htmlspecialchars($file['original_filename']); ?></td>
                                <?php if ($isAdmin): ?>
                                    <td><?php echo isset($file['uploaded_by_username']) ? htmlspecialchars($file['uploaded_by_username']) : 'N/A'; ?></td>
                                <?php endif; ?>
                                <td><?php echo $fileManager->formatBytes($file['file_size']); ?></td>
                                <td class="file-hash" title="<?php echo htmlspecialchars($file['file_hash']); ?>">
                                    <span class="hash-short"><?php echo substr($file['file_hash'], 0, 16); ?>...</span>
                                    <button type="button" onclick="copyToClipboard('<?php echo htmlspecialchars($file['file_hash'], ENT_QUOTES); ?>')" class="btn btn-mini" title="Copy full hash">📋</button>
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
            <?php endif; ?>
        </div>
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
            // Create temporary textarea to copy text
            const textarea = document.createElement('textarea');
            textarea.value = text;
            textarea.style.position = 'fixed';
            textarea.style.opacity = '0';
            document.body.appendChild(textarea);
            textarea.select();
            
            try {
                document.execCommand('copy');
                // Show brief confirmation
                alert('Hash copied to clipboard!');
            } catch (err) {
                alert('Failed to copy hash');
            }
            
            document.body.removeChild(textarea);
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
    </script>
    
    <?php include 'footer.php'; ?>
</body>
</html>
