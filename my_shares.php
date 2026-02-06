<?php
/**
 * My Shares Page
 * Allows users to manage their shared file links
 */
require_once 'config.php';
require_once 'db.php';
require_once 'auth.php';
require_once 'share.php';
require_once 'files.php';
require_once 'rbac.php';

$db = new Database();
$auth = new Auth($db);
$shareManager = new ShareManager($db);
$fileManager = new FileManager($db, $auth);

// Require authentication
RBAC::requireAuth();

// Handle logout
if (isset($_GET['action']) && $_GET['action'] === 'logout') {
    $auth->logout();
    header('Location: login.php');
    exit;
}

// Get current user info
$currentUser = $auth->getCurrentUser();
$isAdmin = RBAC::isAdmin();

// Handle actions
$message = null;

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Verify CSRF token
    if (!$auth->verifyCSRFToken($_POST['csrf_token'] ?? '')) {
        $message = ['type' => 'error', 'message' => 'Invalid request.'];
    } else {
        $action = $_POST['action'] ?? '';
        
        // Create new share
        if ($action === 'create_share' && isset($_POST['file_id'])) {
            $options = [
                'is_public' => isset($_POST['is_public']),
                'password' => $_POST['password'] ?? '',
                'expires_at' => !empty($_POST['expires_at']) ? $_POST['expires_at'] : null,
                'max_downloads' => !empty($_POST['max_downloads']) ? (int)$_POST['max_downloads'] : null
            ];
            
            $result = $shareManager->createShare($_POST['file_id'], $currentUser['id'], $options);
            
            if ($result['success']) {
                $message = [
                    'type' => 'success', 
                    'message' => 'Share link created successfully!',
                    'share_url' => $result['share_url']
                ];
            } else {
                $message = ['type' => 'error', 'message' => $result['error']];
            }
        }
        
        // Delete share
        elseif ($action === 'delete_share' && isset($_POST['share_id'])) {
            $result = $shareManager->deleteShare($_POST['share_id'], $currentUser['id']);
            
            if ($result['success']) {
                $message = ['type' => 'success', 'message' => 'Share link deleted successfully!'];
            } else {
                $message = ['type' => 'error', 'message' => $result['error']];
            }
        }
        
        // Toggle share status
        elseif ($action === 'toggle_share' && isset($_POST['share_id'])) {
            $isActive = isset($_POST['is_active']) ? (bool)$_POST['is_active'] : false;
            $result = $shareManager->updateShare($_POST['share_id'], $currentUser['id'], ['is_active' => $isActive]);
            
            if ($result['success']) {
                $message = ['type' => 'success', 'message' => 'Share link updated successfully!'];
            } else {
                $message = ['type' => 'error', 'message' => $result['error']];
            }
        }
    }
}

// Get user's shares
$shares = $isAdmin ? $shareManager->getAllShares() : $shareManager->getUserShares($currentUser['id']);

// Get user's files for the create share form
$files = $fileManager->getFiles();

$csrfToken = $auth->generateCSRFToken();
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?php echo SITE_NAME; ?> - My Shares</title>
    <link rel="stylesheet" href="style.css">
</head>
<body class="simple-page">
    <?php include 'header.php'; ?>
    
    <div class="container">
        <?php if ($message): ?>
            <div class="alert alert-<?php echo $message['type'] === 'success' ? 'success' : 'error'; ?>">
                <?php echo htmlspecialchars($message['message']); ?>
                <?php if (isset($message['share_url'])): ?>
                    <div class="share-url-display">
                        <strong>Share URL:</strong>
                        <input type="text" value="<?php echo htmlspecialchars($message['share_url']); ?>" readonly onclick="this.select();" class="share-url-input">
                        <button type="button" onclick="copyShareUrl(this)" class="btn btn-small">Copy</button>
                    </div>
                <?php endif; ?>
            </div>
        <?php endif; ?>
        
        <div class="card">
            <h2>🔗 Create Share Link</h2>
            <?php if (empty($files)): ?>
                <p>You have no files to share. <a href="index.php">Upload a file first</a>.</p>
            <?php else: ?>
                <form method="POST" class="share-form">
                    <input type="hidden" name="action" value="create_share">
                    <input type="hidden" name="csrf_token" value="<?php echo $csrfToken; ?>">
                    
                    <div class="form-grid">
                        <div class="form-group">
                            <label for="file_id">Select File</label>
                            <select id="file_id" name="file_id" required>
                                <option value="">-- Select a file --</option>
                                <?php foreach ($files as $file): ?>
                                    <option value="<?php echo $file['id']; ?>">
                                        <?php echo htmlspecialchars($file['original_filename']); ?> 
                                        (<?php echo $shareManager->formatBytes($file['file_size']); ?>)
                                    </option>
                                <?php endforeach; ?>
                            </select>
                        </div>
                        
                        <div class="form-group">
                            <label for="password">Password (optional)</label>
                            <input type="password" id="password" name="password" placeholder="Leave empty for no password">
                        </div>
                        
                        <div class="form-group">
                            <label for="expires_at">Expires (optional)</label>
                            <input type="datetime-local" id="expires_at" name="expires_at">
                        </div>
                        
                        <div class="form-group">
                            <label for="max_downloads">Max Downloads (optional)</label>
                            <input type="number" id="max_downloads" name="max_downloads" min="1" placeholder="Unlimited">
                        </div>
                    </div>
                    
                    <div class="checkbox-group">
                        <input type="checkbox" id="is_public" name="is_public" checked>
                        <label for="is_public">Show in public files list (visible to anonymous users)</label>
                    </div>
                    
                    <button type="submit" class="btn">Create Share Link</button>
                </form>
            <?php endif; ?>
        </div>
        
        <div class="card">
            <h2>📋 <?php echo $isAdmin ? 'All Shares' : 'My Shares'; ?></h2>
            <?php if (empty($shares)): ?>
                <p>No share links created yet.</p>
            <?php else: ?>
                <table class="shares-table">
                    <thead>
                        <tr>
                            <th>File</th>
                            <?php if ($isAdmin): ?><th>Shared By</th><?php endif; ?>
                            <th>Status</th>
                            <th>Downloads</th>
                            <th>Created</th>
                            <th>Expires</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($shares as $share): ?>
                            <tr class="<?php echo $share['is_active'] ? '' : 'inactive-row'; ?>">
                                <td>
                                    <div class="file-name-cell">
                                        <?php echo htmlspecialchars($share['original_filename']); ?>
                                        <?php if ($share['password_hash']): ?>
                                            <span class="badge badge-warning" title="Password protected">🔐</span>
                                        <?php endif; ?>
                                        <?php if ($share['is_public']): ?>
                                            <span class="badge badge-info" title="Public">🌐</span>
                                        <?php endif; ?>
                                    </div>
                                </td>
                                <?php if ($isAdmin): ?>
                                    <td><?php echo htmlspecialchars($share['shared_by_username']); ?></td>
                                <?php endif; ?>
                                <td>
                                    <?php 
                                    $expired = $share['expires_at'] && strtotime($share['expires_at']) < time();
                                    $limitReached = $share['max_downloads'] && $share['download_count'] >= $share['max_downloads'];
                                    
                                    if (!$share['is_active']): ?>
                                        <span class="badge badge-danger">Deactivated</span>
                                    <?php elseif ($expired): ?>
                                        <span class="badge badge-danger">Expired</span>
                                    <?php elseif ($limitReached): ?>
                                        <span class="badge badge-warning">Limit Reached</span>
                                    <?php else: ?>
                                        <span class="badge badge-success">Active</span>
                                    <?php endif; ?>
                                </td>
                                <td>
                                    <?php echo $share['download_count']; ?>
                                    <?php if ($share['max_downloads']): ?>
                                        / <?php echo $share['max_downloads']; ?>
                                    <?php endif; ?>
                                </td>
                                <td><?php echo date('M j, Y', strtotime($share['created_at'])); ?></td>
                                <td>
                                    <?php echo $share['expires_at'] ? date('M j, Y H:i', strtotime($share['expires_at'])) : 'Never'; ?>
                                </td>
                                <td class="actions">
                                    <button type="button" onclick="copyToClipboard('<?php echo $shareManager->getShareUrl($share['share_token']); ?>')" class="btn btn-small" title="Copy link">
                                        📋
                                    </button>
                                    <a href="shared.php?token=<?php echo htmlspecialchars($share['share_token']); ?>" class="btn btn-small" title="View" target="_blank">
                                        👁️
                                    </a>
                                    <form method="POST" style="display: inline;" onsubmit="return confirm('Are you sure you want to delete this share link?')">
                                        <input type="hidden" name="action" value="delete_share">
                                        <input type="hidden" name="share_id" value="<?php echo $share['id']; ?>">
                                        <input type="hidden" name="csrf_token" value="<?php echo $csrfToken; ?>">
                                        <button type="submit" class="btn btn-small btn-danger" title="Delete">🗑️</button>
                                    </form>
                                </td>
                            </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            <?php endif; ?>
        </div>
    </div>
    
    <script>
        function copyToClipboard(text) {
            navigator.clipboard.writeText(text).then(function() {
                alert('Link copied to clipboard!');
            }, function(err) {
                // Fallback for older browsers
                const temp = document.createElement('input');
                temp.value = text;
                document.body.appendChild(temp);
                temp.select();
                document.execCommand('copy');
                document.body.removeChild(temp);
                alert('Link copied to clipboard!');
            });
        }
        
        function copyShareUrl(btn) {
            const input = btn.previousElementSibling;
            input.select();
            document.execCommand('copy');
            btn.textContent = 'Copied!';
            setTimeout(() => btn.textContent = 'Copy', 2000);
        }
    </script>
</body>
</html>
