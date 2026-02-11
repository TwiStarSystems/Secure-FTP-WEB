<?php
// Settings page (User & Admin Settings)
require_once 'config.php';
require_once 'db.php';
require_once 'auth.php';
require_once 'users.php';
require_once 'files.php';
require_once 'rbac.php';

$db = new Database();
$auth = new Auth($db);
$userManager = new UserManager($db);
$fileManager = new FileManager($db, $auth);

// Check if logged in
if (!$auth->isLoggedIn()) {
    header('Location: login.php');
    exit;
}

// Handle logout
if (isset($_GET['action']) && $_GET['action'] === 'logout') {
    $auth->logout();
    header('Location: login.php');
    exit;
}

// Get current user info
$currentUser = $auth->getCurrentUser();
$accessCode = $auth->getCurrentAccessCode();
$isAdmin = RBAC::isAdmin();

$message = null;

// Handle application settings updates (Admin only)
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $isAdmin) {
    if (!$auth->verifyCSRFToken($_POST['csrf_token'])) {
        $message = ['type' => 'error', 'message' => 'Invalid request.'];
    } else {
        if ($_POST['action'] === 'update_base_url') {
            $baseUrl = trim($_POST['base_url']);
            
            // Validate base URL format
            if (!empty($baseUrl)) {
                // Remove trailing slash
                $baseUrl = rtrim($baseUrl, '/');
                
                // Validate URL format
                if (!filter_var($baseUrl, FILTER_VALIDATE_URL)) {
                    $message = ['type' => 'error', 'message' => 'Invalid URL format. Please use format: https://example.com'];
                } else {
                    // Save to database
                    $sql = "INSERT INTO app_settings (setting_key, setting_value, setting_type, description, updated_by) 
                            VALUES (?, ?, ?, ?, ?)
                            ON DUPLICATE KEY UPDATE 
                            setting_value = VALUES(setting_value),
                            updated_at = CURRENT_TIMESTAMP,
                            updated_by = VALUES(updated_by)";
                    
                    $result = $db->query($sql, [
                        'base_url',
                        $baseUrl,
                        'string',
                        'Custom base URL for link generation',
                        $_SESSION['user_id']
                    ]);
                    
                    if ($result) {
                        $message = ['type' => 'success', 'message' => 'Base URL updated successfully!'];
                    } else {
                        $message = ['type' => 'error', 'message' => 'Failed to update base URL.'];
                    }
                }
            } else {
                // Empty = use auto-detection, delete setting
                $sql = "DELETE FROM app_settings WHERE setting_key = ?";
                $db->query($sql, ['base_url']);
                $message = ['type' => 'success', 'message' => 'Base URL cleared. Using auto-detection.'];
            }
        } elseif ($_POST['action'] === 'create_user') {
            $isTemporary = isset($_POST['is_temporary']);
            $expiryDate = $isTemporary && !empty($_POST['expiry_date']) ? $_POST['expiry_date'] : null;
            $role = $_POST['role'] ?? 'user';
            
            // Convert MB to bytes
            $uploadQuotaMB = floatval($_POST['upload_quota']);
            $uploadQuotaBytes = intval($uploadQuotaMB * 1024 * 1024);
            
            $result = $userManager->createUser(
                $_POST['username'],
                $_POST['password'],
                $_POST['email'],
                $role,
                $uploadQuotaBytes,
                $isTemporary,
                $expiryDate
            );
            
            if ($result['success']) {
                $message = ['type' => 'success', 'message' => 'User created successfully!'];
            } else {
                $message = ['type' => 'error', 'message' => $result['error']];
            }
        } elseif ($_POST['action'] === 'create_access_code') {
            $expiryDate = !empty($_POST['expiry_date']) ? $_POST['expiry_date'] : null;
            
            // Convert MB to bytes
            $uploadQuotaMB = floatval($_POST['upload_quota']);
            $uploadQuotaBytes = intval($uploadQuotaMB * 1024 * 1024);
            
            $result = $userManager->createAccessCode(
                intval($_POST['max_uses']),
                $uploadQuotaBytes,
                $expiryDate,
                $_SESSION['user_id']
            );
            
            if ($result['success']) {
                $message = ['type' => 'success', 'message' => 'Access code created: ' . $result['code']];
            } else {
                $message = ['type' => 'error', 'message' => $result['error']];
            }
        } elseif ($_POST['action'] === 'delete_user') {
            $result = $userManager->deleteUser($_POST['user_id']);
            if ($result['success']) {
                $message = ['type' => 'success', 'message' => 'User deleted successfully!'];
            } else {
                $message = ['type' => 'error', 'message' => $result['error']];
            }
        } elseif ($_POST['action'] === 'delete_code') {
            $result = $userManager->deleteAccessCode($_POST['code_id']);
            if ($result['success']) {
                $message = ['type' => 'success', 'message' => 'Access code deleted successfully!'];
            } else {
                $message = ['type' => 'error', 'message' => $result['error']];
            }
        }
    }
}

// Handle password change (for all authenticated users)
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'change_password') {
    if (!$auth->verifyCSRFToken($_POST['csrf_token'])) {
        $message = ['type' => 'error', 'message' => 'Invalid request.'];
    } elseif ($currentUser) {
        $currentPassword = $_POST['current_password'] ?? '';
        $newPassword = $_POST['new_password'] ?? '';
        $confirmPassword = $_POST['confirm_password'] ?? '';
        
        if (empty($currentPassword) || empty($newPassword) || empty($confirmPassword)) {
            $message = ['type' => 'error', 'message' => 'All fields are required.'];
        } elseif ($newPassword !== $confirmPassword) {
            $message = ['type' => 'error', 'message' => 'New passwords do not match.'];
        } elseif (strlen($newPassword) < 8) {
            $message = ['type' => 'error', 'message' => 'Password must be at least 8 characters long.'];
        } else {
            // Verify current password
            if (password_verify($currentPassword, $currentUser['password'])) {
                $hashedPassword = password_hash($newPassword, PASSWORD_BCRYPT);
                $stmt = $db->prepare("UPDATE users SET password = ? WHERE id = ?");
                $stmt->execute([$hashedPassword, $currentUser['id']]);
                $message = ['type' => 'success', 'message' => 'Password changed successfully!'];
            } else {
                $message = ['type' => 'error', 'message' => 'Current password is incorrect.'];
            }
        }
    }
}

// Get admin data if user is admin
$users = [];
$accessCodes = [];
$customBaseUrl = '';
$autoDetectedBaseUrl = '';
if ($isAdmin) {
    $users = $userManager->getAllUsers();
    $accessCodes = $userManager->getAllAccessCodes();
    
    // Get current application settings
    $sql = "SELECT * FROM app_settings WHERE setting_key = ?";
    $baseUrlSetting = $db->fetch($sql, ['base_url']);
    $customBaseUrl = $baseUrlSetting ? $baseUrlSetting['setting_value'] : '';
    
    // Get auto-detected base URL for comparison
    $autoDetectedBaseUrl = getBaseUrl();
}

// Generate CSRF token
$csrfToken = $auth->generateCSRFToken();
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?php echo SITE_NAME; ?> - Settings</title>
    <link rel="stylesheet" href="style.css">
</head>
<body class="simple-page">
    <?php include 'header.php'; ?>
    
    <div class="container<?php echo $isAdmin ? ' admin-container' : ''; ?>">
        <?php if ($message): ?>
            <div class="alert alert-<?php echo $message['type'] === 'success' ? 'success' : 'error'; ?>">
                <?php echo htmlspecialchars($message['message']); ?>
            </div>
        <?php endif; ?>
        
        <div class="card">
            <div class="card-header">
                <h2>⚙️ Account Settings</h2>
            </div>
            <div class="card-body">
                <div class="settings-section">
                    <h3>Account Information</h3>
                    <div class="info-grid">
                        <div class="info-item">
                            <label>Username:</label>
                            <span><strong><?php echo $currentUser ? htmlspecialchars($currentUser['username']) : 'Access Code User'; ?></strong></span>
                        </div>
                        <?php if ($currentUser): ?>
                            <div class="info-item">
                                <label>Account Type:</label>
                                <span class="badge <?php echo $isAdmin ? 'badge-warning' : 'badge-success'; ?>">
                                    <?php echo $isAdmin ? 'Administrator' : 'User'; ?>
                                </span>
                            </div>
                            <div class="info-item">
                                <label>Created:</label>
                                <span><?php echo date('F j, Y', strtotime($currentUser['created_at'])); ?></span>
                            </div>
                        <?php endif; ?>
                    </div>
                </div>
                
                <?php if ($currentUser): ?>
                    <hr style="border-color: var(--color-border); margin: 2rem 0;">
                    
                    <div class="settings-section">
                        <h3>Change Password</h3>
                        <form method="POST" class="form-group">
                            <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($csrfToken); ?>">
                            <input type="hidden" name="action" value="change_password">
                            
                            <div class="form-group">
                                <label for="current_password">Current Password:</label>
                                <input type="password" id="current_password" name="current_password" required>
                            </div>
                            
                            <div class="form-group">
                                <label for="new_password">New Password:</label>
                                <input type="password" id="new_password" name="new_password" required minlength="8">
                                <small style="color: var(--color-muted);">Must be at least 8 characters long</small>
                            </div>
                            
                            <div class="form-group">
                                <label for="confirm_password">Confirm New Password:</label>
                                <input type="password" id="confirm_password" name="confirm_password" required minlength="8">
                            </div>
                            
                            <button type="submit" class="btn">Change Password</button>
                        </form>
                    </div>
                <?php else: ?>
                    <div class="alert alert-info">
                        <strong>Note:</strong> You are logged in with an access code. Password changes are only available for registered users.
                    </div>
                <?php endif; ?>
            </div>
        </div>
        
        <?php if ($isAdmin): ?>
        <!-- Application Settings Section (Admin Only) -->
        <div class="card">
            <div class="card-header">
                <h2>⚙️ Application Settings</h2>
            </div>
            <div class="card-body">
                <form method="POST">
                    <input type="hidden" name="action" value="update_base_url">
                    <input type="hidden" name="csrf_token" value="<?php echo $csrfToken; ?>">
                    
                    <div class="form-group">
                        <label for="base_url">Base URL for Link Generation</label>
                        <input type="url" 
                               id="base_url" 
                               name="base_url" 
                               value="<?php echo htmlspecialchars($customBaseUrl); ?>"
                               placeholder="https://example.com">
                        <small style="display: block; margin-top: 0.5rem; color: var(--color-muted);">
                            <strong>Current Mode:</strong> 
                            <?php if (!empty($customBaseUrl)): ?>
                                Custom URL: <code style="color: var(--color-secondary);"><?php echo htmlspecialchars($customBaseUrl); ?></code>
                            <?php else: ?>
                                Auto-Detection: <code style="color: var(--color-secondary);"><?php echo htmlspecialchars($autoDetectedBaseUrl); ?></code>
                            <?php endif; ?>
                        </small>
                        <small style="display: block; margin-top: 0.25rem; color: var(--color-muted);">
                            Set a custom base URL for share links and other generated URLs. Leave empty to use automatic detection based on HTTP headers (recommended for reverse proxy setups).
                        </small>
                        <small style="display: block; margin-top: 0.25rem; color: var(--color-gold);">
                            💡 <strong>Tip:</strong> Use automatic detection if you're behind a reverse proxy with proper X-Forwarded-* headers configured.
                        </small>
                    </div>
                    
                    <div class="flex gap-2">
                        <button type="submit" class="btn btn-primary">Save Settings</button>
                        <?php if (!empty($customBaseUrl)): ?>
                            <button type="button" class="btn btn-secondary" onclick="clearBaseUrl()">Use Auto-Detection</button>
                        <?php endif; ?>
                    </div>
                </form>
                
                <!-- Detection Info -->
                <div class="hash-info" style="margin-top: 1.5rem;">
                    <strong>🔍 Current Detection Info:</strong><br>
                    <small>
                        <strong>Protocol:</strong> <?php echo htmlspecialchars(getProtocol()); ?><br>
                        <strong>Host:</strong> <?php echo htmlspecialchars(getHost()); ?><br>
                        <strong>Auto-Detected URL:</strong> <?php echo htmlspecialchars($autoDetectedBaseUrl); ?><br>
                        <strong>Active Base URL:</strong> <?php echo htmlspecialchars(getBaseUrl()); ?><br>
                        <?php if (isset($_SERVER['HTTP_X_FORWARDED_PROTO'])): ?>
                            <strong>Behind Proxy:</strong> Yes (X-Forwarded-Proto: <?php echo htmlspecialchars($_SERVER['HTTP_X_FORWARDED_PROTO']); ?>)<br>
                        <?php endif; ?>
                        <?php if (isset($_SERVER['HTTP_X_FORWARDED_HOST'])): ?>
                            <strong>Forwarded Host:</strong> <?php echo htmlspecialchars($_SERVER['HTTP_X_FORWARDED_HOST']); ?><br>
                        <?php endif; ?>
                    </small>
                </div>
            </div>
        </div>
        
        <!-- User Management Section -->
        <div class="card">
            <div class="card-header">
                <h2>👥 Create New User</h2>
            </div>
            <div class="card-body">
            <form method="POST">
                <input type="hidden" name="action" value="create_user">
                <input type="hidden" name="csrf_token" value="<?php echo $csrfToken; ?>">
                
                <div class="form-grid">
                    <div class="form-group">
                        <label for="username">Username *</label>
                        <input type="text" id="username" name="username" required>
                    </div>
                    
                    <div class="form-group">
                        <label for="password">Password *</label>
                        <input type="password" id="password" name="password" required>
                    </div>
                    
                    <div class="form-group">
                        <label for="email">Email</label>
                        <input type="email" id="email" name="email">
                    </div>
                    
                    <div class="form-group">
                        <label for="upload_quota">Upload Quota (MB)</label>
                        <input type="number" id="upload_quota" name="upload_quota" value="1024" step="1" min="1" required>
                        <small>Default: 1024 MB (1 GB)</small>
                    </div>
                </div>
                
                <div class="form-grid">
                    <div class="form-group">
                        <label for="role">User Role</label>
                        <select id="role" name="role">
                            <option value="user" selected>User - Can manage own files</option>
                            <option value="admin">Admin - Full system access</option>
                        </select>
                    </div>
                    
                    <div class="checkbox-group">
                        <input type="checkbox" id="is_temporary" name="is_temporary" onchange="toggleExpiryDate()">
                        <label for="is_temporary" style="margin: 0">Temporary User</label>
                    </div>
                    
                    <div class="form-group" id="expiry_date_group" style="display: none;">
                        <label for="expiry_date">Expiry Date</label>
                        <input type="datetime-local" id="expiry_date" name="expiry_date">
                    </div>
                </div>
                
                <button type="submit" class="btn">Create User</button>
            </form>
            </div>
        </div>
        
        <div class="card">
            <div class="card-header">
                <h2>🔑 Create Access Code</h2>
            </div>
            <div class="card-body">
            <form method="POST">
                <input type="hidden" name="action" value="create_access_code">
                <input type="hidden" name="csrf_token" value="<?php echo $csrfToken; ?>">
                
                <div class="form-grid">
                    <div class="form-group">
                        <label for="max_uses">Max Uses</label>
                        <input type="number" id="max_uses" name="max_uses" value="1" min="1" required>
                    </div>
                    
                    <div class="form-group">
                        <label for="code_upload_quota">Upload Quota (MB)</label>
                        <input type="number" id="code_upload_quota" name="upload_quota" value="1024" step="1" min="1" required>
                        <small>Default: 1024 MB (1 GB)</small>
                    </div>
                    
                    <div class="form-group">
                        <label for="code_expiry_date">Expiry Date (optional)</label>
                        <input type="datetime-local" id="code_expiry_date" name="expiry_date">
                    </div>
                </div>
                
                <button type="submit" class="btn">Create Access Code</button>
            </form>
            </div>
        </div>
        
        <div class="card">
            <div class="card-header">
                <h2>👥 Manage Users</h2>
            </div>
            <div class="card-body">
                <div class="table-container">
                    <table>
                <thead>
                    <tr>
                        <th>Username</th>
                        <th>Email</th>
                        <th>Type</th>
                        <th>Quota</th>
                        <th>Status</th>
                        <th>Last Login</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($users as $user): ?>
                        <tr>
                            <td><?php echo htmlspecialchars($user['username']); ?></td>
                            <td><?php echo htmlspecialchars($user['email']); ?></td>
                            <td>
                                <?php 
                                $userRole = isset($user['role']) && !empty($user['role']) ? $user['role'] : ($user['is_admin'] ? 'admin' : 'user');
                                if ($userRole === 'admin'): ?>
                                    <span class="badge badge-danger">Admin</span>
                                <?php else: ?>
                                    <span class="badge badge-info">User</span>
                                <?php endif; ?>
                                <?php if ($user['is_temporary']): ?>
                                    <span class="badge badge-warning">Temporary</span>
                                <?php endif; ?>
                            </td>
                            <td>
                                <?php echo $fileManager->formatBytes($user['used_quota']); ?> / 
                                <?php echo $fileManager->formatBytes($user['upload_quota']); ?>
                            </td>
                            <td>
                                <?php if ($user['is_active']): ?>
                                    <span class="badge badge-success">Active</span>
                                <?php else: ?>
                                    <span class="badge badge-danger">Inactive</span>
                                <?php endif; ?>
                                <?php if ($user['is_temporary'] && $user['expiry_date']): ?>
                                    <br><small>Expires: <?php echo date('Y-m-d H:i', strtotime($user['expiry_date'])); ?></small>
                                <?php endif; ?>
                            </td>
                            <td><?php echo $user['last_login'] ? date('Y-m-d H:i', strtotime($user['last_login'])) : 'Never'; ?></td>
                            <td>
                                <?php if ($user['username'] !== 'admin'): ?>
                                    <form method="POST" style="display: inline;" onsubmit="return confirm('Are you sure?')">
                                        <input type="hidden" name="action" value="delete_user">
                                        <input type="hidden" name="user_id" value="<?php echo $user['id']; ?>">
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
            </div>
        </div>
        
        <div class="card">
            <div class="card-header">
                <h2>🔑 Manage Access Codes</h2>
            </div>
            <div class="card-body">
                <div class="table-container">
                    <table>
                <thead>
                    <tr>
                        <th>Code</th>
                        <th>Uses</th>
                        <th>Quota</th>
                        <th>Status</th>
                        <th>Created</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody>
                    <?php if (empty($accessCodes)): ?>
                        <tr>
                            <td colspan="6">No access codes created yet.</td>
                        </tr>
                    <?php else: ?>
                        <?php foreach ($accessCodes as $code): ?>
                            <tr>
                                <td class="code-display"><?php echo htmlspecialchars($code['code']); ?></td>
                                <td><?php echo $code['current_uses']; ?> / <?php echo $code['max_uses']; ?></td>
                                <td>
                                    <?php echo $fileManager->formatBytes($code['used_quota']); ?> / 
                                    <?php echo $fileManager->formatBytes($code['upload_quota']); ?>
                                </td>
                                <td>
                                    <?php if ($code['is_active'] && $code['current_uses'] < $code['max_uses']): ?>
                                        <span class="badge badge-success">Active</span>
                                    <?php else: ?>
                                        <span class="badge badge-danger">Inactive</span>
                                    <?php endif; ?>
                                    <?php if ($code['expiry_date']): ?>
                                        <br><small>Expires: <?php echo date('Y-m-d H:i', strtotime($code['expiry_date'])); ?></small>
                                    <?php endif; ?>
                                </td>
                                <td><?php echo date('Y-m-d H:i', strtotime($code['created_at'])); ?></td>
                                <td>
                                    <form method="POST" style="display: inline;" onsubmit="return confirm('Are you sure?')">
                                        <input type="hidden" name="action" value="delete_code">
                                        <input type="hidden" name="code_id" value="<?php echo $code['id']; ?>">
                                        <input type="hidden" name="csrf_token" value="<?php echo $csrfToken; ?>">
                                        <button type="submit" class="btn btn-small btn-danger">Delete</button>
                                    </form>
                                </td>
                            </tr>
                        <?php endforeach; ?>
                    <?php endif; ?>
                </tbody>
                    </table>
                </div>
            </div>
        </div>
        
        <script>
            function toggleExpiryDate() {
                const checkbox = document.getElementById('is_temporary');
                const expiryGroup = document.getElementById('expiry_date_group');
                expiryGroup.style.display = checkbox.checked ? 'flex' : 'none';
            }
            
            function clearBaseUrl() {
                document.getElementById('base_url').value = '';
                document.getElementById('base_url').closest('form').submit();
            }
        </script>
        <?php endif; ?>
    </div>
    
    <?php include 'footer.php'; ?>
</body>
</html>
