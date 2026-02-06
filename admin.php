<?php
// Admin panel
require_once 'config.php';
require_once 'db.php';
require_once 'auth.php';
require_once 'users.php';
require_once 'files.php';

$db = new Database();
$auth = new Auth($db);
$userManager = new UserManager($db);
$fileManager = new FileManager($db, $auth);

// Check if logged in and is admin
if (!$auth->isLoggedIn() || !$auth->isAdmin()) {
    header('Location: login.php');
    exit;
}

$message = null;

// Handle user creation
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action'])) {
    if (!$auth->verifyCSRFToken($_POST['csrf_token'])) {
        $message = ['type' => 'error', 'message' => 'Invalid request.'];
    } else {
        if ($_POST['action'] === 'create_user') {
            $isTemporary = isset($_POST['is_temporary']);
            $expiryDate = $isTemporary && !empty($_POST['expiry_date']) ? $_POST['expiry_date'] : null;
            
            $result = $userManager->createUser(
                $_POST['username'],
                $_POST['password'],
                $_POST['email'],
                isset($_POST['is_admin']),
                intval($_POST['upload_quota']),
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
            
            $result = $userManager->createAccessCode(
                intval($_POST['max_uses']),
                intval($_POST['upload_quota']),
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

// Get all users and access codes
$users = $userManager->getAllUsers();
$accessCodes = $userManager->getAllAccessCodes();

$csrfToken = $auth->generateCSRFToken();
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?php echo SITE_NAME; ?> - Admin Panel</title>
    <link rel="stylesheet" href="style.css">
</head>
<body class="simple-page">
    <?php include 'header.php'; ?>
    
    <div class="container admin-container">
        <?php if ($message): ?>
            <div class="alert alert-<?php echo $message['type'] === 'success' ? 'success' : 'error'; ?>">
                <?php echo htmlspecialchars($message['message']); ?>
            </div>
        <?php endif; ?>
        
        <div class="card">
            <h2>Create New User</h2>
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
                        <label for="upload_quota">Upload Quota (bytes)</label>
                        <input type="number" id="upload_quota" name="upload_quota" value="1073741824" required>
                        <small>Default: 1 GB (1073741824 bytes)</small>
                    </div>
                </div>
                
                <div class="form-grid">
                    <div class="checkbox-group">
                        <input type="checkbox" id="is_admin" name="is_admin">
                        <label for="is_admin" style="margin: 0">Administrator</label>
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
        
        <div class="card">
            <h2>Create Access Code</h2>
            <form method="POST">
                <input type="hidden" name="action" value="create_access_code">
                <input type="hidden" name="csrf_token" value="<?php echo $csrfToken; ?>">
                
                <div class="form-grid">
                    <div class="form-group">
                        <label for="max_uses">Max Uses</label>
                        <input type="number" id="max_uses" name="max_uses" value="1" min="1" required>
                    </div>
                    
                    <div class="form-group">
                        <label for="code_upload_quota">Upload Quota (bytes)</label>
                        <input type="number" id="code_upload_quota" name="upload_quota" value="1073741824" required>
                        <small>Default: 1 GB (1073741824 bytes)</small>
                    </div>
                    
                    <div class="form-group">
                        <label for="code_expiry_date">Expiry Date (optional)</label>
                        <input type="datetime-local" id="code_expiry_date" name="expiry_date">
                    </div>
                </div>
                
                <button type="submit" class="btn">Generate Access Code</button>
            </form>
        </div>
        
        <div class="card">
            <h2>Users</h2>
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
                                <?php if ($user['is_admin']): ?>
                                    <span class="badge badge-danger">Admin</span>
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
        
        <div class="card">
            <h2>Access Codes</h2>
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
    
    <script>
        function toggleExpiryDate() {
            const checkbox = document.getElementById('is_temporary');
            const expiryGroup = document.getElementById('expiry_date_group');
            expiryGroup.style.display = checkbox.checked ? 'flex' : 'none';
        }
    </script>
</body>
</html>
