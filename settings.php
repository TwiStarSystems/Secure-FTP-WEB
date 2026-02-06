<?php
// Settings page
require_once 'config.php';
require_once 'db.php';
require_once 'auth.php';

$db = new Database();
$auth = new Auth($db);

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
$isAdmin = $auth->isAdmin();

$message = null;

// Handle password change
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
    
    <div class="container">
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
    </div>
    
    <?php include 'footer.php'; ?>
</body>
</html>
