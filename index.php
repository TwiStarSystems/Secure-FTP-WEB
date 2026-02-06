<?php
// Main dashboard
require_once 'config.php';
require_once 'db.php';
require_once 'auth.php';
require_once 'files.php';
require_once 'users.php';

$db = new Database();
$auth = new Auth($db);
$fileManager = new FileManager($db, $auth);
$userManager = new UserManager($db);

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

// Get current user info
$currentUser = $auth->getCurrentUser();
$currentAccessCode = $auth->getCurrentAccessCode();
$isAdmin = $auth->isAdmin();

// Get files
$files = $fileManager->getFiles();

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
    <div class="header simple-gradient">
        <div class="header-content">
            <h1>🔒 <?php echo SITE_NAME; ?></h1>
            <div class="header-right">
                <?php if ($isAdmin): ?>
                    <a href="admin.php" class="admin-link">Admin Panel</a>
                <?php endif; ?>
                <div class="user-info">
                    <div><strong><?php echo $currentUser ? htmlspecialchars($currentUser['username']) : 'Access Code User'; ?></strong></div>
                    <small><?php echo $isAdmin ? 'Administrator' : 'User'; ?></small>
                </div>
                <a href="?action=logout" class="btn-logout">Logout</a>
            </div>
        </div>
    </div>
    
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
                        <?php echo htmlspecialchars($uploadMessage['data']['file_hash']); ?>
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
                                <td><?php echo $fileManager->formatBytes($file['file_size']); ?></td>
                                <td class="file-hash" title="<?php echo htmlspecialchars($file['file_hash']); ?>">
                                    <?php echo substr($file['file_hash'], 0, 16); ?>...
                                </td>
                                <td><?php echo date('Y-m-d H:i', strtotime($file['upload_date'])); ?></td>
                                <td><?php echo $file['download_count']; ?></td>
                                <td class="actions">
                                    <a href="download.php?id=<?php echo $file['id']; ?>" class="btn btn-small">Download</a>
                                    <?php if ($currentUser && ($isAdmin || $file['uploaded_by_user'] === $currentUser['id'])): ?>
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
</body>
</html>
