<?php
/**
 * Public Files Page
 * Shows all publicly shared files to anonymous users
 * This is the default landing page for non-authenticated users
 */
require_once 'config.php';
require_once 'db.php';
require_once 'auth.php';
require_once 'share.php';
require_once 'rbac.php';

$db = new Database();
$auth = new Auth($db);
$shareManager = new ShareManager($db);

// Get all public shares
$publicShares = $shareManager->getPublicShares();

// Check if user is logged in
$isLoggedIn = $auth->isLoggedIn();
$currentUser = $auth->getCurrentUser();
$isAdmin = RBAC::isAdmin();
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?php echo SITE_NAME; ?> - Public Files</title>
    <link rel="stylesheet" href="style.css">
</head>
<body class="simple-page public-page">
    <div class="header simple-gradient">
        <div class="header-content">
            <h1>🔒 <?php echo SITE_NAME; ?></h1>
            <div class="header-right">
                <?php if ($isLoggedIn): ?>
                    <a href="index.php" class="header-btn" title="Dashboard">
                        <span class="icon">📁</span> Dashboard
                    </a>
                    
                    <?php if ($isAdmin): ?>
                        <a href="admin.php" class="header-btn" title="Admin Panel">
                            <span class="icon">🔐</span> Admin
                        </a>
                    <?php endif; ?>
                    
                    <div class="user-info">
                        <strong><?php echo htmlspecialchars($currentUser['username']); ?></strong>
                        <small><?php echo RBAC::getRoleDisplayName(RBAC::getCurrentRole()); ?></small>
                    </div>
                    
                    <a href="index.php?action=logout" class="header-btn btn-logout" title="Logout">
                        Logout
                    </a>
                <?php else: ?>
                    <a href="login.php" class="header-btn btn-login" title="Login">
                        <span class="icon">🔑</span> Login
                    </a>
                <?php endif; ?>
            </div>
        </div>
    </div>
    
    <div class="container">
        <div class="page-intro">
            <h2>📂 Public Files</h2>
            <p>Browse and download publicly shared files. Files are shared by registered users for public access.</p>
        </div>
        
        <?php if (empty($publicShares)): ?>
            <div class="card">
                <div class="empty-state">
                    <div class="empty-icon">📭</div>
                    <h3>No Public Files Available</h3>
                    <p>There are currently no publicly shared files available for download.</p>
                    <?php if (!$isLoggedIn): ?>
                        <p><a href="login.php" class="btn">Login to Upload Files</a></p>
                    <?php endif; ?>
                </div>
            </div>
        <?php else: ?>
            <div class="card">
                <div class="files-grid public-files-grid">
                    <?php foreach ($publicShares as $share): ?>
                        <div class="file-card">
                            <div class="file-icon">
                                <?php 
                                $mimeType = $share['mime_type'] ?? '';
                                if (strpos($mimeType, 'image') !== false) echo '🖼️';
                                elseif (strpos($mimeType, 'video') !== false) echo '🎬';
                                elseif (strpos($mimeType, 'audio') !== false) echo '🎵';
                                elseif (strpos($mimeType, 'pdf') !== false) echo '📕';
                                elseif (strpos($mimeType, 'zip') !== false || strpos($mimeType, 'tar') !== false || strpos($mimeType, 'gzip') !== false) echo '📦';
                                elseif (strpos($mimeType, 'text') !== false) echo '📄';
                                else echo '📁';
                                ?>
                            </div>
                            <div class="file-info">
                                <h4 class="file-name" title="<?php echo htmlspecialchars($share['original_filename']); ?>">
                                    <?php 
                                    $filename = $share['original_filename'];
                                    echo htmlspecialchars(strlen($filename) > 30 ? substr($filename, 0, 27) . '...' : $filename);
                                    ?>
                                </h4>
                                <div class="file-meta">
                                    <span class="file-size"><?php echo $shareManager->formatBytes($share['file_size']); ?></span>
                                    <span class="file-separator">•</span>
                                    <span class="file-uploader">by <?php echo htmlspecialchars($share['shared_by_username']); ?></span>
                                </div>
                                <div class="file-meta">
                                    <span class="file-date"><?php echo date('M j, Y', strtotime($share['created_at'])); ?></span>
                                    <?php if ($share['download_count'] > 0): ?>
                                        <span class="file-separator">•</span>
                                        <span class="file-downloads"><?php echo $share['download_count']; ?> downloads</span>
                                    <?php endif; ?>
                                </div>
                            </div>
                            <div class="file-actions">
                                <a href="shared.php?token=<?php echo htmlspecialchars($share['share_token']); ?>" class="btn btn-small">
                                    ⬇️ Download
                                </a>
                            </div>
                        </div>
                    <?php endforeach; ?>
                </div>
            </div>
        <?php endif; ?>
        
        <?php if (!$isLoggedIn): ?>
            <div class="card login-prompt-card">
                <h3>Want to share your own files?</h3>
                <p>Login or register to upload and share files securely.</p>
                <a href="login.php" class="btn">Login / Register</a>
            </div>
        <?php endif; ?>
    </div>
    
    <footer class="page-footer">
        <p>&copy; <?php echo date('Y'); ?> <?php echo SITE_NAME; ?>. Secure file sharing made simple.</p>
    </footer>
</body>
</html>
