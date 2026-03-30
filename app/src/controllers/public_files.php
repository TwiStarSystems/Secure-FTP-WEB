<?php
/**
 * Public Files Page
 * Shows all publicly shared files to anonymous users
 * This is the default landing page for non-authenticated users
 */
require_once APP_DIR . '/src/core/config.php';
require_once APP_DIR . '/src/core/db.php';
require_once APP_DIR . '/src/services/auth.php';
require_once APP_DIR . '/src/services/share.php';
require_once APP_DIR . '/src/services/rbac.php';

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
    <link rel="stylesheet" href="assets/css/style.css">
</head>
<body class="simple-page public-page">
    <?php include APP_DIR . '/src/views/header.php'; ?>
    
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
    </div>
    
    <?php include APP_DIR . '/src/views/footer.php'; ?>
</body>
</html>
