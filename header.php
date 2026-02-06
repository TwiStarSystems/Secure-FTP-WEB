<?php
// Common header for all authenticated pages
// Must be included after auth check and user info is loaded
?>
<div class="header simple-gradient">
    <div class="header-content">
        <h1>🔒 Secure File Transfer</h1>
        <div class="header-right">
            <a href="index.php" class="header-btn" title="Dashboard">
                <span class="icon">📁</span> Dashboard
            </a>
            
            <?php if (isset($isAdmin) && $isAdmin): ?>
                <a href="admin.php" class="header-btn" title="Admin Panel">
                    <span class="icon">🔐</span> Admin
                </a>
            <?php endif; ?>
            
            <div class="user-info">
                <strong><?php echo isset($currentUser) && $currentUser ? htmlspecialchars($currentUser['username']) : 'Access Code User'; ?></strong>
                <small><?php echo isset($isAdmin) && $isAdmin ? 'Administrator' : 'User'; ?></small>
            </div>
            
            <a href="settings.php" class="header-btn" title="Settings">
                <span class="icon">⚙️</span>
            </a>
            
            <a href="?action=logout" class="header-btn btn-logout" title="Logout">
                Logout
            </a>
        </div>
    </div>
</div>
