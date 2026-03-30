<?php
// Common header for all pages
// Must be included after auth check and user info is loaded
require_once APP_DIR . '/src/services/rbac.php';

$headerRole = RBAC::getCurrentRole();
$headerIsAuthenticated = RBAC::isAuthenticated();
$headerIsAdmin = RBAC::isAdmin();
?>
<div class="header simple-gradient">
    <div class="header-content">
        <h1><a href="<?php echo $headerIsAuthenticated ? 'index.php' : 'public.php'; ?>" class="logo-link">🔒 <?php echo SITE_NAME; ?></a></h1>
        <div class="header-right">
            <!-- Public files link - visible to all -->
            <a href="public.php" class="header-btn" title="Public Files">
                <span class="icon">🌐</span> Public Files
            </a>
            
            <?php if ($headerIsAuthenticated): ?>
                <!-- Dashboard - for authenticated users -->
                <a href="index.php" class="header-btn" title="Dashboard">
                    <span class="icon">📁</span> Dashboard
                </a>
                
                <!-- My Shares - for authenticated users -->
                <a href="my_shares.php" class="header-btn" title="My Shares">
                    <span class="icon">🔗</span> My Shares
                </a>
                
                <?php if ($headerIsAdmin): ?>
                    <!-- Settings / Admin Panel - admin only -->
                    <a href="settings.php" class="header-btn" title="Settings">
                        <span class="icon">⚙️</span> Settings
                    </a>
                <?php endif; ?>
                
                <div class="user-info">
                    <div class="user-details">
                        <strong><?php echo isset($currentUser) && $currentUser ? htmlspecialchars($currentUser['username']) : 'Access Code User'; ?></strong>
                        <small><?php echo RBAC::getRoleDisplayName($headerRole); ?></small>
                    </div>
                    <a href="settings.php" class="user-settings-btn" title="Settings">
                        <span class="icon">⚙️</span>
                    </a>
                </div>
                
                <a href="logout.php" class="header-btn btn-logout" title="Logout">
                    Logout
                </a>
            <?php else: ?>
                <!-- Login button for anonymous users -->
                <a href="login.php" class="header-btn btn-login" title="Login">
                    <span class="icon">🔑</span> Login
                </a>
            <?php endif; ?>
        </div>
    </div>
</div>
