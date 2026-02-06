<?php
/**
 * Role-Based Access Control (RBAC) System
 * 
 * Roles:
 * - admin: Full control - manage all files, users, and system settings
 * - user: Authenticated user - manage own files, create share links
 * - anonymous: Non-authenticated - view publicly shared files only
 * 
 * Permissions:
 * - files.view.own: View own files
 * - files.view.all: View all files (admin only)
 * - files.upload: Upload files
 * - files.edit.own: Edit own files
 * - files.edit.all: Edit all files (admin only)
 * - files.delete.own: Delete own files
 * - files.delete.all: Delete all files (admin only)
 * - files.share: Create share links for own files
 * - files.share.all: Create share links for any file (admin)
 * - files.download.shared: Download publicly shared files
 * - users.view: View user list (admin only)
 * - users.create: Create users (admin only)
 * - users.edit: Edit users (admin only)
 * - users.delete: Delete users (admin only)
 * - admin.access: Access admin panel
 */

class RBAC {
    // Define role permissions
    private static $rolePermissions = [
        'admin' => [
            'files.view.own',
            'files.view.all',
            'files.upload',
            'files.edit.own',
            'files.edit.all',
            'files.delete.own',
            'files.delete.all',
            'files.share',
            'files.share.all',
            'files.download.shared',
            'users.view',
            'users.create',
            'users.edit',
            'users.delete',
            'admin.access',
            'settings.manage'
        ],
        'user' => [
            'files.view.own',
            'files.upload',
            'files.edit.own',
            'files.delete.own',
            'files.share',
            'files.download.shared'
        ],
        'anonymous' => [
            'files.download.shared'
        ]
    ];
    
    /**
     * Get the current user's role
     * Returns 'anonymous' if not logged in
     */
    public static function getCurrentRole() {
        if (!isset($_SESSION['user_id'])) {
            // Check if logged in with access code (treat as limited user)
            if (isset($_SESSION['access_code_id'])) {
                return 'user';
            }
            return 'anonymous';
        }
        
        // Check if role is stored in session
        if (isset($_SESSION['user_role'])) {
            return $_SESSION['user_role'];
        }
        
        // Fall back to is_admin flag for backward compatibility
        if (isset($_SESSION['is_admin']) && $_SESSION['is_admin']) {
            return 'admin';
        }
        
        return 'user';
    }
    
    /**
     * Check if the current user has a specific permission
     */
    public static function hasPermission($permission) {
        $role = self::getCurrentRole();
        return self::roleHasPermission($role, $permission);
    }
    
    /**
     * Check if a specific role has a specific permission
     */
    public static function roleHasPermission($role, $permission) {
        if (!isset(self::$rolePermissions[$role])) {
            return false;
        }
        return in_array($permission, self::$rolePermissions[$role]);
    }
    
    /**
     * Get all permissions for a role
     */
    public static function getRolePermissions($role) {
        return self::$rolePermissions[$role] ?? [];
    }
    
    /**
     * Check if user is an admin
     */
    public static function isAdmin() {
        return self::getCurrentRole() === 'admin';
    }
    
    /**
     * Check if user is authenticated (admin or user)
     */
    public static function isAuthenticated() {
        $role = self::getCurrentRole();
        return $role === 'admin' || $role === 'user';
    }
    
    /**
     * Check if user is anonymous (not logged in)
     */
    public static function isAnonymous() {
        return self::getCurrentRole() === 'anonymous';
    }
    
    /**
     * Check if the current user can view a specific file
     */
    public static function canViewFile($file, $currentUser = null) {
        $role = self::getCurrentRole();
        
        // Admins can view all files
        if ($role === 'admin') {
            return true;
        }
        
        // Authenticated users can view their own files
        if ($role === 'user' && $currentUser) {
            if ($file['uploaded_by_user'] === $currentUser['id']) {
                return true;
            }
        }
        
        // Access code users can view files uploaded with their code
        if (isset($_SESSION['access_code_id']) && $file['uploaded_by_code'] === $_SESSION['access_code_id']) {
            return true;
        }
        
        return false;
    }
    
    /**
     * Check if the current user can edit a specific file
     */
    public static function canEditFile($file, $currentUser = null) {
        $role = self::getCurrentRole();
        
        // Admins can edit all files
        if ($role === 'admin') {
            return true;
        }
        
        // Authenticated users can edit their own files
        if ($role === 'user' && $currentUser && $file['uploaded_by_user'] === $currentUser['id']) {
            return true;
        }
        
        return false;
    }
    
    /**
     * Check if the current user can delete a specific file
     */
    public static function canDeleteFile($file, $currentUser = null) {
        $role = self::getCurrentRole();
        
        // Admins can delete all files
        if ($role === 'admin') {
            return true;
        }
        
        // Authenticated users can delete their own files
        if ($role === 'user' && $currentUser && $file['uploaded_by_user'] === $currentUser['id']) {
            return true;
        }
        
        return false;
    }
    
    /**
     * Check if the current user can share a specific file
     */
    public static function canShareFile($file, $currentUser = null) {
        $role = self::getCurrentRole();
        
        // Admins can share all files
        if ($role === 'admin') {
            return true;
        }
        
        // Authenticated users can share their own files
        if ($role === 'user' && $currentUser && $file['uploaded_by_user'] === $currentUser['id']) {
            return true;
        }
        
        return false;
    }
    
    /**
     * Check if the current user can manage other users
     */
    public static function canManageUsers() {
        return self::hasPermission('users.create');
    }
    
    /**
     * Check if the current user can access admin panel
     */
    public static function canAccessAdmin() {
        return self::hasPermission('admin.access');
    }
    
    /**
     * Require authentication - redirect to login if not authenticated
     */
    public static function requireAuth() {
        if (!self::isAuthenticated()) {
            header('Location: login.php');
            exit;
        }
    }
    
    /**
     * Require admin role - redirect to index if not admin
     */
    public static function requireAdmin() {
        if (!self::isAdmin()) {
            header('Location: index.php?error=unauthorized');
            exit;
        }
    }
    
    /**
     * Require a specific permission - redirect with error if not granted
     */
    public static function requirePermission($permission, $redirectUrl = 'index.php') {
        if (!self::hasPermission($permission)) {
            header('Location: ' . $redirectUrl . '?error=permission_denied');
            exit;
        }
    }
    
    /**
     * Get display-friendly role name
     */
    public static function getRoleDisplayName($role) {
        $names = [
            'admin' => 'Administrator',
            'user' => 'User',
            'anonymous' => 'Guest'
        ];
        return $names[$role] ?? 'Unknown';
    }
    
    /**
     * Get all available roles
     */
    public static function getAvailableRoles() {
        return ['admin', 'user'];
    }
}
?>
