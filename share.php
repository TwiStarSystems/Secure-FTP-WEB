<?php
/**
 * Share Management Functions
 * Handles creating, managing, and accessing shared file links
 */
require_once 'db.php';
require_once 'rbac.php';

class ShareManager {
    private $db;
    
    public function __construct($db) {
        $this->db = $db;
    }
    
    /**
     * Create a public share link for a file
     */
    public function createShare($fileId, $userId, $options = []) {
        // Get the file to verify it exists
        $sql = "SELECT * FROM files WHERE id = ?";
        $file = $this->db->fetch($sql, [$fileId]);
        
        if (!$file) {
            return ['success' => false, 'error' => 'File not found.'];
        }
        
        // Check permissions using RBAC
        $currentUser = null;
        if (isset($_SESSION['user_id'])) {
            $sql = "SELECT * FROM users WHERE id = ?";
            $currentUser = $this->db->fetch($sql, [$_SESSION['user_id']]);
        }
        
        if (!RBAC::canShareFile($file, $currentUser)) {
            return ['success' => false, 'error' => 'Permission denied.'];
        }
        
        // Generate unique share token
        $shareToken = bin2hex(random_bytes(32));
        
        // Parse options
        $isPublic = isset($options['is_public']) ? (bool)$options['is_public'] : true;
        $password = isset($options['password']) && !empty($options['password']) 
            ? password_hash($options['password'], PASSWORD_DEFAULT) 
            : null;
        $expiresAt = isset($options['expires_at']) && !empty($options['expires_at']) 
            ? $options['expires_at'] 
            : null;
        $maxDownloads = isset($options['max_downloads']) && $options['max_downloads'] > 0 
            ? (int)$options['max_downloads'] 
            : null;
        
        // Insert share record
        $sql = "INSERT INTO shared_files (file_id, share_token, shared_by_user, is_public, password_hash, expires_at, max_downloads) 
                VALUES (?, ?, ?, ?, ?, ?, ?)";
        
        $result = $this->db->query($sql, [
            $fileId,
            $shareToken,
            $userId,
            $isPublic,
            $password,
            $expiresAt,
            $maxDownloads
        ]);
        
        if ($result) {
            return [
                'success' => true,
                'share_id' => $this->db->lastInsertId(),
                'share_token' => $shareToken,
                'share_url' => $this->getShareUrl($shareToken)
            ];
        }
        
        return ['success' => false, 'error' => 'Failed to create share link.'];
    }
    
    /**
     * Get the full share URL for a token
     * Uses proxy-aware URL generation to work correctly behind reverse proxy
     */
    public function getShareUrl($shareToken) {
        $baseUrl = getBaseUrl();
        return "{$baseUrl}/shared.php?token={$shareToken}";
    }
    
    /**
     * Get share by token
     */
    public function getShareByToken($token) {
        $sql = "SELECT sf.*, f.filename, f.original_filename, f.file_size, f.mime_type, f.file_hash, f.hash_algorithm,
                       u.username as shared_by_username
                FROM shared_files sf
                JOIN files f ON sf.file_id = f.id
                JOIN users u ON sf.shared_by_user = u.id
                WHERE sf.share_token = ? AND sf.is_active = TRUE";
        
        return $this->db->fetch($sql, [$token]);
    }
    
    /**
     * Validate share (check expiry, download limits, etc.)
     */
    public function validateShare($share, $password = null) {
        if (!$share) {
            return ['valid' => false, 'error' => 'Share link not found.'];
        }
        
        // Check if active
        if (!$share['is_active']) {
            return ['valid' => false, 'error' => 'This share link has been deactivated.'];
        }
        
        // Check expiry
        if ($share['expires_at'] && strtotime($share['expires_at']) < time()) {
            return ['valid' => false, 'error' => 'This share link has expired.'];
        }
        
        // Check download limit
        if ($share['max_downloads'] !== null && $share['download_count'] >= $share['max_downloads']) {
            return ['valid' => false, 'error' => 'This share link has reached its download limit.'];
        }
        
        // Check password if required
        if ($share['password_hash'] !== null) {
            if (empty($password)) {
                return ['valid' => false, 'error' => 'password_required', 'requires_password' => true];
            }
            if (!password_verify($password, $share['password_hash'])) {
                return ['valid' => false, 'error' => 'Invalid password.'];
            }
        }
        
        return ['valid' => true];
    }
    
    /**
     * Record a download for the share
     */
    public function recordDownload($shareId) {
        $sql = "UPDATE shared_files SET download_count = download_count + 1 WHERE id = ?";
        $this->db->query($sql, [$shareId]);
    }
    
    /**
     * Get all shares for a user
     */
    public function getUserShares($userId) {
        $sql = "SELECT sf.*, f.original_filename, f.file_size, f.mime_type
                FROM shared_files sf
                JOIN files f ON sf.file_id = f.id
                WHERE sf.shared_by_user = ?
                ORDER BY sf.created_at DESC";
        
        return $this->db->fetchAll($sql, [$userId]);
    }
    
    /**
     * Get all shares for a specific file
     */
    public function getFileShares($fileId) {
        $sql = "SELECT * FROM shared_files WHERE file_id = ? ORDER BY created_at DESC";
        return $this->db->fetchAll($sql, [$fileId]);
    }
    
    /**
     * Get all public shares (for anonymous users)
     */
    public function getPublicShares() {
        $sql = "SELECT sf.*, f.original_filename, f.file_size, f.mime_type, f.file_hash, f.hash_algorithm,
                       u.username as shared_by_username
                FROM shared_files sf
                JOIN files f ON sf.file_id = f.id
                JOIN users u ON sf.shared_by_user = u.id
                WHERE sf.is_public = TRUE 
                AND sf.is_active = TRUE
                AND sf.password_hash IS NULL
                AND (sf.expires_at IS NULL OR sf.expires_at > NOW())
                AND (sf.max_downloads IS NULL OR sf.download_count < sf.max_downloads)
                ORDER BY sf.created_at DESC";
        
        return $this->db->fetchAll($sql);
    }
    
    /**
     * Get all shares (admin only)
     */
    public function getAllShares() {
        $sql = "SELECT sf.*, f.original_filename, f.file_size, f.mime_type,
                       u.username as shared_by_username
                FROM shared_files sf
                JOIN files f ON sf.file_id = f.id
                JOIN users u ON sf.shared_by_user = u.id
                ORDER BY sf.created_at DESC";
        
        return $this->db->fetchAll($sql);
    }
    
    /**
     * Delete a share
     */
    public function deleteShare($shareId, $userId = null) {
        // Get share to check ownership
        $sql = "SELECT * FROM shared_files WHERE id = ?";
        $share = $this->db->fetch($sql, [$shareId]);
        
        if (!$share) {
            return ['success' => false, 'error' => 'Share not found.'];
        }
        
        // Check permissions - admin can delete any, user can only delete own
        if (!RBAC::isAdmin() && $share['shared_by_user'] !== $userId) {
            return ['success' => false, 'error' => 'Permission denied.'];
        }
        
        $sql = "DELETE FROM shared_files WHERE id = ?";
        $result = $this->db->query($sql, [$shareId]);
        
        if ($result) {
            return ['success' => true];
        }
        
        return ['success' => false, 'error' => 'Failed to delete share.'];
    }
    
    /**
     * Delete all shares for a file
     */
    public function deleteFileShares($fileId, $userId = null) {
        // Get file to check ownership
        $sql = "SELECT * FROM files WHERE id = ?";
        $file = $this->db->fetch($sql, [$fileId]);
        
        if (!$file) {
            return ['success' => false, 'error' => 'File not found.'];
        }
        
        // Check permissions
        if (!RBAC::isAdmin() && $file['uploaded_by_user'] !== $userId) {
            return ['success' => false, 'error' => 'Permission denied.'];
        }
        
        $sql = "DELETE FROM shared_files WHERE file_id = ?";
        $result = $this->db->query($sql, [$fileId]);
        
        if ($result !== false) {
            return ['success' => true];
        }
        
        return ['success' => false, 'error' => 'Failed to delete shares.'];
    }
    
    /**
     * Deactivate a share (soft delete)
     */
    public function deactivateShare($shareId, $userId = null) {
        // Get share to check ownership
        $sql = "SELECT * FROM shared_files WHERE id = ?";
        $share = $this->db->fetch($sql, [$shareId]);
        
        if (!$share) {
            return ['success' => false, 'error' => 'Share not found.'];
        }
        
        // Check permissions
        if (!RBAC::isAdmin() && $share['shared_by_user'] !== $userId) {
            return ['success' => false, 'error' => 'Permission denied.'];
        }
        
        $sql = "UPDATE shared_files SET is_active = FALSE WHERE id = ?";
        $result = $this->db->query($sql, [$shareId]);
        
        if ($result) {
            return ['success' => true];
        }
        
        return ['success' => false, 'error' => 'Failed to deactivate share.'];
    }
    
    /**
     * Update share settings
     */
    public function updateShare($shareId, $userId, $data) {
        // Get share to check ownership
        $sql = "SELECT * FROM shared_files WHERE id = ?";
        $share = $this->db->fetch($sql, [$shareId]);
        
        if (!$share) {
            return ['success' => false, 'error' => 'Share not found.'];
        }
        
        // Check permissions
        if (!RBAC::isAdmin() && $share['shared_by_user'] !== $userId) {
            return ['success' => false, 'error' => 'Permission denied.'];
        }
        
        $updates = [];
        $params = [];
        
        if (isset($data['is_public'])) {
            $updates[] = "is_public = ?";
            $params[] = (bool)$data['is_public'];
        }
        
        if (isset($data['password'])) {
            if (empty($data['password'])) {
                $updates[] = "password_hash = NULL";
            } else {
                $updates[] = "password_hash = ?";
                $params[] = password_hash($data['password'], PASSWORD_DEFAULT);
            }
        }
        
        if (isset($data['expires_at'])) {
            $updates[] = "expires_at = ?";
            $params[] = empty($data['expires_at']) ? null : $data['expires_at'];
        }
        
        if (isset($data['max_downloads'])) {
            $updates[] = "max_downloads = ?";
            $params[] = $data['max_downloads'] > 0 ? (int)$data['max_downloads'] : null;
        }
        
        if (isset($data['is_active'])) {
            $updates[] = "is_active = ?";
            $params[] = (bool)$data['is_active'];
        }
        
        if (empty($updates)) {
            return ['success' => false, 'error' => 'No fields to update.'];
        }
        
        $params[] = $shareId;
        $sql = "UPDATE shared_files SET " . implode(", ", $updates) . " WHERE id = ?";
        
        $result = $this->db->query($sql, $params);
        
        if ($result) {
            return ['success' => true];
        }
        
        return ['success' => false, 'error' => 'Failed to update share.'];
    }
    
    /**
     * Format bytes to human readable
     */
    public function formatBytes($bytes, $precision = 2) {
        $units = ['B', 'KB', 'MB', 'GB', 'TB'];
        
        for ($i = 0; $bytes > 1024 && $i < count($units) - 1; $i++) {
            $bytes /= 1024;
        }
        
        return round($bytes, $precision) . ' ' . $units[$i];
    }
}
?>
