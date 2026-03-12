<?php
/**
 * Share Management Functions
 * Handles creating, managing, and accessing shared file links
 */
require_once 'db.php';
require_once 'rbac.php';

class ShareManager {
    private $db;
    private const DEFAULT_RECIPIENT_TOKEN_TTL_HOURS = 168; // 7 days
    private const MAX_RECIPIENT_EMAIL_LENGTH = 191;
    
    public function __construct($db) {
        $this->db = $db;
        $this->ensureRecipientTokenTable();
    }

    /**
     * Create recipient token table if it does not exist yet.
     */
    private function ensureRecipientTokenTable() {
        $sql = "CREATE TABLE IF NOT EXISTS share_recipient_tokens (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    share_id INT NOT NULL UNIQUE,
                    recipient_email VARCHAR(191) NOT NULL,
                    token_hash CHAR(64) NOT NULL,
                    expires_at DATETIME NULL,
                    used_at DATETIME NULL,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                    FOREIGN KEY (share_id) REFERENCES shared_files(id) ON DELETE CASCADE,
                    INDEX idx_recipient_email (recipient_email),
                    INDEX idx_expires_at (expires_at),
                    INDEX idx_used_at (used_at)
                )";

        $this->db->query($sql);
    }

    private function normalizeEmail($email) {
        return strtolower(trim((string)$email));
    }

    /**
     * Validate recipient email with stricter checks than filter_var alone.
     */
    private function isValidRecipientEmail($email) {
        if (!is_string($email)) {
            return false;
        }

        $email = $this->normalizeEmail($email);
        if ($email === '' || strlen($email) > self::MAX_RECIPIENT_EMAIL_LENGTH) {
            return false;
        }

        // Reject control characters and spaces.
        if (preg_match('/[\x00-\x1F\x7F\s]/', $email)) {
            return false;
        }

        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            return false;
        }

        // Keep accepted addresses predictable for this workflow.
        return preg_match('/^[a-z0-9._%+\-]+@[a-z0-9.-]+\.[a-z]{2,63}$/i', $email) === 1;
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
        $recipientEmail = isset($options['recipient_email']) ? $this->normalizeEmail($options['recipient_email']) : '';

        if ($recipientEmail !== '') {
            if (!$this->isValidRecipientEmail($recipientEmail)) {
                return ['success' => false, 'error' => 'A valid recipient email address is required.'];
            }
            // Recipient-restricted links are always private.
            $isPublic = false;
        }

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
            $shareId = $this->db->lastInsertId();
            $shareUrl = $this->getShareUrl($shareToken);

            if ($recipientEmail !== '') {
                $recipientToken = bin2hex(random_bytes(32));
                $recipientTokenHash = hash('sha256', $recipientToken);
                $recipientTokenExpiry = isset($options['recipient_token_expires_at']) && !empty($options['recipient_token_expires_at'])
                    ? $options['recipient_token_expires_at']
                    : date('Y-m-d H:i:s', strtotime('+' . self::DEFAULT_RECIPIENT_TOKEN_TTL_HOURS . ' hours'));

                $tokenSql = "INSERT INTO share_recipient_tokens (share_id, recipient_email, token_hash, expires_at)
                             VALUES (?, ?, ?, ?)
                             ON DUPLICATE KEY UPDATE
                                recipient_email = VALUES(recipient_email),
                                token_hash = VALUES(token_hash),
                                expires_at = VALUES(expires_at),
                                used_at = NULL";

                $tokenSaved = $this->db->query($tokenSql, [
                    $shareId,
                    $recipientEmail,
                    $recipientTokenHash,
                    $recipientTokenExpiry
                ]);

                if (!$tokenSaved) {
                    // Keep DB consistent if token creation fails.
                    $this->db->query("DELETE FROM shared_files WHERE id = ?", [$shareId]);
                    return ['success' => false, 'error' => 'Failed to create recipient access token.'];
                }

                $shareUrl = $this->getRecipientShareUrl($shareToken, $recipientEmail, $recipientToken);
            }

            return [
                'success' => true,
                'share_id' => $shareId,
                'share_token' => $shareToken,
                'share_url' => $shareUrl,
                'recipient_email' => $recipientEmail !== '' ? $recipientEmail : null,
                'recipient_share_url' => $recipientEmail !== '' ? $shareUrl : null
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
     * Get recipient-restricted share URL.
     */
    public function getRecipientShareUrl($shareToken, $recipientEmail, $recipientToken) {
        $baseUrl = getBaseUrl();
        $recipientEmail = rawurlencode($this->normalizeEmail($recipientEmail));
        return "{$baseUrl}/shared.php?token={$shareToken}&recipient={$recipientEmail}&rt={$recipientToken}";
    }

    /**
     * Get recipient restriction row for a share.
     */
    public function getRecipientRestriction($shareId) {
        $sql = "SELECT * FROM share_recipient_tokens WHERE share_id = ? LIMIT 1";
        return $this->db->fetch($sql, [$shareId]);
    }

    /**
     * Validate recipient token restrictions for a share.
     */
    public function validateRecipientAccess($shareId, $recipientEmail = null, $recipientToken = null) {
        $restriction = $this->getRecipientRestriction($shareId);

        if (!$restriction) {
            return ['valid' => true, 'restriction' => null];
        }

        $normalizedRecipient = $this->normalizeEmail($recipientEmail);
        $expectedRecipient = $this->normalizeEmail($restriction['recipient_email']);

        if ($normalizedRecipient === '' || empty($recipientToken)) {
            return [
                'valid' => false,
                'error' => 'This share link is restricted to a specific recipient and requires its full access URL.',
                'restriction' => $restriction
            ];
        }

        if (!filter_var($normalizedRecipient, FILTER_VALIDATE_EMAIL)) {
            return [
                'valid' => false,
                'error' => 'Invalid recipient address in share URL.',
                'restriction' => $restriction
            ];
        }

        if (!hash_equals($expectedRecipient, $normalizedRecipient)) {
            return [
                'valid' => false,
                'error' => 'This link is not valid for this recipient.',
                'restriction' => $restriction
            ];
        }

        if (!preg_match('/^[a-f0-9]{64}$/', $recipientToken)) {
            return [
                'valid' => false,
                'error' => 'Invalid recipient token format.',
                'restriction' => $restriction
            ];
        }

        if (!empty($restriction['used_at'])) {
            return [
                'valid' => false,
                'error' => 'This recipient link has already been used.',
                'restriction' => $restriction
            ];
        }

        if (!empty($restriction['expires_at']) && strtotime($restriction['expires_at']) < time()) {
            return [
                'valid' => false,
                'error' => 'This recipient link has expired.',
                'restriction' => $restriction
            ];
        }

        $providedHash = hash('sha256', $recipientToken);
        if (!hash_equals($restriction['token_hash'], $providedHash)) {
            return [
                'valid' => false,
                'error' => 'Invalid recipient token.',
                'restriction' => $restriction
            ];
        }

        return ['valid' => true, 'restriction' => $restriction];
    }

    /**
     * Mark recipient token as used (one-time use).
     */
    public function consumeRecipientToken($shareId) {
        $sql = "UPDATE share_recipient_tokens
                SET used_at = NOW()
                WHERE share_id = ?
                  AND used_at IS NULL
                  AND (expires_at IS NULL OR expires_at > NOW())";
        $stmt = $this->db->query($sql, [$shareId]);

        if (!$stmt) {
            return ['success' => false, 'error' => 'Failed to update recipient token.'];
        }

        if ($stmt->rowCount() < 1) {
            return ['success' => false, 'error' => 'Recipient token is no longer valid.'];
        }

        return ['success' => true];
    }

    /**
     * Regenerate a fresh recipient-restricted one-time URL for an existing share.
     */
    public function regenerateRecipientShareUrl($shareId, $userId = null, $recipientEmail = null) {
        $shareId = (int)$shareId;
        if ($shareId < 1) {
            return ['success' => false, 'error' => 'Invalid share ID.'];
        }

        $share = $this->db->fetch("SELECT * FROM shared_files WHERE id = ?", [$shareId]);
        if (!$share) {
            return ['success' => false, 'error' => 'Share not found.'];
        }

        if (!RBAC::isAdmin() && $share['shared_by_user'] !== $userId) {
            return ['success' => false, 'error' => 'Permission denied.'];
        }

        $existingRestriction = $this->getRecipientRestriction($shareId);
        $targetRecipient = $recipientEmail !== null && $recipientEmail !== ''
            ? $this->normalizeEmail($recipientEmail)
            : ($existingRestriction ? $this->normalizeEmail($existingRestriction['recipient_email']) : '');

        if (!$this->isValidRecipientEmail($targetRecipient)) {
            return ['success' => false, 'error' => 'A valid recipient email is required to regenerate the link.'];
        }

        $recipientToken = bin2hex(random_bytes(32));
        $recipientTokenHash = hash('sha256', $recipientToken);
        $recipientTokenExpiry = date('Y-m-d H:i:s', strtotime('+' . self::DEFAULT_RECIPIENT_TOKEN_TTL_HOURS . ' hours'));

        $tokenSaved = $this->db->query(
            "INSERT INTO share_recipient_tokens (share_id, recipient_email, token_hash, expires_at)
             VALUES (?, ?, ?, ?)
             ON DUPLICATE KEY UPDATE
                recipient_email = VALUES(recipient_email),
                token_hash = VALUES(token_hash),
                expires_at = VALUES(expires_at),
                used_at = NULL",
            [$shareId, $targetRecipient, $recipientTokenHash, $recipientTokenExpiry]
        );

        if (!$tokenSaved) {
            return ['success' => false, 'error' => 'Failed to regenerate recipient link token.'];
        }

        // Recipient-restricted links are private by design.
        $this->db->query("UPDATE shared_files SET is_public = FALSE WHERE id = ?", [$shareId]);

        $shareUrl = $this->getRecipientShareUrl($share['share_token'], $targetRecipient, $recipientToken);

        return [
            'success' => true,
            'share_url' => $shareUrl,
            'recipient_email' => $targetRecipient
        ];
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
        $sql = "SELECT sf.*, f.original_filename, f.file_size, f.mime_type,
                   srt.recipient_email, srt.used_at AS recipient_used_at, srt.expires_at AS recipient_expires_at
                FROM shared_files sf
                JOIN files f ON sf.file_id = f.id
            LEFT JOIN share_recipient_tokens srt ON srt.share_id = sf.id
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
                  srt.recipient_email, srt.used_at AS recipient_used_at, srt.expires_at AS recipient_expires_at,
                       u.username as shared_by_username
                FROM shared_files sf
                JOIN files f ON sf.file_id = f.id
                JOIN users u ON sf.shared_by_user = u.id
              LEFT JOIN share_recipient_tokens srt ON srt.share_id = sf.id
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
