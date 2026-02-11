<?php
// File management functions
require_once 'db.php';
require_once 'auth.php';
require_once 'rbac.php';

class FileManager {
    private $db;
    private $auth;
    
    public function __construct($db, $auth) {
        $this->db = $db;
        $this->auth = $auth;
        
        // Create uploads directory if it doesn't exist with secure permissions
        if (!file_exists(UPLOAD_DIR)) {
            mkdir(UPLOAD_DIR, 0750, true);
        }
    }
    
    // Upload file
    public function uploadFile($file, $hashAlgorithm = DEFAULT_HASH_ALGORITHM) {
        // Check permission using RBAC
        if (!RBAC::hasPermission('files.upload')) {
            return ['success' => false, 'error' => 'Permission denied.'];
        }
        
        // Validate file
        if (!isset($file['error']) || is_array($file['error'])) {
            return ['success' => false, 'error' => 'Invalid file upload.'];
        }
        
        // Check for upload errors
        if ($file['error'] !== UPLOAD_ERR_OK) {
            return ['success' => false, 'error' => 'Upload failed with error code: ' . $file['error']];
        }
        
        // Check file size
        if ($file['size'] > MAX_FILE_SIZE) {
            return ['success' => false, 'error' => 'File size exceeds maximum allowed size of ' . $this->formatBytes(MAX_FILE_SIZE)];
        }
        
        // Check quota
        $user = $this->auth->getCurrentUser();
        $accessCode = $this->auth->getCurrentAccessCode();
        
        if ($user) {
            if (($user['used_quota'] + $file['size']) > $user['upload_quota']) {
                return ['success' => false, 'error' => 'Upload would exceed your quota limit.'];
            }
        } elseif ($accessCode) {
            if (($accessCode['used_quota'] + $file['size']) > $accessCode['upload_quota']) {
                return ['success' => false, 'error' => 'Upload would exceed access code quota limit.'];
            }
        } else {
            return ['success' => false, 'error' => 'Not authenticated.'];
        }
        
        // Validate hash algorithm
        if (!in_array($hashAlgorithm, HASH_ALGORITHMS)) {
            $hashAlgorithm = DEFAULT_HASH_ALGORITHM;
        }
        
        // Generate unique filename with cryptographically secure random (32 hex characters with timestamp)
        $extension = pathinfo($file['name'], PATHINFO_EXTENSION);
        // Validate extension is safe (alphanumeric only)
        $extension = preg_replace('/[^a-zA-Z0-9]/', '', $extension);
        if (strlen($extension) > 10) {
            $extension = substr($extension, 0, 10);
        }
        $filename = bin2hex(random_bytes(16)) . '_' . time() . '.' . $extension;
        $filepath = UPLOAD_DIR . $filename;
        
        // Move uploaded file
        if (!move_uploaded_file($file['tmp_name'], $filepath)) {
            return ['success' => false, 'error' => 'Failed to save uploaded file.'];
        }
        
        // Calculate file hash
        $fileHash = hash_file($hashAlgorithm, $filepath);
        
        // Get mime type
        $mimeType = mime_content_type($filepath);
        
        // Save to database
        $sql = "INSERT INTO files (filename, original_filename, file_size, file_hash, hash_algorithm, mime_type, uploaded_by_user, uploaded_by_code) 
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)";
        
        $userId = $user ? $user['id'] : null;
        $codeId = $accessCode ? $accessCode['id'] : null;
        
        $result = $this->db->query($sql, [
            $filename,
            $file['name'],
            $file['size'],
            $fileHash,
            $hashAlgorithm,
            $mimeType,
            $userId,
            $codeId
        ]);
        
        if ($result) {
            // Update quota
            if ($user) {
                $sql = "UPDATE users SET used_quota = used_quota + ? WHERE id = ?";
                $this->db->query($sql, [$file['size'], $user['id']]);
            } elseif ($accessCode) {
                $sql = "UPDATE access_codes SET used_quota = used_quota + ? WHERE id = ?";
                $this->db->query($sql, [$file['size'], $accessCode['id']]);
            }
            
            return [
                'success' => true,
                'file_id' => $this->db->lastInsertId(),
                'filename' => $filename,
                'original_filename' => $file['name'],
                'file_hash' => $fileHash,
                'hash_algorithm' => $hashAlgorithm
            ];
        }
        
        // Clean up file if database insert failed
        unlink($filepath);
        return ['success' => false, 'error' => 'Failed to save file information.'];
    }
    
    // Get files for current user/access code
    public function getFiles() {
        $user = $this->auth->getCurrentUser();
        $accessCode = $this->auth->getCurrentAccessCode();
        
        if ($user) {
            // Admin sees all files
            if (RBAC::isAdmin()) {
                $sql = "SELECT f.*, u.username as uploaded_by_username 
                        FROM files f 
                        LEFT JOIN users u ON f.uploaded_by_user = u.id 
                        ORDER BY f.upload_date DESC";
                return $this->db->fetchAll($sql);
            } else {
                // Regular user sees their own files
                $sql = "SELECT * FROM files WHERE uploaded_by_user = ? ORDER BY upload_date DESC";
                return $this->db->fetchAll($sql, [$user['id']]);
            }
        } elseif ($accessCode) {
            // Access code sees files uploaded with that code
            $sql = "SELECT * FROM files WHERE uploaded_by_code = ? ORDER BY upload_date DESC";
            return $this->db->fetchAll($sql, [$accessCode['id']]);
        }
        
        return [];
    }
    
    // Get all files (admin only)
    public function getAllFiles() {
        if (!RBAC::isAdmin()) {
            return [];
        }
        
        $sql = "SELECT f.*, u.username as uploaded_by_username 
                FROM files f 
                LEFT JOIN users u ON f.uploaded_by_user = u.id 
                ORDER BY f.upload_date DESC";
        return $this->db->fetchAll($sql);
    }
    
    // Get file by ID
    public function getFile($fileId) {
        $sql = "SELECT * FROM files WHERE id = ?";
        return $this->db->fetch($sql, [$fileId]);
    }
    
    // Download file
    public function downloadFile($fileId) {
        $file = $this->getFile($fileId);
        
        if (!$file) {
            return ['success' => false, 'error' => 'File not found.'];
        }
        
        // Check permissions using RBAC
        $user = $this->auth->getCurrentUser();
        $accessCode = $this->auth->getCurrentAccessCode();
        
        $hasPermission = false;
        
        // Admin can download all files
        if (RBAC::isAdmin()) {
            $hasPermission = true;
        }
        // User can download their own files
        elseif ($user && $file['uploaded_by_user'] === $user['id']) {
            $hasPermission = true;
        }
        // Access code user can download files from their code
        elseif ($accessCode && $file['uploaded_by_code'] === $accessCode['id']) {
            $hasPermission = true;
        }
        
        if (!$hasPermission) {
            return ['success' => false, 'error' => 'Permission denied.'];
        }
        
        // Validate filename to prevent path traversal
        if (strpos($file['filename'], '..') !== false || strpos($file['filename'], '/') !== false || strpos($file['filename'], '\\') !== false) {
            return ['success' => false, 'error' => 'Invalid filename.'];
        }
        
        $filepath = UPLOAD_DIR . $file['filename'];
        
        if (!file_exists($filepath) || !is_file($filepath)) {
            return ['success' => false, 'error' => 'File not found on disk.'];
        }
        
        // Increment download count
        $sql = "UPDATE files SET download_count = download_count + 1 WHERE id = ?";
        $this->db->query($sql, [$fileId]);
        
        return [
            'success' => true,
            'filepath' => $filepath,
            'filename' => $file['original_filename'],
            'mime_type' => $file['mime_type']
        ];
    }
    
    // Delete file
    public function deleteFile($fileId) {
        $file = $this->getFile($fileId);
        
        if (!$file) {
            return ['success' => false, 'error' => 'File not found.'];
        }
        
        // Check permissions using RBAC
        $user = $this->auth->getCurrentUser();
        
        if (!$user) {
            return ['success' => false, 'error' => 'Permission denied.'];
        }
        
        // Use RBAC to check delete permission
        if (!RBAC::canDeleteFile($file, $user)) {
            return ['success' => false, 'error' => 'Permission denied.'];
        }
        
        // Validate filename to prevent path traversal
        if (strpos($file['filename'], '..') !== false || strpos($file['filename'], '/') !== false || strpos($file['filename'], '\\') !== false) {
            return ['success' => false, 'error' => 'Invalid filename.'];
        }
        
        $filepath = UPLOAD_DIR . $file['filename'];
        
        // Delete file from disk
        if (file_exists($filepath) && is_file($filepath)) {
            unlink($filepath);
        }
        
        // Update quota (ensure it doesn't go below zero)
        if ($file['uploaded_by_user']) {
            $sql = "UPDATE users SET used_quota = GREATEST(0, used_quota - ?) WHERE id = ?";
            $this->db->query($sql, [$file['file_size'], $file['uploaded_by_user']]);
        } elseif ($file['uploaded_by_code']) {
            $sql = "UPDATE access_codes SET used_quota = GREATEST(0, used_quota - ?) WHERE id = ?";
            $this->db->query($sql, [$file['file_size'], $file['uploaded_by_code']]);
        }
        
        // Delete from database
        $sql = "DELETE FROM files WHERE id = ?";
        $this->db->query($sql, [$fileId]);
        
        return ['success' => true];
    }
    
    /**
     * Update file expiry date (auto-delete date)
     */
    public function updateFileExpiry($fileId, $expiryDate = null) {
        // Get file to check ownership
        $sql = "SELECT * FROM files WHERE id = ?";
        $file = $this->db->fetch($sql, [$fileId]);
        
        if (!$file) {
            return ['success' => false, 'error' => 'File not found.'];
        }
        
        // Get current user
        $currentUser = $this->auth->getCurrentUser();
        
        // Check permissions using RBAC
        if (!RBAC::canDeleteFile($file, $currentUser)) {
            return ['success' => false, 'error' => 'Permission denied.'];
        }
        
        $sql = "UPDATE files SET file_expiry_date = ? WHERE id = ?";
        $result = $this->db->query($sql, [empty($expiryDate) ? null : $expiryDate, $fileId]);
        
        if ($result) {
            return ['success' => true];
        }
        
        return ['success' => false, 'error' => 'Failed to update file expiry date.'];
    }
    
    // Format bytes to human readable
    public function formatBytes($bytes, $precision = 2) {
        $units = ['B', 'KB', 'MB', 'GB', 'TB'];
        
        for ($i = 0; $bytes > 1024 && $i < count($units) - 1; $i++) {
            $bytes /= 1024;
        }
        
        return round($bytes, $precision) . ' ' . $units[$i];
    }
}
?>
