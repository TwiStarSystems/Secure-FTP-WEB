<?php
// File management functions
require_once 'db.php';
require_once 'auth.php';
require_once 'rbac.php';
require_once 'app_settings.php';

class FileManager {
    private $db;
    private $auth;
    private $appSettings;
    
    public function __construct($db, $auth) {
        $this->db = $db;
        $this->auth = $auth;
        $this->appSettings = new AppSettingsManager($db);

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
            $fileCountLimit = isset($accessCode['file_count_limit']) ? intval($accessCode['file_count_limit']) : 3;
            if ($fileCountLimit > 0) {
                $countRow = $this->db->fetch(
                    "SELECT COUNT(*) AS file_count FROM files WHERE uploaded_by_code = ?",
                    [$accessCode['id']]
                );
                $currentFileCount = $countRow ? intval($countRow['file_count']) : 0;

                if ($currentFileCount >= $fileCountLimit) {
                    return ['success' => false, 'error' => 'Access code file count limit reached (' . $fileCountLimit . ' files).'];
                }
            }

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

        // Duplicate file detection — same hash within the same uploader's file set
        $duplicate = $this->findDuplicate(
            $fileHash, $hashAlgorithm,
            $user ? $user['id'] : null,
            $accessCode ? $accessCode['id'] : null
        );
        if ($duplicate) {
            unlink($filepath);
            return [
                'success'           => false,
                'duplicate'         => true,
                'error'             => 'This file is identical to an existing upload: "' . $duplicate['original_filename'] . '".',
                'existing_file_id'  => (int)$duplicate['id'],
                'existing_filename' => $duplicate['original_filename']
            ];
        }

        // Get mime type
        $mimeType = mime_content_type($filepath);

        // Validate MIME type against admin-configured allowlist
        $allowedMimeTypes = $this->appSettings->getAllowedMimeTypes();
        if (!empty($allowedMimeTypes) && !in_array(strtolower((string)$mimeType), $allowedMimeTypes, true)) {
            unlink($filepath);
            return ['success' => false, 'error' => 'File type "' . $mimeType . '" is not permitted on this server.'];
        }

        // Optional ClamAV virus scan
        if ($this->appSettings->isVirusScanEnabled()) {
            $scanResult = $this->runClamAVScan($filepath);
            if ($scanResult !== null && !$scanResult['clean']) {
                unlink($filepath);
                return ['success' => false, 'error' => 'File rejected: ' . $scanResult['message']];
            }
        }

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

    /**
     * Return a duplicate file record if one with the same hash already exists
     * for the same uploader (user or access code). Returns false/null if none.
     */
    private function findDuplicate($hash, $algorithm, $userId, $codeId) {
        if ($userId !== null) {
            return $this->db->fetch(
                "SELECT id, original_filename FROM files WHERE file_hash = ? AND hash_algorithm = ? AND uploaded_by_user = ? LIMIT 1",
                [$hash, $algorithm, $userId]
            );
        }
        if ($codeId !== null) {
            return $this->db->fetch(
                "SELECT id, original_filename FROM files WHERE file_hash = ? AND hash_algorithm = ? AND uploaded_by_code = ? LIMIT 1",
                [$hash, $algorithm, $codeId]
            );
        }
        return null;
    }

    /**
     * Run an optional ClamAV scan on a file already on disk.
     * Returns null if ClamAV is unavailable or exec() is disabled (= skip silently).
     * Returns ['clean' => bool, 'message' => string] otherwise.
     */
    private function runClamAVScan($filepath) {
        if (!function_exists('exec')) {
            return null;
        }
        // Prefer the daemon client (clamdscan) — faster; fall back to standalone clamscan.
        $candidates = [
            '/usr/bin/clamdscan',   '/usr/local/bin/clamdscan',
            '/usr/bin/clamscan',    '/usr/local/bin/clamscan'
        ];
        $binary = null;
        foreach ($candidates as $candidate) {
            if (is_executable($candidate)) {
                $binary = $candidate;
                break;
            }
        }
        if ($binary === null) {
            return null; // ClamAV not installed — skip silently
        }
        $output   = [];
        $exitCode = 0;
        exec($binary . ' --no-summary ' . escapeshellarg($filepath) . ' 2>&1', $output, $exitCode);
        // 0 = clean, 1 = virus found, 2 = error
        return [
            'clean'   => $exitCode === 0,
            'message' => $exitCode === 1
                ? 'Malware detected. File has been rejected.'
                : 'Scan error: ' . trim(implode(' ', array_filter($output)))
        ];
    }
}
?>
