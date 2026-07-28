<?php
// File management functions
require_once APP_DIR . '/src/core/db.php';
require_once APP_DIR . '/src/services/auth.php';
require_once APP_DIR . '/src/services/rbac.php';
require_once APP_DIR . '/src/services/app_settings.php';

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

        // Get mime type (fast — stays synchronous)
        $mimeType = mime_content_type($filepath);

        // Validate MIME type against admin-configured allowlist
        $allowedMimeTypes = $this->appSettings->getAllowedMimeTypes();
        if (!empty($allowedMimeTypes) && !in_array(strtolower((string)$mimeType), $allowedMimeTypes, true)) {
            unlink($filepath);
            return ['success' => false, 'error' => 'File type "' . $mimeType . '" is not permitted on this server.'];
        }

        // Save to database with processing_status = 'pending'
        // Hashing, duplicate detection, virus scan, and encryption happen in the background.
        $sql = "INSERT INTO files (filename, original_filename, file_size, hash_algorithm, mime_type, uploaded_by_user, uploaded_by_code, processing_status) 
                VALUES (?, ?, ?, ?, ?, ?, ?, 'pending')";
        
        $userId = $user ? $user['id'] : null;
        $codeId = $accessCode ? $accessCode['id'] : null;
        
        $result = $this->db->query($sql, [
            $filename,
            $file['name'],
            $file['size'],
            $hashAlgorithm,
            $mimeType,
            $userId,
            $codeId
        ]);
        
        if ($result) {
            $newFileId = $this->db->lastInsertId();

            // Update quota immediately
            if ($user) {
                $sql = "UPDATE users SET used_quota = used_quota + ? WHERE id = ?";
                $this->db->query($sql, [$file['size'], $user['id']]);
            } elseif ($accessCode) {
                $sql = "UPDATE access_codes SET used_quota = used_quota + ? WHERE id = ?";
                $this->db->query($sql, [$file['size'], $accessCode['id']]);
            }

            // Spawn background worker for hashing + encryption
            $this->spawnProcessor($newFileId, $hashAlgorithm);
            
            return [
                'success' => true,
                'file_id' => $newFileId,
                'filename' => $filename,
                'original_filename' => $file['name'],
                'processing' => true
            ];
        }
        
        // Clean up file if database insert failed
        unlink($filepath);
        return ['success' => false, 'error' => 'Failed to save file information.'];
    }

    /**
     * Spawn the background file processor (hashing, dedup, encryption).
     * Fails the file immediately (instead of leaving it stuck at 'pending')
     * if the environment can't actually run a background worker.
     */
    private function spawnProcessor($fileId, $hashAlgorithm) {
        if (!function_exists('exec')) {
            $this->failProcessing($fileId, 'Background processing is unavailable on this server (exec() is disabled). Contact an administrator.');
            return;
        }

        $phpBin = self::findPhpCliBinary();
        if ($phpBin === null) {
            $this->failProcessing($fileId, 'Background processing is unavailable: no PHP CLI binary could be located on this server.');
            return;
        }

        $script = APP_DIR . '/src/services/process_file.php';
        $cmd = escapeshellarg($phpBin) . ' '
             . escapeshellarg($script) . ' '
             . escapeshellarg((string)$fileId) . ' '
             . escapeshellarg($hashAlgorithm)
             . ' > /dev/null 2>&1 &';
        exec($cmd);
    }

    /**
     * Mark a file as failed before processing ever started, and log why.
     */
    private function failProcessing($fileId, $message) {
        error_log("FileManager::spawnProcessor: {$message} (file ID {$fileId})");
        $this->db->query(
            "UPDATE files SET processing_status = 'failed', processing_error = ? WHERE id = ?",
            [$message, $fileId]
        );
    }

    /**
     * Locate the PHP CLI binary.  PHP_BINARY points to php-fpm when running
     * under FPM, which cannot execute CLI scripts.  Walk a short list of
     * well-known paths, then fall back to resolving 'php' on PATH.
     * Returns null if no usable CLI binary can be found at all.
     */
    private static function findPhpCliBinary() {
        // If we are already in CLI, PHP_BINARY is fine.
        if (PHP_SAPI === 'cli' || PHP_SAPI === 'cli-server') {
            return PHP_BINARY ?: 'php';
        }

        // Common CLI binary locations (version-specific first)
        $majorMinor = PHP_MAJOR_VERSION . '.' . PHP_MINOR_VERSION;
        $candidates = [
            '/usr/bin/php' . $majorMinor,       // e.g. /usr/bin/php8.4
            '/usr/bin/php' . PHP_MAJOR_VERSION,  // e.g. /usr/bin/php8
            '/usr/bin/php',
            '/usr/local/bin/php',
        ];

        foreach ($candidates as $path) {
            if (is_executable($path)) {
                return $path;
            }
        }

        // Last resort: see if 'php' resolves to something on PATH at all.
        if (function_exists('shell_exec')) {
            $resolved = trim((string) @shell_exec('command -v php 2>/dev/null'));
            if ($resolved !== '' && is_executable($resolved)) {
                return $resolved;
            }
        }

        return null; // No usable PHP CLI binary found.
    }

    /**
     * Get the processing status of a file.
     */
    public function getFileProcessingStatus($fileId) {
        $sql = "SELECT id, processing_status, processing_error, file_hash, hash_algorithm FROM files WHERE id = ?";
        return $this->db->fetch($sql, [$fileId]);
    }
    
    // Get files for current user/access code
    public function getFiles() {
        $user = $this->auth->getCurrentUser();
        $accessCode = $this->auth->getCurrentAccessCode();
        
        if ($user) {
            // All users (including admin) see only their own files in "My Files"
            $sql = "SELECT * FROM files WHERE uploaded_by_user = ? ORDER BY upload_date DESC";
            return $this->db->fetchAll($sql, [$user['id']]);
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

    /**
     * Get all files with share status info (admin only).
     * Returns each file with active_share_count and share_types summary.
     */
    public function getAllFilesWithShareStatus() {
        if (!RBAC::isAdmin()) {
            return [];
        }

        $sql = "SELECT f.*, u.username as uploaded_by_username,
                       COUNT(DISTINCT sf.id) AS total_shares,
                       SUM(CASE WHEN sf.is_active = TRUE
                                 AND (sf.expires_at IS NULL OR sf.expires_at > NOW())
                                 AND (sf.max_downloads IS NULL OR sf.download_count < sf.max_downloads)
                            THEN 1 ELSE 0 END) AS active_shares,
                       SUM(CASE WHEN sf.is_public = TRUE AND sf.is_active = TRUE
                                 AND (sf.expires_at IS NULL OR sf.expires_at > NOW())
                                 AND (sf.max_downloads IS NULL OR sf.download_count < sf.max_downloads)
                            THEN 1 ELSE 0 END) AS public_shares
                FROM files f
                LEFT JOIN users u ON f.uploaded_by_user = u.id
                LEFT JOIN shared_files sf ON sf.file_id = f.id
                GROUP BY f.id
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
            'mime_type' => $file['mime_type'],
            'file_size' => (int)$file['file_size'],
            'encryption_iv' => $file['encryption_iv'] ?? null
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

        // Files rejected as duplicates or malware during background processing are already
        // unlinked and quota-refunded by process_file.php before being marked 'failed'. Only
        // refund here if the file was still on disk, so those don't get refunded a second time.
        $existedOnDisk = file_exists($filepath) && is_file($filepath);

        // Delete file from disk
        if ($existedOnDisk) {
            unlink($filepath);
        }

        // Update quota (ensure it doesn't go below zero)
        if ($existedOnDisk) {
            if ($file['uploaded_by_user']) {
                $sql = "UPDATE users SET used_quota = GREATEST(0, used_quota - ?) WHERE id = ?";
                $this->db->query($sql, [$file['file_size'], $file['uploaded_by_user']]);
            } elseif ($file['uploaded_by_code']) {
                $sql = "UPDATE access_codes SET used_quota = GREATEST(0, used_quota - ?) WHERE id = ?";
                $this->db->query($sql, [$file['file_size'], $file['uploaded_by_code']]);
            }
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

    /**
     * Check whether file encryption at rest is enabled and properly configured.
     */
    public static function isEncryptionEnabled() {
        return defined('FILE_ENCRYPTION_KEY')
            && FILE_ENCRYPTION_KEY !== 'CHANGE_THIS_KEY'
            && strlen(FILE_ENCRYPTION_KEY) === 64
            && ctype_xdigit(FILE_ENCRYPTION_KEY);
    }

    /**
     * Encrypt a file on disk in-place using AES-256-GCM with chunked streaming.
     *
     * Format: sequential blocks of [4-byte BE ciphertext length][ciphertext][16-byte GCM tag].
     * Each 1 MB plaintext chunk is encrypted with a per-chunk IV derived from
     * the base IV XORed with a big-endian chunk counter.
     *
     * @param  string $filepath  Absolute path to the plaintext file.
     * @return array  ['success' => bool, 'iv' => hex-encoded 12-byte base IV] on success.
     */
    public static function encryptFile($filepath) {
        $key = hex2bin(FILE_ENCRYPTION_KEY);
        if (strlen($key) !== 32) {
            return ['success' => false, 'error' => 'Invalid encryption key length.'];
        }

        $baseIv = random_bytes(12);
        $chunkSize = 1048576; // 1 MB
        $tempPath = $filepath . '.enc';

        $in  = fopen($filepath, 'rb');
        $out = fopen($tempPath, 'wb');
        if ($in === false || $out === false) {
            if ($in)  fclose($in);
            if ($out) fclose($out);
            @unlink($tempPath);
            return ['success' => false, 'error' => 'Could not open file for encryption.'];
        }

        $chunkIndex = 0;
        while (!feof($in)) {
            $chunk = fread($in, $chunkSize);
            if ($chunk === '' || $chunk === false) break;

            $iv = self::deriveChunkIv($baseIv, $chunkIndex);
            $tag = '';
            $encrypted = openssl_encrypt($chunk, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $iv, $tag, '', 16);
            if ($encrypted === false) {
                fclose($in);
                fclose($out);
                @unlink($tempPath);
                return ['success' => false, 'error' => 'openssl_encrypt failed on chunk ' . $chunkIndex];
            }

            fwrite($out, pack('N', strlen($encrypted)));
            fwrite($out, $encrypted);
            fwrite($out, $tag);

            $chunkIndex++;
        }

        fclose($in);
        fclose($out);

        // Atomic replace: remove original, rename encrypted file
        unlink($filepath);
        rename($tempPath, $filepath);

        return ['success' => true, 'iv' => bin2hex($baseIv)];
    }

    /**
     * Decrypt an AES-256-GCM encrypted file and stream it directly to the output buffer.
     *
     * @param  string      $filepath  Path to the encrypted file on disk.
     * @param  string      $ivHex     Hex-encoded 12-byte base IV from the database.
     * @return bool        True on success, false on failure (tampered data or wrong key).
     */
    public static function decryptFileStream($filepath, $ivHex) {
        $key = hex2bin(FILE_ENCRYPTION_KEY);
        $baseIv = hex2bin($ivHex);

        $fh = fopen($filepath, 'rb');
        if ($fh === false) return false;

        $chunkIndex = 0;
        while (!feof($fh)) {
            $lenData = fread($fh, 4);
            if ($lenData === false || strlen($lenData) < 4) break;

            $len = unpack('N', $lenData)[1];
            if ($len === 0 || $len > 1048576 + 256) break; // sanity: no chunk larger than ~1 MB + GCM overhead

            $ciphertext = '';
            $remaining = $len;
            while ($remaining > 0 && !feof($fh)) {
                $read = fread($fh, $remaining);
                if ($read === false) break;
                $ciphertext .= $read;
                $remaining -= strlen($read);
            }

            $tag = '';
            $tagRemaining = 16;
            while ($tagRemaining > 0 && !feof($fh)) {
                $read = fread($fh, $tagRemaining);
                if ($read === false) break;
                $tag .= $read;
                $tagRemaining -= strlen($read);
            }

            if (strlen($ciphertext) !== $len || strlen($tag) !== 16) {
                fclose($fh);
                return false;
            }

            $iv = self::deriveChunkIv($baseIv, $chunkIndex);
            $decrypted = openssl_decrypt($ciphertext, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $iv, $tag);
            if ($decrypted === false) {
                fclose($fh);
                return false; // Authentication failed — tampered data or wrong key
            }

            echo $decrypted;
            flush();

            $chunkIndex++;
        }

        fclose($fh);
        return true;
    }

    /**
     * Derive a per-chunk IV by XORing the first 4 bytes of the base IV with a big-endian chunk counter.
     */
    private static function deriveChunkIv($baseIv, $chunkIndex) {
        $iv = $baseIv;
        $counter = pack('N', $chunkIndex);
        for ($i = 0; $i < 4; $i++) {
            $iv[$i] = $iv[$i] ^ $counter[$i];
        }
        return $iv;
    }
}
