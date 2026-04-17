#!/usr/bin/env php
<?php
/**
 * Background file processor — performs hashing, duplicate detection,
 * optional virus scanning, and encryption after a file has been received.
 *
 * Usage (called internally by FileManager::spawnProcessor):
 *   php process_file.php <file_id> <hash_algorithm>
 *
 * Must be invoked from CLI only.
 */

if (PHP_SAPI !== 'cli') {
    http_response_code(403);
    exit('CLI only');
}

if ($argc < 3) {
    fwrite(STDERR, "Usage: php process_file.php <file_id> <hash_algorithm>\n");
    exit(1);
}

$fileId        = (int) $argv[1];
$hashAlgorithm = $argv[2];

// Bootstrap the application
define('APP_BASE', dirname(__DIR__, 2));
define('APP_DIR', APP_BASE . '/app');
require_once APP_DIR . '/src/core/config.php';
require_once APP_DIR . '/src/core/db.php';
require_once APP_DIR . '/src/services/app_settings.php';
require_once APP_DIR . '/src/services/files.php';

$db = new Database();

// ------------------------------------------------------------------
// Helper: update the processing state of the file row
// ------------------------------------------------------------------
function setProcessingStatus($db, $fileId, $status, $error = null) {
    $db->query(
        "UPDATE files SET processing_status = ?, processing_error = ? WHERE id = ?",
        [$status, $error, $fileId]
    );
}

// Mark as "processing"
setProcessingStatus($db, $fileId, 'processing');

// Fetch the file row
$file = $db->fetch("SELECT * FROM files WHERE id = ?", [$fileId]);
if (!$file) {
    fwrite(STDERR, "File ID {$fileId} not found in database.\n");
    exit(1);
}

$filepath = UPLOAD_DIR . $file['filename'];
if (!file_exists($filepath) || !is_file($filepath)) {
    setProcessingStatus($db, $fileId, 'failed', 'File not found on disk.');
    exit(1);
}

// Validate hash algorithm
if (!in_array($hashAlgorithm, HASH_ALGORITHMS, true)) {
    $hashAlgorithm = DEFAULT_HASH_ALGORITHM;
}

// ------------------------------------------------------------------
// 1. Compute file hash
// ------------------------------------------------------------------
$fileHash = hash_file($hashAlgorithm, $filepath);
if ($fileHash === false) {
    setProcessingStatus($db, $fileId, 'failed', 'Hashing failed.');
    exit(1);
}

// ------------------------------------------------------------------
// 2. Duplicate detection
// ------------------------------------------------------------------
$userId = $file['uploaded_by_user'];
$codeId = $file['uploaded_by_code'];

$duplicate = null;
if ($userId !== null) {
    $duplicate = $db->fetch(
        "SELECT id, original_filename FROM files WHERE file_hash = ? AND hash_algorithm = ? AND uploaded_by_user = ? AND id != ? LIMIT 1",
        [$fileHash, $hashAlgorithm, $userId, $fileId]
    );
} elseif ($codeId !== null) {
    $duplicate = $db->fetch(
        "SELECT id, original_filename FROM files WHERE file_hash = ? AND hash_algorithm = ? AND uploaded_by_code = ? AND id != ? LIMIT 1",
        [$fileHash, $hashAlgorithm, $codeId, $fileId]
    );
}

if ($duplicate) {
    // Remove file from disk and roll back quota
    @unlink($filepath);

    if ($userId !== null) {
        $db->query("UPDATE users SET used_quota = GREATEST(0, used_quota - ?) WHERE id = ?", [$file['file_size'], $userId]);
    } elseif ($codeId !== null) {
        $db->query("UPDATE access_codes SET used_quota = GREATEST(0, used_quota - ?) WHERE id = ?", [$file['file_size'], $codeId]);
    }

    setProcessingStatus($db, $fileId, 'failed',
        'Duplicate of existing file: "' . $duplicate['original_filename'] . '".'
    );
    // Store duplicate metadata for the UI
    $db->query(
        "UPDATE files SET file_hash = ?, hash_algorithm = ? WHERE id = ?",
        [$fileHash, $hashAlgorithm, $fileId]
    );
    exit(0);
}

// ------------------------------------------------------------------
// 3. Optional ClamAV virus scan
// ------------------------------------------------------------------
$appSettings = new AppSettingsManager($db);
if ($appSettings->isVirusScanEnabled() && function_exists('exec')) {
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
    if ($binary !== null) {
        $output   = [];
        $exitCode = 0;
        exec($binary . ' --no-summary ' . escapeshellarg($filepath) . ' 2>&1', $output, $exitCode);
        if ($exitCode === 1) {
            @unlink($filepath);
            if ($userId !== null) {
                $db->query("UPDATE users SET used_quota = GREATEST(0, used_quota - ?) WHERE id = ?", [$file['file_size'], $userId]);
            } elseif ($codeId !== null) {
                $db->query("UPDATE access_codes SET used_quota = GREATEST(0, used_quota - ?) WHERE id = ?", [$file['file_size'], $codeId]);
            }
            setProcessingStatus($db, $fileId, 'failed', 'Malware detected. File has been rejected.');
            exit(0);
        }
    }
}

// ------------------------------------------------------------------
// 4. Encrypt file at rest (AES-256-GCM)
// ------------------------------------------------------------------
$encryptionIv = null;
if (FileManager::isEncryptionEnabled()) {
    $encResult = FileManager::encryptFile($filepath);
    if (!$encResult['success']) {
        setProcessingStatus($db, $fileId, 'failed', 'Encryption failed: ' . $encResult['error']);
        exit(1);
    }
    $encryptionIv = $encResult['iv'];
}

// ------------------------------------------------------------------
// 5. Finalize — write hash, encryption IV, mark ready
// ------------------------------------------------------------------
$db->query(
    "UPDATE files SET file_hash = ?, hash_algorithm = ?, encryption_iv = ?, processing_status = 'ready', processing_error = NULL WHERE id = ?",
    [$fileHash, $hashAlgorithm, $encryptionIv, $fileId]
);

exit(0);
