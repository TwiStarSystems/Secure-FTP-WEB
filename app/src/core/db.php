<?php
// Database connection and helper functions
require_once APP_DIR . '/src/core/config.php';

class Database {
    private $conn;
    
    public function __construct() {
        try {
            $this->conn = new PDO(
                "mysql:host=" . DB_HOST . ";dbname=" . DB_NAME,
                DB_USER,
                DB_PASS,
                array(PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION)
            );
        } catch(PDOException $e) {
            die("Database connection failed: " . $e->getMessage());
        }
    }
    
    public function getConnection() {
        return $this->conn;
    }
    
    public function query($sql, $params = []) {
        try {
            $stmt = $this->conn->prepare($sql);
            $stmt->execute($params);
            return $stmt;
        } catch(PDOException $e) {
            // Log the detailed error for administrators
            error_log("Database query error: " . $e->getMessage());
            // Return a generic error to prevent information disclosure
            return false;
        }
    }
    
    public function fetch($sql, $params = []) {
        $stmt = $this->query($sql, $params);
        return $stmt ? $stmt->fetch(PDO::FETCH_ASSOC) : false;
    }
    
    public function fetchAll($sql, $params = []) {
        $stmt = $this->query($sql, $params);
        return $stmt ? $stmt->fetchAll(PDO::FETCH_ASSOC) : false;
    }
    
    public function lastInsertId() {
        return $this->conn->lastInsertId();
    }
}

// Clean up expired temporary users
function cleanupExpiredUsers($db) {
    $sql = "DELETE FROM users WHERE is_temporary = TRUE AND expiry_date < NOW()";
    $db->query($sql);
}

// Clean up expired access codes
function cleanupExpiredAccessCodes($db) {
    $sql = "UPDATE access_codes SET is_active = FALSE WHERE expiry_date < NOW()";
    $db->query($sql);
}

// Clean up old login attempts (older than 24 hours)
function cleanupOldLoginAttempts($db) {
    $sql = "DELETE FROM login_attempts WHERE attempt_time < DATE_SUB(NOW(), INTERVAL 24 HOUR)";
    $db->query($sql);
}

// Clean up old MFA email codes
function cleanupOldMfaEmailCodes($db) {
    $sql = "DELETE FROM mfa_email_codes WHERE expires_at < NOW() OR used_at IS NOT NULL";
    $db->query($sql);
}

// Mark files stuck in the async processing pipeline (background worker crashed,
// was never spawned, or never finished) as 'failed' instead of leaving them to
// poll forever with no resolution. Does not touch quota or the file on disk —
// the original bytes are still there, just unhashed/unencrypted; deleting the
// row via FileManager::deleteFile() is what reconciles quota and disk.
function cleanupStuckProcessingFiles($db, $maxAgeSeconds = PROCESSING_STUCK_TIMEOUT_SECONDS) {
    $sql = "UPDATE files
            SET processing_status = 'failed',
                processing_error = 'Processing timed out — the background worker did not finish in time.'
            WHERE processing_status IN ('pending', 'processing')
              AND upload_date < DATE_SUB(NOW(), INTERVAL ? SECOND)";
    $db->query($sql, [$maxAgeSeconds]);
}

?>
