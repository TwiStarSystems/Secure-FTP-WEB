<?php
// Database connection and helper functions
require_once 'config.php';

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
            error_log("Database query error: " . $e->getMessage());
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

?>
