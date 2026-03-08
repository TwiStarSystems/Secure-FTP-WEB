<?php
// Security monitoring utilities for abuse prevention and audit logging
require_once 'db.php';

class SecurityMonitor {
    private $db;

    public function __construct($db) {
        $this->db = $db;
        $this->ensureSchema();
    }

    public function getClientIp() {
        if (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
            $parts = explode(',', $_SERVER['HTTP_X_FORWARDED_FOR']);
            return trim($parts[0]);
        }

        if (!empty($_SERVER['HTTP_X_REAL_IP'])) {
            return trim($_SERVER['HTTP_X_REAL_IP']);
        }

        return $_SERVER['REMOTE_ADDR'] ?? 'unknown';
    }

    public function registerRequest($actionType, $identifier, $maxRequests, $windowSeconds, $lockoutSeconds) {
        $state = $this->getCounterState($actionType, $identifier);
        $now = time();

        if (!empty($state['lockout_until']) && strtotime($state['lockout_until']) > $now) {
            return [
                'allowed' => false,
                'retry_after' => strtotime($state['lockout_until']) - $now
            ];
        }

        $windowStartTs = $now - $windowSeconds;
        $count = 1;
        if ($state && !empty($state['last_attempt']) && strtotime($state['last_attempt']) >= $windowStartTs) {
            $count = intval($state['attempt_count']) + 1;
        }

        $lockoutUntil = null;
        if ($count > $maxRequests) {
            $lockoutUntil = date('Y-m-d H:i:s', $now + $lockoutSeconds);
        }

        $this->saveCounterState($actionType, $identifier, $count, $lockoutUntil);

        if ($lockoutUntil !== null) {
            return [
                'allowed' => false,
                'retry_after' => $lockoutSeconds
            ];
        }

        return [
            'allowed' => true,
            'retry_after' => 0
        ];
    }

    public function getLockStatus($actionType, $identifier) {
        $state = $this->getCounterState($actionType, $identifier);
        if (!$state || empty($state['lockout_until'])) {
            return ['locked' => false, 'retry_after' => 0];
        }

        $remaining = strtotime($state['lockout_until']) - time();
        if ($remaining <= 0) {
            return ['locked' => false, 'retry_after' => 0];
        }

        return ['locked' => true, 'retry_after' => $remaining];
    }

    public function registerFailure($actionType, $identifier, $maxAttempts, $windowSeconds, $lockoutSeconds) {
        $state = $this->getCounterState($actionType, $identifier);
        $now = time();

        if (!empty($state['lockout_until']) && strtotime($state['lockout_until']) > $now) {
            return [
                'locked' => true,
                'retry_after' => strtotime($state['lockout_until']) - $now
            ];
        }

        $windowStartTs = $now - $windowSeconds;
        $count = 1;
        if ($state && !empty($state['last_attempt']) && strtotime($state['last_attempt']) >= $windowStartTs) {
            $count = intval($state['attempt_count']) + 1;
        }

        $lockoutUntil = null;
        $locked = false;
        $retryAfter = 0;

        if ($count >= $maxAttempts) {
            $lockoutUntil = date('Y-m-d H:i:s', $now + $lockoutSeconds);
            $locked = true;
            $retryAfter = $lockoutSeconds;
        }

        $this->saveCounterState($actionType, $identifier, $count, $lockoutUntil);

        return [
            'locked' => $locked,
            'retry_after' => $retryAfter
        ];
    }

    public function clearCounter($actionType, $identifier) {
        $this->db->query(
            "DELETE FROM abuse_counters WHERE action_type = ? AND identifier = ?",
            [$actionType, $identifier]
        );
    }

    public function logEvent($eventType, $severity = 'info', $userId = null, $identifier = '', $context = []) {
        $ip = $this->getClientIp();
        $contextJson = json_encode($context, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);

        $this->db->query(
            "INSERT INTO security_audit_events (event_type, severity, user_id, ip_address, identifier, context_json)
             VALUES (?, ?, ?, ?, ?, ?)",
            [$eventType, $severity, $userId, $ip, $identifier, $contextJson]
        );

        if (in_array($severity, ['warning', 'critical'], true)) {
            error_log('[SECURITY][' . strtoupper($severity) . '] ' . $eventType . ' ip=' . $ip . ' id=' . $identifier);
        }
    }

    public function cleanupOldData() {
        $this->db->query(
            "DELETE FROM abuse_counters
             WHERE (lockout_until IS NULL OR lockout_until < NOW())
             AND last_attempt < DATE_SUB(NOW(), INTERVAL 2 DAY)"
        );

        $this->db->query(
            "DELETE FROM security_audit_events
             WHERE created_at < DATE_SUB(NOW(), INTERVAL 90 DAY)"
        );
    }

    public function getRecentEvents($limit = 200) {
        $limit = max(1, min(1000, intval($limit)));

        $sql = "SELECT e.*, u.username
                FROM security_audit_events e
                LEFT JOIN users u ON e.user_id = u.id
                ORDER BY e.created_at DESC
                LIMIT " . $limit;

        return $this->db->fetchAll($sql) ?: [];
    }

    public function getFilteredEvents($filters = [], $limit = 2000) {
        $limit = max(1, min(10000, intval($limit)));

        $sql = "SELECT e.*, u.username
                FROM security_audit_events e
                LEFT JOIN users u ON e.user_id = u.id
                WHERE 1=1";

        $params = [];

        if (!empty($filters['severity']) && in_array($filters['severity'], ['info', 'warning', 'critical'], true)) {
            $sql .= " AND e.severity = ?";
            $params[] = $filters['severity'];
        }

        if (!empty($filters['event_type'])) {
            $sql .= " AND e.event_type = ?";
            $params[] = $filters['event_type'];
        }

        if (!empty($filters['date_from'])) {
            $sql .= " AND e.created_at >= ?";
            $params[] = $filters['date_from'] . ' 00:00:00';
        }

        if (!empty($filters['date_to'])) {
            $sql .= " AND e.created_at <= ?";
            $params[] = $filters['date_to'] . ' 23:59:59';
        }

        if (!empty($filters['search'])) {
            $searchLike = '%' . $filters['search'] . '%';
            $sql .= " AND (
                e.event_type LIKE ?
                OR e.ip_address LIKE ?
                OR e.identifier LIKE ?
                OR e.context_json LIKE ?
                OR u.username LIKE ?
            )";
            $params[] = $searchLike;
            $params[] = $searchLike;
            $params[] = $searchLike;
            $params[] = $searchLike;
            $params[] = $searchLike;
        }

        $sql .= " ORDER BY e.created_at DESC LIMIT " . $limit;

        return $this->db->fetchAll($sql, $params) ?: [];
    }

    public function getDistinctEventTypes($limit = 500) {
        $limit = max(1, min(2000, intval($limit)));

        $sql = "SELECT DISTINCT event_type
                FROM security_audit_events
                ORDER BY event_type ASC
                LIMIT " . $limit;

        $rows = $this->db->fetchAll($sql) ?: [];
        $types = [];

        foreach ($rows as $row) {
            if (!empty($row['event_type'])) {
                $types[] = $row['event_type'];
            }
        }

        return $types;
    }

    private function getCounterState($actionType, $identifier) {
        return $this->db->fetch(
            "SELECT * FROM abuse_counters WHERE action_type = ? AND identifier = ? LIMIT 1",
            [$actionType, $identifier]
        );
    }

    private function saveCounterState($actionType, $identifier, $count, $lockoutUntil = null) {
        $this->db->query(
            "INSERT INTO abuse_counters (action_type, identifier, attempt_count, first_attempt, last_attempt, lockout_until)
             VALUES (?, ?, ?, NOW(), NOW(), ?)
             ON DUPLICATE KEY UPDATE
                attempt_count = VALUES(attempt_count),
                last_attempt = NOW(),
                lockout_until = VALUES(lockout_until)",
            [$actionType, $identifier, $count, $lockoutUntil]
        );
    }

    private function ensureSchema() {
        $this->db->query("CREATE TABLE IF NOT EXISTS abuse_counters (
            id INT AUTO_INCREMENT PRIMARY KEY,
            action_type VARCHAR(64) NOT NULL,
            identifier VARCHAR(191) NOT NULL,
            attempt_count INT DEFAULT 0,
            first_attempt DATETIME DEFAULT CURRENT_TIMESTAMP,
            last_attempt DATETIME DEFAULT CURRENT_TIMESTAMP,
            lockout_until DATETIME NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            UNIQUE KEY uniq_action_identifier (action_type, identifier),
            INDEX idx_lockout_until (lockout_until),
            INDEX idx_last_attempt (last_attempt)
        )");

        $this->db->query("CREATE TABLE IF NOT EXISTS security_audit_events (
            id BIGINT AUTO_INCREMENT PRIMARY KEY,
            event_type VARCHAR(100) NOT NULL,
            severity ENUM('info', 'warning', 'critical') DEFAULT 'info',
            user_id INT NULL,
            ip_address VARCHAR(64) NOT NULL,
            identifier VARCHAR(191) DEFAULT '',
            context_json TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL,
            INDEX idx_event_type (event_type),
            INDEX idx_created_at (created_at),
            INDEX idx_ip_address (ip_address)
        )");
    }
}
?>