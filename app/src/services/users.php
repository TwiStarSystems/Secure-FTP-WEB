<?php
// User management functions (admin only)
require_once APP_DIR . '/src/core/db.php';
require_once APP_DIR . '/src/services/rbac.php';

class UserManager {
    private $db;
    private const ACCESS_CODE_LENGTH = 7;
    private const ACCESS_CODE_CHARSET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
    
    public function __construct($db) {
        $this->db = $db;
        $this->ensureAccessCodeSchema();
    }

    private function ensureAccessCodeSchema() {
        $hasFileLimitColumn = $this->db->fetch("SHOW COLUMNS FROM access_codes LIKE 'file_count_limit'");
        if (!$hasFileLimitColumn) {
            $this->db->query("ALTER TABLE access_codes ADD COLUMN file_count_limit INT NOT NULL DEFAULT 3 AFTER upload_quota");
        }
    }
    
    // Create new user
    public function createUser($username, $password, $email, $role = 'user', $uploadQuota = 1073741824, $isTemporary = false, $expiryDate = null) {
        $username = strtolower(trim((string)$username));

        // Validate input
        if (empty($username) || empty($password)) {
            return ['success' => false, 'error' => 'Username and password are required.'];
        }

        if (!preg_match('/^[a-z0-9._-]{3,50}$/', $username)) {
            return ['success' => false, 'error' => 'Username must be lowercase only (a-z, 0-9, dot, underscore, hyphen) and 3-50 characters.'];
        }
        
        // Validate role
        if (!in_array($role, ['admin', 'user'])) {
            $role = 'user';
        }
        
        // Check if username exists
        $sql = "SELECT id FROM users WHERE username = ?";
        $existing = $this->db->fetch($sql, [$username]);
        
        if ($existing) {
            return ['success' => false, 'error' => 'Username already exists.'];
        }
        
        // Hash password
        $passwordHash = password_hash($password, PASSWORD_DEFAULT);
        
        // Set is_admin for backward compatibility
        $isAdmin = ($role === 'admin');
        
        // Insert user
        $sql = "INSERT INTO users (username, password_hash, email, role, is_admin, upload_quota, is_temporary, expiry_date) 
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)";
        
        $result = $this->db->query($sql, [
            $username,
            $passwordHash,
            $email,
            $role,
            $isAdmin,
            $uploadQuota,
            $isTemporary,
            $expiryDate
        ]);
        
        if ($result) {
            return ['success' => true, 'user_id' => $this->db->lastInsertId()];
        }
        
        return ['success' => false, 'error' => 'Failed to create user.'];
    }
    
    // Update user
    public function updateUser($userId, $data) {
        $updates = [];
        $params = [];

        if (isset($data['username'])) {
            $username = strtolower(trim((string)$data['username']));
            if ($username === '') {
                return ['success' => false, 'error' => 'Username cannot be empty.'];
            }

            if (!preg_match('/^[a-z0-9._-]{3,50}$/', $username)) {
                return ['success' => false, 'error' => 'Username must be lowercase only (a-z, 0-9, dot, underscore, hyphen) and 3-50 characters.'];
            }

            $existingUser = $this->db->fetch(
                "SELECT id FROM users WHERE username = ? AND id != ? LIMIT 1",
                [$username, $userId]
            );

            if ($existingUser) {
                return ['success' => false, 'error' => 'Username already exists.'];
            }

            $updates[] = "username = ?";
            $params[] = $username;
        }
        
        if (isset($data['email'])) {
            $updates[] = "email = ?";
            $params[] = $data['email'];
        }
        
        if (isset($data['upload_quota'])) {
            $updates[] = "upload_quota = ?";
            $params[] = $data['upload_quota'];
        }
        
        // Handle role update
        if (isset($data['role'])) {
            if (in_array($data['role'], ['admin', 'user'])) {
                $updates[] = "role = ?";
                $params[] = $data['role'];
                // Also update is_admin for backward compatibility
                $updates[] = "is_admin = ?";
                $params[] = ($data['role'] === 'admin');
            }
        } elseif (isset($data['is_admin'])) {
            // Backward compatibility: if is_admin is set, update role too
            $updates[] = "is_admin = ?";
            $params[] = $data['is_admin'];
            $updates[] = "role = ?";
            $params[] = $data['is_admin'] ? 'admin' : 'user';
        }
        
        if (isset($data['is_active'])) {
            $updates[] = "is_active = ?";
            $params[] = $data['is_active'];
        }
        
        if (isset($data['expiry_date'])) {
            $updates[] = "expiry_date = ?";
            $params[] = $data['expiry_date'];
        }
        
        if (isset($data['password']) && !empty($data['password'])) {
            $updates[] = "password_hash = ?";
            $params[] = password_hash($data['password'], PASSWORD_DEFAULT);
        }
        
        if (empty($updates)) {
            return ['success' => false, 'error' => 'No fields to update.'];
        }
        
        $params[] = $userId;
        $sql = "UPDATE users SET " . implode(", ", $updates) . " WHERE id = ?";
        
        $result = $this->db->query($sql, $params);
        
        if ($result) {
            return ['success' => true];
        }
        
        return ['success' => false, 'error' => 'Failed to update user.'];
    }
    
    // Delete user
    public function deleteUser($userId) {
        // Get user's files to delete
        $sql = "SELECT filename FROM files WHERE uploaded_by_user = ?";
        $files = $this->db->fetchAll($sql, [$userId]);
        
        // Delete files from disk
        foreach ($files as $file) {
            // Validate filename to prevent path traversal
            if (strpos($file['filename'], '..') !== false || strpos($file['filename'], '/') !== false || strpos($file['filename'], '\\') !== false) {
                continue;
            }
            $filepath = UPLOAD_DIR . $file['filename'];
            if (file_exists($filepath) && is_file($filepath)) {
                unlink($filepath);
            }
        }
        
        // Delete user (cascade will delete files from database)
        $sql = "DELETE FROM users WHERE id = ?";
        $result = $this->db->query($sql, [$userId]);
        
        if ($result) {
            return ['success' => true];
        }
        
        return ['success' => false, 'error' => 'Failed to delete user.'];
    }
    
    // Get all users
    public function getAllUsers() {
        $sql = "SELECT id, username, email, role, is_admin, upload_quota, used_quota, is_temporary, expiry_date, created_at, last_login, is_active 
                FROM users ORDER BY created_at DESC";
        return $this->db->fetchAll($sql);
    }
    
    // Get user by ID
    public function getUser($userId) {
        $sql = "SELECT id, username, email, role, is_admin, upload_quota, used_quota, is_temporary, expiry_date, created_at, last_login, is_active 
                FROM users WHERE id = ?";
        return $this->db->fetch($sql, [$userId]);
    }
    
    private function normalizeAccessCode($code) {
        return strtoupper(trim((string)$code));
    }

    private function isValidAccessCode($code) {
        return preg_match('/^[A-Z0-9]{' . self::ACCESS_CODE_LENGTH . '}$/', $code) === 1;
    }

    private function accessCodeExists($code) {
        $row = $this->db->fetch("SELECT id FROM access_codes WHERE code = ? LIMIT 1", [$code]);
        return !empty($row);
    }

    private function generateRandomAccessCode() {
        $maxIndex = strlen(self::ACCESS_CODE_CHARSET) - 1;
        $code = '';

        for ($i = 0; $i < self::ACCESS_CODE_LENGTH; $i++) {
            $code .= self::ACCESS_CODE_CHARSET[random_int(0, $maxIndex)];
        }

        return $code;
    }

    // Create access code
    public function createAccessCode($maxUses = 1, $uploadQuota = 1073741824, $expiryDate = null, $createdBy = null, $customCode = null, $fileCountLimit = 3) {
        $maxUses = intval($maxUses);
        if ($maxUses < 0) {
            return ['success' => false, 'error' => 'Max uses cannot be negative.'];
        }

        if ($maxUses > 10000) {
            return ['success' => false, 'error' => 'Max uses cannot exceed 10000.'];
        }

        if ($maxUses === 0 && empty($expiryDate)) {
            return ['success' => false, 'error' => 'Expiry date is required when max uses is 0.'];
        }

        $uploadQuota = intval($uploadQuota);
        if ($uploadQuota < 1) {
            return ['success' => false, 'error' => 'Upload quota must be greater than 0.'];
        }

        $fileCountLimit = intval($fileCountLimit);
        if ($fileCountLimit < 1 || $fileCountLimit > 10000) {
            return ['success' => false, 'error' => 'File count limit must be between 1 and 10000.'];
        }

        $inputCode = $this->normalizeAccessCode($customCode);
        $code = '';

        if ($inputCode !== '') {
            if (!$this->isValidAccessCode($inputCode)) {
                return ['success' => false, 'error' => 'Access code must be exactly 7 alphanumeric characters.'];
            }

            if ($this->accessCodeExists($inputCode)) {
                return ['success' => false, 'error' => 'Access code already exists. Please choose a different code.'];
            }

            $code = $inputCode;
        } else {
            // Generate a unique random code with bounded retries.
            for ($attempt = 0; $attempt < 30; $attempt++) {
                $candidate = $this->generateRandomAccessCode();
                if (!$this->accessCodeExists($candidate)) {
                    $code = $candidate;
                    break;
                }
            }

            if ($code === '') {
                return ['success' => false, 'error' => 'Failed to generate a unique access code. Please try again.'];
            }
        }
        
        $sql = "INSERT INTO access_codes (code, max_uses, upload_quota, file_count_limit, expiry_date, created_by) 
            VALUES (?, ?, ?, ?, ?, ?)";
        
        $result = $this->db->query($sql, [$code, $maxUses, $uploadQuota, $fileCountLimit, $expiryDate, $createdBy]);
        
        if ($result) {
            return ['success' => true, 'code' => $code, 'code_id' => $this->db->lastInsertId()];
        }
        
        return ['success' => false, 'error' => 'Failed to create access code.'];
    }
    
    // Get all access codes
    public function getAllAccessCodes() {
        $sql = "SELECT ac.*, 
                       (SELECT COUNT(*) FROM files f WHERE f.uploaded_by_code = ac.id) AS file_count_used
                FROM access_codes ac
                ORDER BY ac.created_at DESC";
        return $this->db->fetchAll($sql);
    }

    public function getAccessCodeById($codeId) {
        $sql = "SELECT * FROM access_codes WHERE id = ? LIMIT 1";
        return $this->db->fetch($sql, [intval($codeId)]);
    }
    
    // Delete access code
    public function deleteAccessCode($codeId) {
        $codeId = intval($codeId);
        if ($codeId < 1) {
            return ['success' => false, 'error' => 'Invalid access code ID.'];
        }

        $codeExists = $this->db->fetch("SELECT id FROM access_codes WHERE id = ? LIMIT 1", [$codeId]);
        if (!$codeExists) {
            return ['success' => false, 'error' => 'Access code not found.'];
        }

        // Get files uploaded with this code to delete
        $sql = "SELECT filename FROM files WHERE uploaded_by_code = ?";
        $files = $this->db->fetchAll($sql, [$codeId]);
        
        // Delete files from disk
        foreach ($files as $file) {
            // Validate filename to prevent path traversal
            if (strpos($file['filename'], '..') !== false || strpos($file['filename'], '/') !== false || strpos($file['filename'], '\\') !== false) {
                continue;
            }
            $filepath = UPLOAD_DIR . $file['filename'];
            if (file_exists($filepath) && is_file($filepath)) {
                unlink($filepath);
            }
        }
        
        // Delete access code
        $sql = "DELETE FROM access_codes WHERE id = ?";
        $result = $this->db->query($sql, [$codeId]);
        
        if ($result) {
            return ['success' => true];
        }
        
        return ['success' => false, 'error' => 'Failed to delete access code.'];
    }
}
?>
