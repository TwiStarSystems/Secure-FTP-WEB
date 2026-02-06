<?php
// User management functions (admin only)
require_once 'db.php';
require_once 'rbac.php';

class UserManager {
    private $db;
    
    public function __construct($db) {
        $this->db = $db;
    }
    
    // Create new user
    public function createUser($username, $password, $email, $role = 'user', $uploadQuota = 1073741824, $isTemporary = false, $expiryDate = null) {
        // Validate input
        if (empty($username) || empty($password)) {
            return ['success' => false, 'error' => 'Username and password are required.'];
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
    
    // Create access code
    public function createAccessCode($maxUses = 1, $uploadQuota = 1073741824, $expiryDate = null, $createdBy = null) {
        // Generate random access code
        $code = bin2hex(random_bytes(16));
        
        $sql = "INSERT INTO access_codes (code, max_uses, upload_quota, expiry_date, created_by) 
                VALUES (?, ?, ?, ?, ?)";
        
        $result = $this->db->query($sql, [$code, $maxUses, $uploadQuota, $expiryDate, $createdBy]);
        
        if ($result) {
            return ['success' => true, 'code' => $code, 'code_id' => $this->db->lastInsertId()];
        }
        
        return ['success' => false, 'error' => 'Failed to create access code.'];
    }
    
    // Get all access codes
    public function getAllAccessCodes() {
        $sql = "SELECT * FROM access_codes ORDER BY created_at DESC";
        return $this->db->fetchAll($sql);
    }
    
    // Delete access code
    public function deleteAccessCode($codeId) {
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
