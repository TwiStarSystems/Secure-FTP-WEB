<?php
// Authentication and rate limiting functions
require_once 'db.php';

class Auth {
    private $db;
    
    public function __construct($db) {
        $this->db = $db;
    }
    
    // Check if IP or username is rate limited
    public function isRateLimited($identifier) {
        // Clean up old attempts first
        cleanupOldLoginAttempts($this->db);
        
        $sql = "SELECT COUNT(*) as attempts FROM login_attempts 
                WHERE identifier = ? 
                AND attempt_time > DATE_SUB(NOW(), INTERVAL ? SECOND)
                AND was_successful = FALSE";
        
        $result = $this->db->fetch($sql, [$identifier, LOCKOUT_DURATION]);
        
        if ($result && $result['attempts'] >= MAX_LOGIN_ATTEMPTS) {
            return true;
        }
        return false;
    }
    
    // Record login attempt
    public function recordLoginAttempt($identifier, $success = false) {
        $sql = "INSERT INTO login_attempts (identifier, was_successful) VALUES (?, ?)";
        $this->db->query($sql, [$identifier, $success]);
        
        // If successful, clear failed attempts
        if ($success) {
            $sql = "DELETE FROM login_attempts WHERE identifier = ? AND was_successful = FALSE";
            $this->db->query($sql, [$identifier]);
        }
    }
    
    // User login
    public function login($username, $password) {
        $identifier = $username . '_' . $_SERVER['REMOTE_ADDR'];
        
        // Check rate limiting
        if ($this->isRateLimited($identifier)) {
            return ['success' => false, 'error' => 'Too many failed attempts. Please try again later.'];
        }
        
        // Clean up expired users
        cleanupExpiredUsers($this->db);
        
        $sql = "SELECT * FROM users WHERE username = ? AND is_active = TRUE";
        $user = $this->db->fetch($sql, [$username]);
        
        if ($user && password_verify($password, $user['password_hash'])) {
            // Check if temporary user has expired
            if ($user['is_temporary'] && $user['expiry_date'] && strtotime($user['expiry_date']) < time()) {
                $this->recordLoginAttempt($identifier, false);
                return ['success' => false, 'error' => 'User account has expired.'];
            }
            
            // Update last login
            $sql = "UPDATE users SET last_login = NOW() WHERE id = ?";
            $this->db->query($sql, [$user['id']]);
            
            // Record successful attempt
            $this->recordLoginAttempt($identifier, true);
            
            // Set session
            $_SESSION['user_id'] = $user['id'];
            $_SESSION['username'] = $user['username'];
            $_SESSION['is_admin'] = $user['is_admin'];
            $_SESSION['login_time'] = time();
            
            return ['success' => true, 'user' => $user];
        }
        
        // Record failed attempt
        $this->recordLoginAttempt($identifier, false);
        return ['success' => false, 'error' => 'Invalid username or password.'];
    }
    
    // Access code login
    public function loginWithAccessCode($code) {
        $identifier = 'code_' . $_SERVER['REMOTE_ADDR'];
        
        // Check rate limiting
        if ($this->isRateLimited($identifier)) {
            return ['success' => false, 'error' => 'Too many failed attempts. Please try again later.'];
        }
        
        // Clean up expired codes
        cleanupExpiredAccessCodes($this->db);
        
        $sql = "SELECT * FROM access_codes WHERE code = ? AND is_active = TRUE";
        $accessCode = $this->db->fetch($sql, [$code]);
        
        if ($accessCode) {
            // Check if code has expired
            if ($accessCode['expiry_date'] && strtotime($accessCode['expiry_date']) < time()) {
                $this->recordLoginAttempt($identifier, false);
                return ['success' => false, 'error' => 'Access code has expired.'];
            }
            
            // Check if max uses reached
            if ($accessCode['current_uses'] >= $accessCode['max_uses']) {
                $this->recordLoginAttempt($identifier, false);
                return ['success' => false, 'error' => 'Access code has reached maximum uses.'];
            }
            
            // Increment use count
            $sql = "UPDATE access_codes SET current_uses = current_uses + 1 WHERE id = ?";
            $this->db->query($sql, [$accessCode['id']]);
            
            // Record successful attempt
            $this->recordLoginAttempt($identifier, true);
            
            // Set session
            $_SESSION['access_code_id'] = $accessCode['id'];
            $_SESSION['access_code'] = $accessCode['code'];
            $_SESSION['login_time'] = time();
            
            return ['success' => true, 'access_code' => $accessCode];
        }
        
        // Record failed attempt
        $this->recordLoginAttempt($identifier, false);
        return ['success' => false, 'error' => 'Invalid access code.'];
    }
    
    // Check if user is logged in
    public function isLoggedIn() {
        if (isset($_SESSION['user_id']) || isset($_SESSION['access_code_id'])) {
            // Check session timeout
            if (isset($_SESSION['login_time']) && (time() - $_SESSION['login_time'] > SESSION_TIMEOUT)) {
                $this->logout();
                return false;
            }
            return true;
        }
        return false;
    }
    
    // Check if logged in user is admin
    public function isAdmin() {
        return isset($_SESSION['is_admin']) && $_SESSION['is_admin'] === true;
    }
    
    // Get current user data
    public function getCurrentUser() {
        if (isset($_SESSION['user_id'])) {
            $sql = "SELECT * FROM users WHERE id = ?";
            return $this->db->fetch($sql, [$_SESSION['user_id']]);
        }
        return null;
    }
    
    // Get current access code data
    public function getCurrentAccessCode() {
        if (isset($_SESSION['access_code_id'])) {
            $sql = "SELECT * FROM access_codes WHERE id = ?";
            return $this->db->fetch($sql, [$_SESSION['access_code_id']]);
        }
        return null;
    }
    
    // Logout
    public function logout() {
        session_unset();
        session_destroy();
    }
    
    // Generate CSRF token
    public function generateCSRFToken() {
        if (!isset($_SESSION['csrf_token'])) {
            $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
        }
        return $_SESSION['csrf_token'];
    }
    
    // Verify CSRF token
    public function verifyCSRFToken($token) {
        if (!isset($_SESSION['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $token)) {
            return false;
        }
        // Rotate token after verification for security
        unset($_SESSION['csrf_token']);
        return true;
    }
}
?>
