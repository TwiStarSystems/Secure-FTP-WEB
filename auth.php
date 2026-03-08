<?php
// Authentication and rate limiting functions
require_once 'db.php';
require_once 'rbac.php';
require_once 'mfa.php';

class Auth {
    private $db;
    private $mfaService;
    
    public function __construct($db) {
        $this->db = $db;
        $this->mfaService = new MFAService($db);
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
            
            $mfaSettings = $this->mfaService->getUserMfaSettings($user['id']);
            $availableMethods = $this->mfaService->getAvailableMethods($mfaSettings);

            if ($availableMethods['totp'] || $availableMethods['email']) {
                $_SESSION['mfa_pending_user_id'] = $user['id'];
                $_SESSION['mfa_pending_identifier'] = $identifier;
                $_SESSION['mfa_pending_started_at'] = time();
                $_SESSION['mfa_available_methods'] = $availableMethods;

                if ($availableMethods['email'] && !$availableMethods['totp']) {
                    $emailResult = $this->mfaService->sendEmailCode($user['id']);
                    if (!$emailResult['success']) {
                        return ['success' => false, 'error' => 'Email MFA is enabled but code delivery failed: ' . $emailResult['error']];
                    }
                }

                return [
                    'success' => false,
                    'requires_mfa' => true,
                    'available_methods' => $availableMethods
                ];
            }

            $this->completeUserLogin($user, $identifier);
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

    public function hasPendingMfa() {
        return isset($_SESSION['mfa_pending_user_id']);
    }

    public function getPendingMfaMethods() {
        if (!$this->hasPendingMfa()) {
            return ['totp' => false, 'email' => false];
        }

        $methods = $_SESSION['mfa_available_methods'] ?? ['totp' => false, 'email' => false];
        return [
            'totp' => !empty($methods['totp']),
            'email' => !empty($methods['email'])
        ];
    }

    public function sendPendingEmailMfaCode() {
        if (!$this->hasPendingMfa()) {
            return ['success' => false, 'error' => 'No MFA challenge in progress.'];
        }

        $methods = $this->getPendingMfaMethods();
        if (!$methods['email']) {
            return ['success' => false, 'error' => 'Email MFA is not available for this account.'];
        }

        $userId = intval($_SESSION['mfa_pending_user_id']);
        return $this->mfaService->sendEmailCode($userId);
    }

    public function verifyPendingMfa($method, $code) {
        if (!$this->hasPendingMfa()) {
            return ['success' => false, 'error' => 'No MFA challenge in progress.'];
        }

        if (!in_array($method, ['totp', 'email'], true)) {
            return ['success' => false, 'error' => 'Invalid MFA method.'];
        }

        $methods = $this->getPendingMfaMethods();
        if (empty($methods[$method])) {
            return ['success' => false, 'error' => 'Selected MFA method is not enabled for this account.'];
        }

        $userId = intval($_SESSION['mfa_pending_user_id']);
        $identifier = 'mfa_' . $userId . '_' . $_SERVER['REMOTE_ADDR'];

        if ($this->isRateLimited($identifier)) {
            return ['success' => false, 'error' => 'Too many failed MFA attempts. Please retry login.'];
        }

        $cleanCode = preg_replace('/\D/', '', (string)$code);
        if (strlen($cleanCode) !== 6) {
            $this->recordLoginAttempt($identifier, false);
            return ['success' => false, 'error' => 'MFA code must be 6 digits.'];
        }

        $verified = false;
        if ($method === 'totp') {
            $verified = $this->mfaService->verifyTotpCode($userId, $cleanCode);
        } elseif ($method === 'email') {
            $verified = $this->mfaService->verifyEmailCode($userId, $cleanCode);
        }

        if (!$verified) {
            $this->recordLoginAttempt($identifier, false);
            return ['success' => false, 'error' => 'Invalid or expired MFA code.'];
        }

        $this->recordLoginAttempt($identifier, true);

        $user = $this->db->fetch("SELECT * FROM users WHERE id = ? AND is_active = TRUE LIMIT 1", [$userId]);
        if (!$user) {
            $this->clearPendingMfa();
            return ['success' => false, 'error' => 'Account no longer available.'];
        }

        $primaryIdentifier = $_SESSION['mfa_pending_identifier'] ?? ($user['username'] . '_' . $_SERVER['REMOTE_ADDR']);
        $this->clearPendingMfa();
        $this->completeUserLogin($user, $primaryIdentifier);

        return ['success' => true];
    }

    private function clearPendingMfa() {
        unset($_SESSION['mfa_pending_user_id']);
        unset($_SESSION['mfa_pending_identifier']);
        unset($_SESSION['mfa_pending_started_at']);
        unset($_SESSION['mfa_available_methods']);
    }

    private function completeUserLogin($user, $identifier) {
        $sql = "UPDATE users SET last_login = NOW() WHERE id = ?";
        $this->db->query($sql, [$user['id']]);

        $this->recordLoginAttempt($identifier, true);

        $role = isset($user['role']) && !empty($user['role']) ? $user['role'] : ($user['is_admin'] ? 'admin' : 'user');

        $_SESSION['user_id'] = $user['id'];
        $_SESSION['username'] = $user['username'];
        $_SESSION['is_admin'] = $user['is_admin'];
        $_SESSION['user_role'] = $role;
        $_SESSION['login_time'] = time();
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
    
    // Get current user role using RBAC
    public function getRole() {
        return RBAC::getCurrentRole();
    }
    
    // Check if user has permission using RBAC
    public function hasPermission($permission) {
        return RBAC::hasPermission($permission);
    }
}
?>
