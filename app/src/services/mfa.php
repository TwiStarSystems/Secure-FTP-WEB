<?php
// Multi-Factor Authentication service (TOTP + Email Codes)
require_once APP_DIR . '/src/core/config.php';
require_once APP_DIR . '/src/core/db.php';
require_once APP_DIR . '/src/services/app_settings.php';
require_once APP_DIR . '/src/support/smtp_mailer.php';

class MFAService {
    private $db;
    private $settingsManager;
    private $smtpMailer;
    private const SECRET_PREFIX = 'enc:v1:';

    public function __construct($db) {
        $this->db = $db;
        $this->settingsManager = new AppSettingsManager($db);
        $this->smtpMailer = new SMTPMailer($db);
        $this->ensureSchema();
    }

    public function ensureSchema() {
        $this->db->query("CREATE TABLE IF NOT EXISTS user_mfa_settings (
            id INT AUTO_INCREMENT PRIMARY KEY,
            user_id INT NOT NULL UNIQUE,
            totp_enabled BOOLEAN DEFAULT FALSE,
            totp_secret TEXT NULL,
            email_enabled BOOLEAN DEFAULT FALSE,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
            INDEX idx_mfa_user (user_id)
        )");

        $this->db->query("CREATE TABLE IF NOT EXISTS mfa_email_codes (
            id INT AUTO_INCREMENT PRIMARY KEY,
            user_id INT NOT NULL,
            code_hash VARCHAR(255) NOT NULL,
            expires_at DATETIME NOT NULL,
            used_at DATETIME NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
            INDEX idx_mfa_code_user (user_id),
            INDEX idx_mfa_code_expires (expires_at)
        )");
    }

    public function getUserMfaSettings($userId) {
        $sql = "SELECT m.*, u.username, u.email
                FROM users u
                LEFT JOIN user_mfa_settings m ON m.user_id = u.id
                WHERE u.id = ?
                LIMIT 1";

        $row = $this->db->fetch($sql, [$userId]);
        if (!$row) {
            return null;
        }

        $totpSecret = '';
        if (!empty($row['totp_secret'])) {
            $totpSecret = $this->decryptSecret($row['totp_secret']);
        }

        return [
            'user_id' => intval($userId),
            'username' => $row['username'],
            'email' => $row['email'] ?? '',
            'totp_enabled' => !empty($row['totp_enabled']) && intval($row['totp_enabled']) === 1,
            'totp_secret' => $totpSecret,
            'email_enabled' => !empty($row['email_enabled']) && intval($row['email_enabled']) === 1
        ];
    }

    public function hasMfaEnabled($userId) {
        $settings = $this->getUserMfaSettings($userId);
        if (!$settings) {
            return false;
        }

        return $this->getAvailableMethods($settings)['totp'] || $this->getAvailableMethods($settings)['email'];
    }

    public function getAvailableMethods($settingsOrUserId) {
        $settings = is_array($settingsOrUserId) ? $settingsOrUserId : $this->getUserMfaSettings($settingsOrUserId);
        if (!$settings) {
            return ['totp' => false, 'email' => false];
        }

        $totpAvailable = $settings['totp_enabled'] && !empty($settings['totp_secret']);
        $emailAvailable = $settings['email_enabled'] && filter_var($settings['email'], FILTER_VALIDATE_EMAIL);

        return [
            'totp' => $totpAvailable,
            'email' => $emailAvailable
        ];
    }

    public function enableTotpForUser($userId) {
        $secret = $this->generateTotpSecret();
        $encryptedSecret = $this->encryptSecret($secret);

        if ($encryptedSecret === '') {
            return ['success' => false, 'error' => 'Failed to encrypt TOTP secret.'];
        }

        $sql = "INSERT INTO user_mfa_settings (user_id, totp_enabled, totp_secret, email_enabled)
                VALUES (?, TRUE, ?, FALSE)
                ON DUPLICATE KEY UPDATE
                    totp_enabled = TRUE,
                    totp_secret = VALUES(totp_secret)";

        $saved = $this->db->query($sql, [$userId, $encryptedSecret]);
        if (!$saved) {
            return ['success' => false, 'error' => 'Failed to enable TOTP MFA.'];
        }

        return [
            'success' => true,
            'secret' => $secret
        ];
    }

    public function disableTotpForUser($userId) {
        $sql = "INSERT INTO user_mfa_settings (user_id, totp_enabled, totp_secret, email_enabled)
                VALUES (?, FALSE, NULL, FALSE)
                ON DUPLICATE KEY UPDATE
                    totp_enabled = FALSE,
                    totp_secret = NULL";

        return $this->db->query($sql, [$userId]);
    }

    public function enableEmailForUser($userId) {
        $user = $this->db->fetch("SELECT email FROM users WHERE id = ? LIMIT 1", [$userId]);
        if (!$user || !filter_var($user['email'], FILTER_VALIDATE_EMAIL)) {
            return ['success' => false, 'error' => 'A valid account email is required to enable Email MFA.'];
        }

        $sql = "INSERT INTO user_mfa_settings (user_id, totp_enabled, email_enabled)
                VALUES (?, FALSE, TRUE)
                ON DUPLICATE KEY UPDATE
                    email_enabled = TRUE";

        $saved = $this->db->query($sql, [$userId]);
        if (!$saved) {
            return ['success' => false, 'error' => 'Failed to enable Email MFA.'];
        }

        return ['success' => true];
    }

    public function disableEmailForUser($userId) {
        $sql = "INSERT INTO user_mfa_settings (user_id, totp_enabled, email_enabled)
                VALUES (?, FALSE, FALSE)
                ON DUPLICATE KEY UPDATE
                    email_enabled = FALSE";

        return $this->db->query($sql, [$userId]);
    }

    public function sendEmailCode($userId) {
        cleanupOldMfaEmailCodes($this->db);

        $settings = $this->getUserMfaSettings($userId);
        if (!$settings) {
            return ['success' => false, 'error' => 'User not found.'];
        }

        $methods = $this->getAvailableMethods($settings);
        if (!$methods['email']) {
            return ['success' => false, 'error' => 'Email MFA is not enabled or no valid email is configured.'];
        }

        if (!$this->smtpMailer->isConfigured()) {
            return ['success' => false, 'error' => 'SMTP is not configured.'];
        }

        $code = str_pad((string)random_int(0, 999999), 6, '0', STR_PAD_LEFT);
        $codeHash = password_hash($code, PASSWORD_DEFAULT);
        $expiresAt = date('Y-m-d H:i:s', time() + 600);

        $this->db->query("DELETE FROM mfa_email_codes WHERE user_id = ? AND used_at IS NULL", [$userId]);

        $inserted = $this->db->query(
            "INSERT INTO mfa_email_codes (user_id, code_hash, expires_at) VALUES (?, ?, ?)",
            [$userId, $codeHash, $expiresAt]
        );

        if (!$inserted) {
            return ['success' => false, 'error' => 'Failed to generate MFA email code.'];
        }

        $subject = 'Your MFA Verification Code - ' . SITE_NAME;
        $textBody = "Your verification code is: {$code}\n\nThis code expires in 10 minutes.";
        $htmlBody = '<p>Your verification code is:</p><p style="font-size: 1.4rem; font-weight: bold;">' .
                    htmlspecialchars($code) .
                    '</p><p>This code expires in 10 minutes.</p>';

        $sendResult = $this->smtpMailer->send($settings['email'], $subject, $htmlBody, $textBody);

        if (!$sendResult['success']) {
            return ['success' => false, 'error' => $sendResult['error']];
        }

        return [
            'success' => true,
            'email' => $settings['email']
        ];
    }

    public function verifyEmailCode($userId, $code) {
        cleanupOldMfaEmailCodes($this->db);

        $sql = "SELECT * FROM mfa_email_codes
                WHERE user_id = ?
                AND used_at IS NULL
                AND expires_at > NOW()
                ORDER BY created_at DESC
                LIMIT 1";

        $row = $this->db->fetch($sql, [$userId]);
        if (!$row) {
            return false;
        }

        if (!password_verify($code, $row['code_hash'])) {
            return false;
        }

        $this->db->query("UPDATE mfa_email_codes SET used_at = NOW() WHERE id = ?", [$row['id']]);
        return true;
    }

    public function verifyTotpCode($userId, $code) {
        $settings = $this->getUserMfaSettings($userId);
        if (!$settings || !$settings['totp_enabled'] || empty($settings['totp_secret'])) {
            return false;
        }

        $cleanCode = preg_replace('/\D/', '', (string)$code);
        if (strlen($cleanCode) !== 6) {
            return false;
        }

        $secretBinary = $this->base32Decode($settings['totp_secret']);
        if ($secretBinary === '') {
            return false;
        }

        $timeSlice = (int)floor(time() / 30);

        for ($offset = -1; $offset <= 1; $offset++) {
            $calculated = $this->calculateTotp($secretBinary, $timeSlice + $offset);
            if (hash_equals($calculated, $cleanCode)) {
                return true;
            }
        }

        return false;
    }

    public function getTotpProvisioningUri($username, $secret) {
        $issuer = rawurlencode(SITE_NAME);
        $label = rawurlencode(SITE_NAME . ':' . $username);
        return "otpauth://totp/{$label}?secret={$secret}&issuer={$issuer}&algorithm=SHA1&digits=6&period=30";
    }

    private function generateTotpSecret($length = 20) {
        $bytes = random_bytes($length);
        return $this->base32Encode($bytes);
    }

    private function calculateTotp($secretBinary, $timeSlice) {
        $time = pack('N*', 0) . pack('N*', $timeSlice);
        $hash = hash_hmac('sha1', $time, $secretBinary, true);
        $offset = ord(substr($hash, -1)) & 0x0F;
        $truncated = (
            ((ord($hash[$offset]) & 0x7F) << 24) |
            ((ord($hash[$offset + 1]) & 0xFF) << 16) |
            ((ord($hash[$offset + 2]) & 0xFF) << 8) |
            (ord($hash[$offset + 3]) & 0xFF)
        );

        $code = $truncated % 1000000;
        return str_pad((string)$code, 6, '0', STR_PAD_LEFT);
    }

    private function base32Encode($data) {
        $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
        $bits = '';
        $encoded = '';

        foreach (str_split($data) as $char) {
            $bits .= str_pad(decbin(ord($char)), 8, '0', STR_PAD_LEFT);
        }

        $chunks = str_split($bits, 5);
        foreach ($chunks as $chunk) {
            if (strlen($chunk) < 5) {
                $chunk = str_pad($chunk, 5, '0', STR_PAD_RIGHT);
            }
            $encoded .= $alphabet[bindec($chunk)];
        }

        return $encoded;
    }

    private function base32Decode($data) {
        $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
        $data = strtoupper(preg_replace('/[^A-Z2-7]/', '', $data));
        if ($data === '') {
            return '';
        }

        $bits = '';
        foreach (str_split($data) as $char) {
            $position = strpos($alphabet, $char);
            if ($position === false) {
                return '';
            }
            $bits .= str_pad(decbin($position), 5, '0', STR_PAD_LEFT);
        }

        $binary = '';
        $bytes = str_split($bits, 8);
        foreach ($bytes as $byte) {
            if (strlen($byte) === 8) {
                $binary .= chr(bindec($byte));
            }
        }

        return $binary;
    }

    private function getEncryptionKey() {
        return hash('sha256', DB_HOST . '|' . DB_NAME . '|' . DB_USER . '|' . DB_PASS . '|mfa|' . SITE_NAME, true);
    }

    private function encryptSecret($plainText) {
        if ($plainText === '') {
            return '';
        }

        $iv = random_bytes(12);
        $tag = '';
        $cipherText = openssl_encrypt(
            $plainText,
            'aes-256-gcm',
            $this->getEncryptionKey(),
            OPENSSL_RAW_DATA,
            $iv,
            $tag,
            '',
            16
        );

        if ($cipherText === false) {
            return '';
        }

        return self::SECRET_PREFIX . base64_encode($iv . $tag . $cipherText);
    }

    private function decryptSecret($value) {
        if ($value === '') {
            return '';
        }

        if (strpos($value, self::SECRET_PREFIX) !== 0) {
            return $value;
        }

        $payload = base64_decode(substr($value, strlen(self::SECRET_PREFIX)), true);
        if ($payload === false || strlen($payload) < 28) {
            return '';
        }

        $iv = substr($payload, 0, 12);
        $tag = substr($payload, 12, 16);
        $cipherText = substr($payload, 28);

        $plainText = openssl_decrypt(
            $cipherText,
            'aes-256-gcm',
            $this->getEncryptionKey(),
            OPENSSL_RAW_DATA,
            $iv,
            $tag,
            ''
        );

        return $plainText === false ? '' : $plainText;
    }
}
?>