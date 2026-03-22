<?php
// Application settings helper
require_once 'db.php';

class AppSettingsManager {
    private $db;
    private const SMTP_SECRET_PREFIX = 'enc:v1:';

    public function __construct($db) {
        $this->db = $db;
    }

    public function get($key, $default = '') {
        $sql = "SELECT setting_value FROM app_settings WHERE setting_key = ? LIMIT 1";
        $result = $this->db->fetch($sql, [$key]);

        if (!$result || !array_key_exists('setting_value', $result)) {
            return $default;
        }

        return $result['setting_value'];
    }

    public function set($key, $value, $type = 'string', $description = '', $updatedBy = null) {
        $sql = "INSERT INTO app_settings (setting_key, setting_value, setting_type, description, updated_by)
                VALUES (?, ?, ?, ?, ?)
                ON DUPLICATE KEY UPDATE
                setting_value = VALUES(setting_value),
                setting_type = VALUES(setting_type),
                description = VALUES(description),
                updated_at = CURRENT_TIMESTAMP,
                updated_by = VALUES(updated_by)";

        return $this->db->query($sql, [$key, $value, $type, $description, $updatedBy]);
    }

    public function delete($key) {
        $sql = "DELETE FROM app_settings WHERE setting_key = ?";
        return $this->db->query($sql, [$key]);
    }

    public function getInt($key, $default, $min = 1, $max = 86400) {
        $value = $this->get($key, (string)$default);

        if (!is_numeric($value)) {
            return intval($default);
        }

        $intValue = intval($value);
        if ($intValue < $min) {
            return $min;
        }
        if ($intValue > $max) {
            return $max;
        }

        return $intValue;
    }

    public function getSecurityThresholds() {
        return [
            'max_download_requests_window' => $this->getInt('security_max_download_requests_window', MAX_DOWNLOAD_REQUESTS_WINDOW, 1, 10000),
            'download_request_window_seconds' => $this->getInt('security_download_request_window_seconds', DOWNLOAD_REQUEST_WINDOW_SECONDS, 1, 86400),
            'download_request_lockout_seconds' => $this->getInt('security_download_request_lockout_seconds', DOWNLOAD_REQUEST_LOCKOUT_SECONDS, 1, 86400),

            'max_download_failure_attempts' => $this->getInt('security_max_download_failure_attempts', MAX_DOWNLOAD_FAILURE_ATTEMPTS, 1, 10000),
            'download_failure_window_seconds' => $this->getInt('security_download_failure_window_seconds', DOWNLOAD_FAILURE_WINDOW_SECONDS, 1, 86400),
            'download_failure_lockout_seconds' => $this->getInt('security_download_failure_lockout_seconds', DOWNLOAD_FAILURE_LOCKOUT_SECONDS, 1, 86400),

            'max_share_token_failure_attempts' => $this->getInt('security_max_share_token_failure_attempts', MAX_SHARE_TOKEN_FAILURE_ATTEMPTS, 1, 10000),
            'share_token_failure_window_seconds' => $this->getInt('security_share_token_failure_window_seconds', SHARE_TOKEN_FAILURE_WINDOW_SECONDS, 1, 86400),
            'share_token_failure_lockout_seconds' => $this->getInt('security_share_token_failure_lockout_seconds', SHARE_TOKEN_FAILURE_LOCKOUT_SECONDS, 1, 86400),

            'max_share_password_failure_attempts' => $this->getInt('security_max_share_password_failure_attempts', MAX_SHARE_PASSWORD_FAILURE_ATTEMPTS, 1, 10000),
            'share_password_failure_window_seconds' => $this->getInt('security_share_password_failure_window_seconds', SHARE_PASSWORD_FAILURE_WINDOW_SECONDS, 1, 86400),
            'share_password_failure_lockout_seconds' => $this->getInt('security_share_password_failure_lockout_seconds', SHARE_PASSWORD_FAILURE_LOCKOUT_SECONDS, 1, 86400),

            'max_share_requests_window' => $this->getInt('security_max_share_requests_window', MAX_SHARE_REQUESTS_WINDOW, 1, 10000),
            'share_request_window_seconds' => $this->getInt('security_share_request_window_seconds', SHARE_REQUEST_WINDOW_SECONDS, 1, 86400),
            'share_request_lockout_seconds' => $this->getInt('security_share_request_lockout_seconds', SHARE_REQUEST_LOCKOUT_SECONDS, 1, 86400)
        ];
    }

    public function getSmtpSettings() {
        return [
            'enabled' => $this->get('smtp_enabled', '0') === '1',
            'host' => $this->get('smtp_host', ''),
            'port' => intval($this->get('smtp_port', '587')),
            'encryption' => $this->get('smtp_encryption', 'tls'),
            'username' => $this->get('smtp_username', ''),
            'password' => $this->getSmtpPassword(),
            'auth_required' => $this->get('smtp_auth_required', '1') === '1',
            'from_email' => $this->get('smtp_from_email', ''),
            'from_name' => $this->get('smtp_from_name', SITE_NAME)
        ];
    }

    public function getSmtpPassword() {
        $storedPassword = $this->get('smtp_password', '');

        if ($storedPassword === '') {
            return '';
        }

        if ($this->isEncryptedValue($storedPassword)) {
            return $this->decryptValue($storedPassword);
        }

        // Backward compatibility: migrate legacy plaintext value to encrypted storage
        $this->setSmtpPassword($storedPassword, null);
        return $storedPassword;
    }

    public function setSmtpPassword($password, $updatedBy = null) {
        $encryptedPassword = $password === '' ? '' : $this->encryptValue($password);

        return $this->set(
            'smtp_password',
            $encryptedPassword,
            'string',
            'SMTP authentication password (encrypted at rest)',
            $updatedBy
        );
    }

    private function isEncryptedValue($value) {
        return strpos($value, self::SMTP_SECRET_PREFIX) === 0;
    }

    private function getEncryptionKey() {
        return hash('sha256', DB_HOST . '|' . DB_NAME . '|' . DB_USER . '|' . DB_PASS . '|' . SITE_NAME, true);
    }

    private function encryptValue($plainText) {
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

        return self::SMTP_SECRET_PREFIX . base64_encode($iv . $tag . $cipherText);
    }

    private function decryptValue($encryptedValue) {
        if (!$this->isEncryptedValue($encryptedValue)) {
            return $encryptedValue;
        }

        $encodedPayload = substr($encryptedValue, strlen(self::SMTP_SECRET_PREFIX));
        $payload = base64_decode($encodedPayload, true);

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

    /**
     * Returns an array of allowed MIME types from settings.
     * An empty array means all types are permitted (no restriction).
     */
    public function getAllowedMimeTypes() {
        $stored = $this->get('allowed_mime_types', '');
        if (trim($stored) === '') {
            return [];
        }
        $entries = preg_split('/[\r\n,]+/', $stored);
        $types = [];
        foreach ($entries as $entry) {
            $type = trim(strtolower($entry));
            if ($type !== '') {
                $types[] = $type;
            }
        }
        return array_values(array_unique($types));
    }

    public function isVirusScanEnabled() {
        return $this->get('virus_scan_enabled', '0') === '1';
    }
}
?>