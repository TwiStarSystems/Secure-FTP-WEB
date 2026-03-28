-- Database schema for Secure FTP Web Application

CREATE DATABASE IF NOT EXISTS secure_ftp;
USE secure_ftp;

-- Users table with RBAC role support
-- Roles: 'admin' = full control, 'user' = authenticated user with own files
CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    email VARCHAR(100),
    role ENUM('admin', 'user') DEFAULT 'user',
    is_admin BOOLEAN DEFAULT FALSE, -- Kept for backward compatibility
    upload_quota BIGINT DEFAULT 1073741824, -- 1 GB default
    used_quota BIGINT DEFAULT 0,
    is_temporary BOOLEAN DEFAULT FALSE,
    expiry_date DATETIME NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_login DATETIME NULL,
    is_active BOOLEAN DEFAULT TRUE
);

-- Access codes table
CREATE TABLE IF NOT EXISTS access_codes (
    id INT AUTO_INCREMENT PRIMARY KEY,
    code VARCHAR(64) UNIQUE NOT NULL,
    max_uses INT DEFAULT 1,
    current_uses INT DEFAULT 0,
    upload_quota BIGINT DEFAULT 1073741824,
    file_count_limit INT DEFAULT 3,
    used_quota BIGINT DEFAULT 0,
    expiry_date DATETIME NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    created_by INT,
    is_active BOOLEAN DEFAULT TRUE,
    FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE SET NULL
);

-- Files table
CREATE TABLE IF NOT EXISTS files (
    id INT AUTO_INCREMENT PRIMARY KEY,
    filename VARCHAR(255) NOT NULL,
    original_filename VARCHAR(255) NOT NULL,
    file_size BIGINT NOT NULL,
    file_hash VARCHAR(128),
    hash_algorithm VARCHAR(20),
    encryption_iv VARCHAR(24) NULL,
    mime_type VARCHAR(100),
    uploaded_by_user INT NULL,
    uploaded_by_code INT NULL,
    upload_date DATETIME DEFAULT CURRENT_TIMESTAMP,
    download_count INT DEFAULT 0,
    file_expiry_date DATETIME NULL,
    FOREIGN KEY (uploaded_by_user) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (uploaded_by_code) REFERENCES access_codes(id) ON DELETE CASCADE
);

-- Shared files table for public sharing
CREATE TABLE IF NOT EXISTS shared_files (
    id INT AUTO_INCREMENT PRIMARY KEY,
    file_id INT NOT NULL,
    share_token VARCHAR(64) UNIQUE NOT NULL,
    shared_by_user INT NOT NULL,
    is_public BOOLEAN DEFAULT TRUE,
    password_hash VARCHAR(255) NULL, -- Optional password protection
    expires_at DATETIME NULL,
    max_downloads INT NULL, -- NULL = unlimited
    download_count INT DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    is_active BOOLEAN DEFAULT TRUE,
    FOREIGN KEY (file_id) REFERENCES files(id) ON DELETE CASCADE,
    FOREIGN KEY (shared_by_user) REFERENCES users(id) ON DELETE CASCADE,
    INDEX idx_share_token (share_token),
    INDEX idx_is_public (is_public, is_active)
);

-- Recipient-restricted one-time access tokens for private shares
CREATE TABLE IF NOT EXISTS share_recipient_tokens (
    id INT AUTO_INCREMENT PRIMARY KEY,
    share_id INT NOT NULL UNIQUE,
    recipient_email VARCHAR(191) NOT NULL,
    token_hash CHAR(64) NOT NULL,
    expires_at DATETIME NULL,
    used_at DATETIME NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (share_id) REFERENCES shared_files(id) ON DELETE CASCADE,
    INDEX idx_recipient_email (recipient_email),
    INDEX idx_expires_at (expires_at),
    INDEX idx_used_at (used_at)
);

-- Login attempts table for rate limiting
CREATE TABLE IF NOT EXISTS login_attempts (
    id INT AUTO_INCREMENT PRIMARY KEY,
    identifier VARCHAR(100) NOT NULL, -- username or IP
    attempt_time DATETIME DEFAULT CURRENT_TIMESTAMP,
    was_successful BOOLEAN DEFAULT FALSE,
    INDEX idx_identifier_time (identifier, attempt_time)
);

-- Application settings table
CREATE TABLE IF NOT EXISTS app_settings (
    id INT AUTO_INCREMENT PRIMARY KEY,
    setting_key VARCHAR(100) UNIQUE NOT NULL,
    setting_value TEXT,
    setting_type ENUM('string', 'integer', 'boolean', 'json') DEFAULT 'string',
    description TEXT,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    updated_by INT,
    FOREIGN KEY (updated_by) REFERENCES users(id) ON DELETE SET NULL,
    INDEX idx_setting_key (setting_key)
);

-- Per-user MFA settings (TOTP and Email)
CREATE TABLE IF NOT EXISTS user_mfa_settings (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL UNIQUE,
    totp_enabled BOOLEAN DEFAULT FALSE,
    totp_secret TEXT NULL,
    email_enabled BOOLEAN DEFAULT FALSE,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    INDEX idx_mfa_user (user_id)
);

-- Email MFA one-time codes
CREATE TABLE IF NOT EXISTS mfa_email_codes (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    code_hash VARCHAR(255) NOT NULL,
    expires_at DATETIME NOT NULL,
    used_at DATETIME NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    INDEX idx_mfa_code_user (user_id),
    INDEX idx_mfa_code_expires (expires_at)
);

-- Abuse counters for download/share brute-force protection
CREATE TABLE IF NOT EXISTS abuse_counters (
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
);

-- Security audit events for suspicious activity tracking
CREATE TABLE IF NOT EXISTS security_audit_events (
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
);

-- Password reset tokens for self-service account recovery
CREATE TABLE IF NOT EXISTS password_reset_tokens (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    token_hash CHAR(64) NOT NULL UNIQUE,
    expires_at DATETIME NOT NULL,
    used_at DATETIME NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    INDEX idx_reset_token_hash (token_hash),
    INDEX idx_reset_expires_at (expires_at)
);

-- Create default admin user (username: admin, password: admin123)
-- IMPORTANT: Change this password immediately after installation!
-- Password hash for 'admin123'
INSERT INTO users (username, password_hash, email, role, is_admin, upload_quota, is_temporary) 
VALUES ('admin', '$2y$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi', 'admin@example.com', 'admin', TRUE, 107374182400, FALSE)
ON DUPLICATE KEY UPDATE username=username;
