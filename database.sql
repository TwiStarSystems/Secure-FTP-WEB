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
    mime_type VARCHAR(100),
    uploaded_by_user INT NULL,
    uploaded_by_code INT NULL,
    upload_date DATETIME DEFAULT CURRENT_TIMESTAMP,
    download_count INT DEFAULT 0,
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

-- Create default admin user (username: admin, password: admin123)
-- IMPORTANT: Change this password immediately after installation!
-- Password hash for 'admin123'
INSERT INTO users (username, password_hash, email, role, is_admin, upload_quota, is_temporary) 
VALUES ('admin', '$2y$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi', 'admin@example.com', 'admin', TRUE, 107374182400, FALSE)
ON DUPLICATE KEY UPDATE username=username;
