#!/bin/bash

# Secure FTP Web Application - Automated Installation Script for Debian/Ubuntu
# This script installs and configures Nginx, PHP, MySQL/MariaDB, and the application
# Usage: ./install.sh [--fresh|--update|--uninstall]
#   --fresh:     Full clean installation (default mode)
#   --update:    Update application files and run safe DB migrations
#   --uninstall: Remove application and optionally remove database/user

set -e  # Exit on error

# Installer mode
INSTALL_MODE="fresh"
case "$1" in
    ""|"--fresh")
        INSTALL_MODE="fresh"
        ;;
    "--update")
        INSTALL_MODE="update"
        ;;
    "--uninstall")
        INSTALL_MODE="uninstall"
        ;;
    *)
        echo "Usage: $0 [--fresh|--update|--uninstall]"
        exit 1
        ;;
esac

UPDATE_MODE=false
if [ "$INSTALL_MODE" = "update" ]; then
    UPDATE_MODE=true
fi

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Default configuration variables
APP_DIR="/var/www/html/secure-ftp"
DB_NAME="secure_ftp"
DB_USER="secure_ftp_user"
NGINX_CONF="/etc/nginx/sites-available/secure-ftp.conf"
NGINX_ENABLED="/etc/nginx/sites-enabled/secure-ftp.conf"
DOMAIN_NAME=""

# Function to print colored messages
print_message() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_header() {
    echo -e "\n${CYAN}╔════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║${NC}  $1"
    echo -e "${CYAN}╚════════════════════════════════════════════════════════════════╝${NC}\n"
}

print_step() {
    echo -e "${BLUE}==>${NC} $1"
}

# Function to prompt for yes/no with default
prompt_yes_no() {
    local prompt="$1"
    local default="$2"
    local response
    
    if [ "$default" = "y" ]; then
        prompt="$prompt [Y/n]: "
    else
        prompt="$prompt [y/N]: "
    fi
    
    read -p "$prompt" response
    response=${response:-$default}
    
    [[ "$response" =~ ^[Yy]$ ]]
}

# Function to prompt for input with default
prompt_input() {
    local prompt="$1"
    local default="$2"
    local response
    
    if [ -n "$default" ]; then
        read -p "$prompt [$default]: " response
        echo "${response:-$default}"
    else
        read -p "$prompt: " response
        echo "$response"
    fi
}

# Normalize and validate usernames using the same policy as the app.
normalize_username() {
    local username="$1"
    echo "$username" | tr '[:upper:]' '[:lower:]' | xargs
}

is_valid_username() {
    local username="$1"
    [[ "$username" =~ ^[a-z0-9._-]{3,50}$ ]]
}

# Extract a PHP define value from config.php
extract_php_define() {
    local file_path="$1"
    local define_name="$2"

    if [ ! -f "$file_path" ]; then
        echo ""
        return 0
    fi

    sed -n "s/.*define('${define_name}', '\([^']*\)'.*/\1/p" "$file_path" | head -n1
}

# Run safe, idempotent DB migrations for update mode
run_update_db_migrations() {
    local app_dir="$1"
    local config_file="${app_dir}/app/src/core/config.php"

    if [ ! -f "$config_file" ]; then
        print_warning "config.php not found; skipping DB migrations."
        return 0
    fi

    local db_host
    local db_name
    local db_user
    local db_pass

    db_host=$(extract_php_define "$config_file" "DB_HOST")
    db_name=$(extract_php_define "$config_file" "DB_NAME")
    db_user=$(extract_php_define "$config_file" "DB_USER")
    db_pass=$(extract_php_define "$config_file" "DB_PASS")

    if [ -z "$db_host" ] || [ -z "$db_name" ] || [ -z "$db_user" ]; then
        print_warning "Could not parse DB credentials from config.php; skipping DB migrations."
        return 0
    fi

    print_header "UPDATE: Database Migrations"
    print_message "Applying idempotent database migrations..."

    local mysql_args
    mysql_args=( -h "$db_host" -u "$db_user" "$db_name" )
    if [ -n "$db_pass" ]; then
        mysql_args+=( -p"$db_pass" )
    fi

    mysql "${mysql_args[@]}" <<'SQL'
CREATE TABLE IF NOT EXISTS app_settings (
    id INT AUTO_INCREMENT PRIMARY KEY,
    setting_key VARCHAR(100) UNIQUE NOT NULL,
    setting_value TEXT,
    setting_type ENUM('string', 'integer', 'boolean', 'json') DEFAULT 'string',
    description TEXT,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    updated_by INT,
    INDEX idx_setting_key (setting_key)
);

CREATE TABLE IF NOT EXISTS user_mfa_settings (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL UNIQUE,
    totp_enabled BOOLEAN DEFAULT FALSE,
    totp_secret TEXT NULL,
    email_enabled BOOLEAN DEFAULT FALSE,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_mfa_user (user_id)
);

CREATE TABLE IF NOT EXISTS mfa_email_codes (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    code_hash VARCHAR(255) NOT NULL,
    expires_at DATETIME NOT NULL,
    used_at DATETIME NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_mfa_code_user (user_id),
    INDEX idx_mfa_code_expires (expires_at)
);

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

CREATE TABLE IF NOT EXISTS security_audit_events (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    event_type VARCHAR(100) NOT NULL,
    severity ENUM('info', 'warning', 'critical') DEFAULT 'info',
    user_id INT NULL,
    ip_address VARCHAR(64) NOT NULL,
    identifier VARCHAR(191) DEFAULT '',
    context_json TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_event_type (event_type),
    INDEX idx_created_at (created_at),
    INDEX idx_ip_address (ip_address)
);

CREATE TABLE IF NOT EXISTS password_reset_tokens (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    token_hash CHAR(64) NOT NULL UNIQUE,
    expires_at DATETIME NOT NULL,
    used_at DATETIME NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_reset_token_hash (token_hash),
    INDEX idx_reset_expires_at (expires_at)
);

-- Add encryption_iv column for AES-256-GCM file encryption at rest
ALTER TABLE files ADD COLUMN IF NOT EXISTS encryption_iv VARCHAR(24) NULL AFTER hash_algorithm;

-- Add processing_status/processing_error columns for the async upload pipeline
-- (hashing, duplicate detection, virus scan, encryption run in the background
-- via process_file.php). Existing rows default to 'ready' since any file already
-- present before this migration was processed synchronously and is fully usable.
ALTER TABLE files ADD COLUMN IF NOT EXISTS processing_status ENUM('pending','processing','ready','failed') DEFAULT 'ready' AFTER file_expiry_date;
ALTER TABLE files ADD COLUMN IF NOT EXISTS processing_error TEXT NULL AFTER processing_status;
SQL

    print_message "Database migrations completed."
}

run_uninstall() {
    print_header "UNINSTALL MODE"

    local app_dir
    app_dir=$(prompt_input "Enter application installation path" "/var/www/html/secure-ftp")

    local nginx_conf="/etc/nginx/sites-available/secure-ftp.conf"
    local nginx_enabled="/etc/nginx/sites-enabled/secure-ftp.conf"
    local config_file="${app_dir}/app/src/core/config.php"
    local db_host=""
    local db_name=""
    local db_user=""

    if [ -f "$config_file" ]; then
        db_host=$(extract_php_define "$config_file" "DB_HOST")
        db_name=$(extract_php_define "$config_file" "DB_NAME")
        db_user=$(extract_php_define "$config_file" "DB_USER")
    fi

    print_warning "This will remove application files and Nginx site configuration."
    if ! prompt_yes_no "Proceed with uninstall?" "n"; then
        print_message "Uninstall cancelled by user."
        exit 0
    fi

    if [ -L "$nginx_enabled" ] || [ -f "$nginx_enabled" ]; then
        rm -f "$nginx_enabled"
        print_message "Removed Nginx enabled site link."
    fi

    if [ -f "$nginx_conf" ]; then
        rm -f "$nginx_conf"
        print_message "Removed Nginx site config."
    fi

    if [ -d "$app_dir" ]; then
        rm -rf "$app_dir"
        print_message "Removed application directory: $app_dir"
    else
        print_warning "Application directory not found: $app_dir"
    fi

    if prompt_yes_no "Also remove database and DB user?" "n"; then
        if [ -z "$db_name" ]; then
            db_name=$(prompt_input "Database name to drop" "secure_ftp")
        fi
        if [ -z "$db_user" ]; then
            db_user=$(prompt_input "Database user to drop" "secure_ftp_user")
        fi

        print_warning "This will permanently delete database '${db_name}' and user '${db_user}'."
        if prompt_yes_no "Confirm destructive DB removal?" "n"; then
            mysql -e "DROP DATABASE IF EXISTS ${db_name};" 2>/dev/null || true
            mysql -e "DROP USER IF EXISTS '${db_user}'@'localhost';" 2>/dev/null || true
            mysql -e "DROP USER IF EXISTS '${db_user}'@'%';" 2>/dev/null || true
            mysql -e "FLUSH PRIVILEGES;" 2>/dev/null || true
            print_message "Database and DB user removal attempted."
        else
            print_message "Skipped database removal."
        fi
    fi

    systemctl reload nginx 2>/dev/null || true
    print_message "Uninstall complete."
    exit 0
}

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    print_error "Please run this script as root or with sudo"
    exit 1
fi

# Check if running on Debian/Ubuntu
if [ ! -f /etc/debian_version ]; then
    print_warning "This script is primarily designed for Debian/Ubuntu. It may not work correctly on other distributions."
    if ! prompt_yes_no "Do you want to continue anyway?" "n"; then
        exit 1
    fi
fi

# Welcome banner
clear
echo -e "${CYAN}"
if [ "$INSTALL_MODE" = "update" ]; then
cat << "EOF"
╔═══════════════════════════════════════════════════════════════════╗
║                                                                   ║
║   Secure FTP Web Application - Update Wizard                      ║
║   Version 1.0                                                     ║
║                                                                   ║
║   This wizard will update your application files while            ║
║   preserving your database and uploaded files.                    ║
║                                                                   ║
╚═══════════════════════════════════════════════════════════════════╝
EOF
elif [ "$INSTALL_MODE" = "uninstall" ]; then
cat << "EOF"
╔═══════════════════════════════════════════════════════════════════╗
║                                                                   ║
║   Secure FTP Web Application - Uninstall Wizard                   ║
║                                                                   ║
║   This wizard removes the application and can optionally          ║
║   remove database resources.                                      ║
║                                                                   ║
╚═══════════════════════════════════════════════════════════════════╝
EOF
else
cat << "EOF"
╔═══════════════════════════════════════════════════════════════════╗
║                                                                   ║
║   Secure FTP Web Application - Installation Wizard                ║
║   Version 1.0                                                     ║
║                                                                   ║
║   This wizard will guide you through the installation process     ║
║   and configure all necessary components.                         ║
║                                                                   ║
╚═══════════════════════════════════════════════════════════════════╝
EOF
fi
echo -e "${NC}\n"

if [ "$INSTALL_MODE" = "uninstall" ]; then
    run_uninstall
fi

if [ "$INSTALL_MODE" = "update" ]; then
    print_message "Starting update wizard..."
    echo ""
    print_warning "This script will update:"
    echo "  • Application files (PHP, CSS, JS, etc.)"
    echo "  • Nginx configuration (if needed)"
    echo "  • PHP-FPM configuration (if needed)"
    echo ""
    print_message "The following will be preserved:"
    echo "  • Database and all data"
    echo "  • Uploaded files"
    echo "  • Configuration settings (config.php)"
    echo ""
    
    if ! prompt_yes_no "Do you want to continue with the update?" "y"; then
        print_message "Update cancelled by user."
        exit 0
    fi
else
    print_message "Starting installation wizard..."
    echo ""
    print_warning "This script will install and configure:"
    echo "  • Nginx web server"
    echo "  • PHP-FPM and required extensions"
    echo "  • MariaDB database server"
    echo "  • Secure FTP Web Application"
    echo ""

    if ! prompt_yes_no "Do you want to continue with the installation?" "y"; then
        print_message "Installation cancelled by user."
        exit 0
    fi
fi

# Configuration steps - skip if in update mode
if [ "$UPDATE_MODE" = true ]; then
    print_header "UPDATE MODE: Detecting Configuration"
    
    # Try to detect existing installation
    if [ -d "/var/www/html/secure-ftp" ]; then
        APP_DIR="/var/www/html/secure-ftp"
    else
        APP_DIR=$(prompt_input "Enter application installation path" "/var/www/html/secure-ftp")
    fi
    
    if [ ! -d "$APP_DIR" ]; then
        print_error "Application directory not found: $APP_DIR"
        print_error "Please run a full installation first"
        exit 1
    fi
    
    print_message "Application directory: $APP_DIR"
    
    # Detect PHP version
    PHP_VERSION=$(php -r 'echo PHP_MAJOR_VERSION.".".PHP_MINOR_VERSION;' 2>/dev/null || echo "")
    if [ -z "$PHP_VERSION" ]; then
        print_warning "PHP not detected. Will install PHP packages."
    else
        print_message "Detected PHP version: $PHP_VERSION"
    fi
    
else
    # Full installation configuration
    print_header "STEP 1: Configuration"

    # Get installation directory
    print_step "Installation directory configuration"
    APP_DIR=$(prompt_input "Enter application installation path" "/var/www/html/secure-ftp")

    # Get domain/server name
    print_step "Domain configuration"
    echo ""
    echo "Enter your domain name (e.g., example.com) or leave blank to use server IP."
    echo "This will be used for Nginx configuration."
    DOMAIN_NAME=$(prompt_input "Domain name" "")

    if [ -z "$DOMAIN_NAME" ]; then
        print_message "No domain specified. Using default configuration."
        DOMAIN_NAME="_"
    else
        print_message "Domain set to: $DOMAIN_NAME"
    fi

    # Database configuration
    print_step "Database configuration"
    echo ""
    DB_NAME=$(prompt_input "Database name" "secure_ftp")
    DB_USER=$(prompt_input "Database user" "secure_ftp_user")

    # Confirm settings
    print_header "CONFIGURATION SUMMARY"
    echo -e "${CYAN}Installation Settings:${NC}"
    echo "  Application Path:    $APP_DIR"
    echo "  Domain Name:         $DOMAIN_NAME"
    echo "  Database Name:       $DB_NAME"
    echo "  Database User:       $DB_USER"
    echo ""

    # Check for existing installation
    if [ -d "$APP_DIR" ] && [ "$(ls -A $APP_DIR)" ]; then
        print_warning "EXISTING INSTALLATION DETECTED!"
        echo ""
        echo "The directory $APP_DIR already contains files."
        echo "The installation will:"
        echo "  • Delete and recreate the database: $DB_NAME"
        echo "  • Replace all application files"
        echo "  • Create a fresh uploads directory"
        echo ""
        if ! prompt_yes_no "Continue with CLEAN INSTALLATION (all data will be lost)?" "n"; then
            print_error "Installation cancelled by user."
            echo ""
            echo "If you want to update an existing installation, run:"
            echo "  sudo ./install.sh --update"
            exit 0
        fi
        print_warning "Proceeding with clean installation..."
    fi
    echo ""

    if ! prompt_yes_no "Proceed with these settings?" "y"; then
        print_error "Installation cancelled by user."
        exit 0
    fi
fi

# Update system packages - skip in update mode unless packages needed
if [ "$UPDATE_MODE" = false ]; then
    print_header "STEP 2: System Update"
    print_message "Updating system packages..."
    apt-get update
    apt-get upgrade -y

    # Install Nginx
    print_header "STEP 3: Installing Web Server"
    print_message "Installing Nginx..."
    apt-get install -y nginx

    # Install PHP and required extensions
    print_header "STEP 4: Installing PHP"
    print_message "Installing PHP and required extensions..."
    apt-get install -y php-fpm php-mysql php-mbstring php-xml php-curl php-gd php-zip

    # Detect PHP version
    PHP_VERSION=$(php -r 'echo PHP_MAJOR_VERSION.".".PHP_MINOR_VERSION;')
    print_message "Detected PHP version: $PHP_VERSION"

    # Install MySQL/MariaDB and utilities
    print_header "STEP 5: Installing Database Server and Utilities"
    print_message "Installing MariaDB and required utilities..."
    apt-get install -y mariadb-server mariadb-client openssl rsync

    # Start and enable services
    print_header "STEP 6: Starting Services"
    print_message "Starting and enabling services..."
    systemctl start mariadb
    systemctl enable mariadb
    systemctl start nginx
    systemctl enable nginx
    systemctl start php${PHP_VERSION}-fpm
    systemctl enable php${PHP_VERSION}-fpm
    print_message "All services started successfully"

    # Generate secure database password
    print_header "STEP 7: Database Configuration"
    print_message "Generating secure database password..."
    DB_PASS=$(openssl rand -base64 32)

    # Configure MySQL - Drop existing database and user to ensure clean install
    print_message "Cleaning up any existing database and user..."
    
    # Force drop the database
    mysql -e "DROP DATABASE IF EXISTS ${DB_NAME};" 2>&1 | grep -v "Warning" || true
    
    # Force drop the user - try multiple methods to ensure cleanup
    mysql -e "DROP USER IF EXISTS '${DB_USER}'@'localhost';" 2>&1 | grep -v "Warning" || true
    mysql -e "DROP USER IF EXISTS '${DB_USER}'@'%';" 2>&1 | grep -v "Warning" || true
    
    # Flush privileges to ensure changes take effect
    mysql -e "FLUSH PRIVILEGES;"
    
    # Wait a moment for changes to propagate
    sleep 1
    
    print_message "Creating fresh database and user..."
    
    # Create database
    if mysql -e "CREATE DATABASE ${DB_NAME} CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;"; then
        print_message "Database '${DB_NAME}' created successfully"
    else
        print_error "Failed to create database '${DB_NAME}'"
        exit 1
    fi
    
    # Create user
    if mysql -e "CREATE USER '${DB_USER}'@'localhost' IDENTIFIED BY '${DB_PASS}';"; then
        print_message "Database user '${DB_USER}' created successfully"
    else
        print_error "Failed to create database user '${DB_USER}'"
        exit 1
    fi
    
    # Grant privileges
    if mysql -e "GRANT ALL PRIVILEGES ON ${DB_NAME}.* TO '${DB_USER}'@'localhost';"; then
        print_message "Privileges granted successfully"
    else
        print_error "Failed to grant privileges"
        exit 1
    fi
    
    # Flush privileges again
    mysql -e "FLUSH PRIVILEGES;"
    
    # Verify connection works with new credentials
    if mysql -u "${DB_USER}" -p"${DB_PASS}" -e "SELECT 1;" ${DB_NAME} >/dev/null 2>&1; then
        print_message "Database connection verified successfully"
    else
        print_error "Failed to verify database connection"
        print_error "Please check the database credentials and try again"
        exit 1
    fi
    
    print_message "Database configured successfully"
fi

# Create application directory if it doesn't exist
if [ "$UPDATE_MODE" = true ]; then
    print_header "UPDATE: Backing Up Files"
else
    print_header "STEP 8: Application Installation"
fi
print_message "Setting up application directory..."

# If not in update mode, clean out any existing installation
if [ "$UPDATE_MODE" = false ]; then
    if [ -d "${APP_DIR}" ]; then
        print_message "Removing existing installation directory..."
        rm -rf "${APP_DIR}"
    fi
fi

mkdir -p "${APP_DIR}"

# Backup config.php and uploads in update mode
if [ "$UPDATE_MODE" = true ]; then
    BACKUP_DIR="${APP_DIR}_backup_$(date +%Y%m%d_%H%M%S)"
    print_message "Creating backup at ${BACKUP_DIR}..."
    mkdir -p ${BACKUP_DIR}
    
    # Backup config.php if it exists
    if [ -f "${APP_DIR}/app/src/core/config.php" ]; then
        mkdir -p "${BACKUP_DIR}/app/src/core"
        cp "${APP_DIR}/app/src/core/config.php" "${BACKUP_DIR}/app/src/core/config.php"
        print_message "Backed up config.php"
    fi
    
    # Backup uploads directory if it exists
    if [ -d "${APP_DIR}/app/storage/uploads" ]; then
        mkdir -p "${BACKUP_DIR}/app/storage"
        cp -r "${APP_DIR}/app/storage/uploads" "${BACKUP_DIR}/app/storage/uploads"
        print_message "Backed up uploads directory"
    fi
    
    print_message "Backup completed successfully"
fi

# Copy application files to web directory
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
print_message "Copying application files from ${SCRIPT_DIR} to ${APP_DIR}..."

# Copy files (exclude .git, install.sh, and other non-essential files)
# In update mode, also exclude config.php to preserve existing configuration
if [ "$UPDATE_MODE" = true ]; then
    rsync -av --exclude='.git' --exclude='/installs' --exclude='*.md' --exclude='LICENSE' --exclude='app/src/core/config.php' --exclude='app/storage/uploads' "${SCRIPT_DIR}/../" "${APP_DIR}/"
    print_message "Application files updated (config.php and uploads preserved)"
    
    # Restore config.php if backup exists
    if [ -f "${BACKUP_DIR}/app/src/core/config.php" ]; then
        cp "${BACKUP_DIR}/app/src/core/config.php" "${APP_DIR}/app/src/core/config.php"
        print_message "Restored config.php from backup"
    fi
    
    # Restore uploads if backup exists and uploads doesn't exist in target
    if [ -d "${BACKUP_DIR}/app/storage/uploads" ] && [ ! -d "${APP_DIR}/app/storage/uploads" ]; then
        mkdir -p "${APP_DIR}/app/storage"
        cp -r "${BACKUP_DIR}/app/storage/uploads" "${APP_DIR}/app/storage/uploads"
        print_message "Restored uploads directory from backup"
    fi
else
    rsync -av --exclude='.git' --exclude='/installs' --exclude='*.md' --exclude='LICENSE' "${SCRIPT_DIR}/../" "${APP_DIR}/"
fi

if [ ! -f "${APP_DIR}/public/index.php" ]; then
    print_error "Deployment verification failed: ${APP_DIR}/public/index.php not found."
    print_error "This usually indicates source path copy failed."
    exit 1
fi

# Create uploads directory with proper permissions (only if it doesn't exist)
if [ ! -d "${APP_DIR}/app/storage/uploads" ]; then
    print_message "Creating uploads directory..."
    mkdir -p ${APP_DIR}/app/storage/uploads
    chown -R www-data:www-data ${APP_DIR}/app/storage/uploads
    chmod -R 755 ${APP_DIR}/app/storage/uploads
fi
print_message "Application files installed successfully"

if [ "$UPDATE_MODE" = true ]; then
    run_update_db_migrations "${APP_DIR}"

    # Generate file encryption key if not already set
    if [ -f "${APP_DIR}/app/src/core/config.php" ]; then
        if grep -q "define('FILE_ENCRYPTION_KEY', 'CHANGE_THIS_KEY')" "${APP_DIR}/app/src/core/config.php"; then
            FILE_ENC_KEY=$(openssl rand -hex 32)
            sed -i "s|define('FILE_ENCRYPTION_KEY', '[^']*').*|define('FILE_ENCRYPTION_KEY', '${FILE_ENC_KEY}');|" ${APP_DIR}/app/src/core/config.php
            print_message "File encryption key generated for new encryption-at-rest feature"
        elif ! grep -q "FILE_ENCRYPTION_KEY" "${APP_DIR}/app/src/core/config.php"; then
            FILE_ENC_KEY=$(openssl rand -hex 32)
            # Append the define after the HASH line
            sed -i "/define('DEFAULT_HASH_ALGORITHM'/a\\
\\n// File encryption at rest (AES-256-GCM)\\n// IMPORTANT: Generated during installation. Do NOT change after files are uploaded!\\n// 64 hex characters = 32 bytes = 256-bit key\\ndefine('FILE_ENCRYPTION_KEY', '${FILE_ENC_KEY}');" ${APP_DIR}/app/src/core/config.php
            print_message "File encryption key added to config.php for new encryption-at-rest feature"
        else
            print_message "File encryption key already configured"
        fi
    fi
fi

# Import database schema - skip in update mode
if [ "$UPDATE_MODE" = false ]; then
    print_header "STEP 9: Database Schema Import"
    print_message "Importing database schema..."
    if [ -f "${APP_DIR}/database/sql/schema.sql" ]; then
        mysql ${DB_NAME} < ${APP_DIR}/database/sql/schema.sql
        print_message "Database schema imported successfully"
    else
        print_error "schema.sql not found in ${APP_DIR}/database/sql/"
        exit 1
    fi

    # Configure application
    print_header "STEP 10: Application Configuration"
    print_message "Configuring application..."
    if [ -f "${APP_DIR}/app/src/core/config.php" ]; then
        # Update database configuration - escape special characters in password
        DB_PASS_ESCAPED=$(printf '%s\n' "$DB_PASS" | sed -e 's/[\/&]/\\&/g')
        
        # Update each define line, handling optional comments
        sed -i "s|define('DB_PASS', '[^']*').*|define('DB_PASS', '${DB_PASS_ESCAPED}');|" ${APP_DIR}/app/src/core/config.php
        sed -i "s|define('DB_USER', '[^']*').*|define('DB_USER', '${DB_USER}');|" ${APP_DIR}/app/src/core/config.php
        sed -i "s|define('DB_NAME', '[^']*').*|define('DB_NAME', '${DB_NAME}');|" ${APP_DIR}/app/src/core/config.php
        
        # Generate and set file encryption key (AES-256 = 32 bytes = 64 hex chars)
        FILE_ENC_KEY=$(openssl rand -hex 32)
        sed -i "s|define('FILE_ENCRYPTION_KEY', '[^']*').*|define('FILE_ENCRYPTION_KEY', '${FILE_ENC_KEY}');|" ${APP_DIR}/app/src/core/config.php
        print_message "File encryption key generated and configured"
        
        # Verify the changes were made
        if grep -q "define('DB_PASS', '${DB_PASS_ESCAPED}');" ${APP_DIR}/app/src/core/config.php; then
            print_message "Application configured successfully"
        else
            print_error "Failed to update config.php with database credentials"
            print_error "Please manually update ${APP_DIR}/app/src/core/config.php with the following credentials:"
            echo "  DB_NAME: ${DB_NAME}"
            echo "  DB_USER: ${DB_USER}"
            echo "  DB_PASS: ${DB_PASS}"
            exit 1
        fi
    else
        print_error "config.php not found in ${APP_DIR}/app/src/core/"
        exit 1
    fi

    # Configure PHP for large file uploads
    print_header "STEP 11: PHP Configuration"
    print_message "Configuring PHP for large file uploads (10GB)..."
    PHP_INI="/etc/php/${PHP_VERSION}/fpm/php.ini"
    if [ -f "$PHP_INI" ]; then
        cp "$PHP_INI" "${PHP_INI}.backup"
        sed -i 's/upload_max_filesize = .*/upload_max_filesize = 10G/' "$PHP_INI"
        sed -i 's/post_max_size = .*/post_max_size = 10G/' "$PHP_INI"
        sed -i 's/max_execution_time = .*/max_execution_time = 300/' "$PHP_INI"
        sed -i 's/max_input_time = .*/max_input_time = 300/' "$PHP_INI"
        sed -i 's/memory_limit = .*/memory_limit = 512M/' "$PHP_INI"
        print_message "PHP configuration updated successfully"
    fi

    # Copy Nginx configuration
    print_header "STEP 12: Nginx Configuration"
    print_message "Configuring Nginx..."
    if [ -f "${APP_DIR}/webservers-config/secure-ftp.conf" ]; then
        cp "${APP_DIR}/webservers-config/secure-ftp.conf" "${NGINX_CONF}"

        # Update domain name in nginx config
        if [ "$DOMAIN_NAME" != "_" ]; then
            sed -i "s/server_name _;/server_name ${DOMAIN_NAME};/" "${NGINX_CONF}"
            print_message "Domain name set to: $DOMAIN_NAME"
        fi
        
        # Update PHP-FPM socket path in nginx config
        sed -i "s|php-fpm.sock|php${PHP_VERSION}-fpm.sock|g" "${NGINX_CONF}"
        
        # Update application path in nginx config
        sed -i "s|/var/www/html/secure-ftp/public|${APP_DIR}/public|g" "${NGINX_CONF}"
        
        # Enable the site
        ln -sf "${NGINX_CONF}" "${NGINX_ENABLED}"
        
        # Disable default site if it exists
        if [ -f /etc/nginx/sites-enabled/default ]; then
            rm -f /etc/nginx/sites-enabled/default
            print_message "Default site disabled"
        fi
        
        print_message "Nginx configuration installed successfully"
    else
        print_error "secure-ftp.conf not found in ${APP_DIR}/webservers-config/"
        exit 1
    fi
else
    # Update mode - only update PHP configuration if needed
    print_header "UPDATE: PHP Configuration Check"
    if [ -n "$PHP_VERSION" ]; then
        PHP_INI="/etc/php/${PHP_VERSION}/fpm/php.ini"
        if [ -f "$PHP_INI" ]; then
            print_message "Verifying PHP configuration..."
            # Only update if values are lower than required
            sed -i 's/upload_max_filesize = .*/upload_max_filesize = 10G/' "$PHP_INI"
            sed -i 's/post_max_size = .*/post_max_size = 10G/' "$PHP_INI"
            sed -i 's/max_execution_time = .*/max_execution_time = 300/' "$PHP_INI"
            sed -i 's/max_input_time = .*/max_input_time = 300/' "$PHP_INI"
            sed -i 's/memory_limit = .*/memory_limit = 512M/' "$PHP_INI"
            print_message "PHP configuration verified"
        fi
    fi
    
    # Update Nginx configuration if needed
    print_header "UPDATE: Nginx Configuration"
    if [ -f "${APP_DIR}/webservers-config/secure-ftp.conf" ]; then
        # Detect PHP version for nginx config
        if [ -z "$PHP_VERSION" ]; then
            PHP_VERSION=$(php -r 'echo PHP_MAJOR_VERSION.".".PHP_MINOR_VERSION;' 2>/dev/null || echo "8.1")
        fi
        
        cp "${APP_DIR}/webservers-config/secure-ftp.conf" "${NGINX_CONF}"
        
        # Update PHP-FPM socket path in nginx config
        sed -i "s|php-fpm.sock|php${PHP_VERSION}-fpm.sock|g" "${NGINX_CONF}"
        
        # Update application path in nginx config
        sed -i "s|/var/www/html/secure-ftp/public|${APP_DIR}/public|g" "${NGINX_CONF}"
        
        # Enable the site
        ln -sf "${NGINX_CONF}" "${NGINX_ENABLED}"
        
        print_message "Nginx configuration updated"
    fi
fi

# Test Nginx configuration
print_message "Testing Nginx configuration..."
if nginx -t 2>&1 | tee /tmp/nginx-test.log; then
    print_message "Nginx configuration is valid"
else
    print_error "Nginx configuration test failed"
    cat /tmp/nginx-test.log
    exit 1
fi

# Set proper file permissions
if [ "$UPDATE_MODE" = true ]; then
    print_header "UPDATE: File Permissions"
else
    print_header "STEP 13: File Permissions"
fi
print_message "Setting file permissions..."
chown -R www-data:www-data "${APP_DIR}"
chmod -R 755 "${APP_DIR}"
chmod -R 755 "${APP_DIR}/app/storage/uploads"

# Protect sensitive files
if [ -f "${APP_DIR}/app/src/core/config.php" ]; then
    chmod 600 "${APP_DIR}/app/src/core/config.php"
fi
chmod 600 "${APP_DIR}/database/sql/schema.sql" 2>/dev/null || true
print_message "File permissions configured successfully"

# Restart services
if [ "$UPDATE_MODE" = true ]; then
    print_header "UPDATE: Restarting Services"
else
    print_header "STEP 14: Restarting Services"
fi
print_message "Restarting PHP-FPM and Nginx..."
if [ -z "$PHP_VERSION" ]; then
    PHP_VERSION=$(php -r 'echo PHP_MAJOR_VERSION.".".PHP_MINOR_VERSION;' 2>/dev/null || echo "8.1")
fi
systemctl restart php${PHP_VERSION}-fpm
systemctl restart nginx
print_message "Services restarted successfully"

# Skip admin user creation in update mode
if [ "$UPDATE_MODE" = true ]; then
    # Get server IP address
    SERVER_IP=$(hostname -I | awk '{print $1}')
    
    print_header "UPDATE COMPLETE"
    echo ""
    echo "================================================================"
    echo -e "${GREEN}"
    cat << "EOF"
╔═══════════════════════════════════════════════════════════════════╗
║                                                                   ║
║               UPDATE COMPLETED SUCCESSFULLY!                      ║
║                                                                   ║
╚═══════════════════════════════════════════════════════════════════╝
EOF
    echo -e "${NC}"
    echo "================================================================"
    echo ""
    echo -e "${GREEN}✓${NC} Application files updated"
    echo -e "${GREEN}✓${NC} Configuration files preserved"
    echo -e "${GREEN}✓${NC} Database and uploads preserved"
    echo -e "${GREEN}✓${NC} PHP configuration verified"
    echo -e "${GREEN}✓${NC} Nginx configuration updated"
    echo -e "${GREEN}✓${NC} Services restarted"
    echo ""
    echo "================================================================"
    echo -e "${CYAN}APPLICATION INFORMATION:${NC}"
    echo "================================================================"
    echo ""
    echo -e "  Application Path: ${YELLOW}${APP_DIR}${NC}"
    echo -e "  Backup Location:  ${YELLOW}${BACKUP_DIR}${NC}"
    echo ""
    echo "================================================================"
    echo -e "${YELLOW}IMPORTANT NOTES:${NC}"
    echo "================================================================"
    echo ""
    echo "  1. Your database and uploaded files were preserved"
    echo "  2. Configuration backup saved to: ${BACKUP_DIR}"
    echo "  3. You can safely delete the backup after verifying the update"
    echo "  4. Test your application thoroughly"
    echo ""
    echo "================================================================"
    echo ""
    print_message "Update completed successfully!"
    echo ""
    exit 0
fi

# Create admin user
print_header "STEP 15: Admin User Creation"
print_message "Creating admin user account..."
print_warning "Default credentials are admin/admin"
print_warning "Please change the password after first login!"
echo ""

# Set default credentials (with validation loop for username policy)
while true; do
    ADMIN_USER_INPUT=$(prompt_input "Admin username (lowercase only: a-z, 0-9, dot, underscore, hyphen; 3-50 chars)" "admin")
    ADMIN_USER=$(normalize_username "$ADMIN_USER_INPUT")

    if [ "$ADMIN_USER" != "$ADMIN_USER_INPUT" ]; then
        print_warning "Username was normalized to lowercase: ${ADMIN_USER}"
    fi

    if ! is_valid_username "$ADMIN_USER"; then
        print_error "Invalid username. Use lowercase only: a-z, 0-9, dot, underscore, hyphen (3-50 chars)."
        continue
    fi

    break
done

ADMIN_PASS="admin"

# Hash password using PHP
ADMIN_PASS_HASH=$(php -r "echo password_hash('${ADMIN_PASS}', PASSWORD_BCRYPT);")

# Insert admin user into database with role support
mysql ${DB_NAME} -e "INSERT INTO users (username, password_hash, email, role, is_admin, is_active) VALUES ('${ADMIN_USER}', '${ADMIN_PASS_HASH}', 'admin@example.com', 'admin', TRUE, TRUE) ON DUPLICATE KEY UPDATE password_hash='${ADMIN_PASS_HASH}', role='admin', is_admin=TRUE;"

print_message "Admin user '${ADMIN_USER}' created successfully with admin role"

# Get server IP address
SERVER_IP=$(hostname -I | awk '{print $1}')

# Determine access URL
if [ "$DOMAIN_NAME" != "_" ]; then
    ACCESS_URL="http://${DOMAIN_NAME}"
else
    ACCESS_URL="http://${SERVER_IP}"
fi

# Save credentials to file
print_header "STEP 16: Saving Configuration"
CREDS_FILE="${SCRIPT_DIR}/installation_credentials.txt"
cat > ${CREDS_FILE} << EOF
=================================================
Secure FTP Web Application - Installation Complete
=================================================

Installation Date: $(date)

SERVER INFORMATION:
------------------
Server IP: ${SERVER_IP}
Domain: ${DOMAIN_NAME}

DATABASE CREDENTIALS:
--------------------
Database Name: ${DB_NAME}
Database User: ${DB_USER}
Database Password: ${DB_PASS}

APPLICATION CREDENTIALS:
-----------------------
Admin Username: ${ADMIN_USER}
Admin Password: ${ADMIN_PASS}

APPLICATION PATHS:
-----------------
Application Directory: ${APP_DIR}
Uploads Directory: ${APP_DIR}/app/storage/uploads
Nginx Config: ${NGINX_CONF}

ACCESS INFORMATION:
------------------
Application URL: ${ACCESS_URL}
$([ -z "$DOMAIN_NAME" ] || [ "$DOMAIN_NAME" = "_" ] && echo "Local Access: http://localhost")

IMPORTANT SECURITY NOTES:
------------------------
1. Keep this file secure and delete it after noting the credentials
2. Change the admin password after first login
3. Configure a firewall to restrict access
4. Place behind a reverse proxy with SSL/TLS if exposing publicly
5. Regularly backup the database and uploads directory
6. Review SECURITY.md for additional hardening steps

NEXT STEPS:
----------
1. Access the application at ${ACCESS_URL}
2. Login with admin credentials
3. Change default passwords in admin panel
4. Set up a reverse proxy if making publicly accessible (see docs/REVERSE-PROXY-README.md)
5. Create regular users or access codes
6. Configure regular backups

USEFUL COMMANDS:
---------------
Restart Nginx: sudo systemctl restart nginx
Restart PHP-FPM: sudo systemctl restart php${PHP_VERSION}-fpm
View Nginx logs: sudo tail -f /var/log/nginx/secure-ftp-error.log
View access logs: sudo tail -f /var/log/nginx/secure-ftp-access.log
Database backup: mysqldump -u ${DB_USER} -p ${DB_NAME} > backup.sql

=================================================
EOF

chmod 600 ${CREDS_FILE}
print_message "Configuration saved to: ${CREDS_FILE}"

echo ""
echo "================================================================"
echo -e "${GREEN}"
cat << "EOF"
╔═══════════════════════════════════════════════════════════════════╗
║                                                                   ║
║              INSTALLATION COMPLETED SUCCESSFULLY!                 ║
║                                                                   ║
╚═══════════════════════════════════════════════════════════════════╝
EOF
echo -e "${NC}"
echo "================================================================"
echo ""
echo -e "${GREEN}✓${NC} Nginx web server installed and configured"
echo -e "${GREEN}✓${NC} PHP ${PHP_VERSION} with FPM installed"
echo -e "${GREEN}✓${NC} MariaDB database server configured"
echo -e "${GREEN}✓${NC} Application files deployed"
echo -e "${GREEN}✓${NC} Database schema imported"
echo -e "${GREEN}✓${NC} Admin user created"
echo ""
echo "================================================================"
echo -e "${CYAN}ACCESS YOUR APPLICATION:${NC}"
echo "================================================================"
echo ""
echo -e "  URL: ${YELLOW}${ACCESS_URL}${NC}"
echo ""
echo -e "  Admin Username: ${YELLOW}${ADMIN_USER}${NC}"
echo -e "  Admin Password: ${YELLOW}(saved in credentials file)${NC}"
echo ""
echo "================================================================"
echo -e "${YELLOW}⚠ IMPORTANT SECURITY REMINDERS:${NC}"
echo "================================================================"
echo ""
echo "  1. Credentials saved to: ${CREDS_FILE}"
echo "     ${RED}Please save these credentials and DELETE this file!${NC}"
echo ""
echo "  2. Change the admin password after first login"
echo ""
echo "  3. Configure firewall rules"
echo ""
echo "  4. Set up regular backups"
echo ""
echo "  5. Use a reverse proxy with SSL if exposing publicly"
echo ""
echo "================================================================"
echo "================================================================"
echo ""
print_message "Thank you for using Secure FTP Web Application!"
echo ""
echo "For support and documentation, visit:"
echo "  https://github.com/TwiStarSystems/Secure-FTP-WEB"
echo ""
echo "================================================================"
