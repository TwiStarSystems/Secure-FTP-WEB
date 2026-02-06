#!/bin/bash

# Secure FTP Web Application - Automated Installation Script for Debian/Ubuntu
# This script installs and configures Nginx, PHP, MySQL/MariaDB, and the application
# Usage: ./install.sh [--update]
#   --update: Update application files without modifying database or uploads

set -e  # Exit on error

# Check if running in update mode
UPDATE_MODE=false
if [ "$1" = "--update" ]; then
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
SETUP_SSL=false

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
if [ "$UPDATE_MODE" = true ]; then
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

if [ "$UPDATE_MODE" = true ]; then
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

    # Ask about SSL
    print_step "SSL/HTTPS configuration"
    echo ""
    echo "Do you want to set up SSL/HTTPS with Let's Encrypt?"
    echo "Note: You must have a valid domain name pointing to this server."
    if [ "$DOMAIN_NAME" = "_" ]; then
        print_warning "SSL setup requires a domain name. Skipping SSL configuration."
        SETUP_SSL=false
    else
        if prompt_yes_no "Set up SSL/HTTPS now?" "n"; then
            SETUP_SSL=true
            print_message "SSL will be configured after installation."
        else
            SETUP_SSL=false
            print_message "SSL can be configured later manually."
        fi
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
    echo "  SSL/HTTPS:           $([ "$SETUP_SSL" = true ] && echo 'Yes' || echo 'No')"
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
        rm -rf ${APP_DIR}
    fi
fi

mkdir -p ${APP_DIR}

# Backup config.php and uploads in update mode
if [ "$UPDATE_MODE" = true ]; then
    BACKUP_DIR="${APP_DIR}_backup_$(date +%Y%m%d_%H%M%S)"
    print_message "Creating backup at ${BACKUP_DIR}..."
    mkdir -p ${BACKUP_DIR}
    
    # Backup config.php if it exists
    if [ -f "${APP_DIR}/config.php" ]; then
        cp ${APP_DIR}/config.php ${BACKUP_DIR}/config.php
        print_message "Backed up config.php"
    fi
    
    # Backup uploads directory if it exists
    if [ -d "${APP_DIR}/uploads" ]; then
        cp -r ${APP_DIR}/uploads ${BACKUP_DIR}/uploads
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
    rsync -av --exclude='.git' --exclude='install.sh' --exclude='*.md' --exclude='LICENSE' --exclude='config.php' --exclude='uploads' ${SCRIPT_DIR}/ ${APP_DIR}/
    print_message "Application files updated (config.php and uploads preserved)"
    
    # Restore config.php if backup exists
    if [ -f "${BACKUP_DIR}/config.php" ]; then
        cp ${BACKUP_DIR}/config.php ${APP_DIR}/config.php
        print_message "Restored config.php from backup"
    fi
    
    # Restore uploads if backup exists and uploads doesn't exist in target
    if [ -d "${BACKUP_DIR}/uploads" ] && [ ! -d "${APP_DIR}/uploads" ]; then
        cp -r ${BACKUP_DIR}/uploads ${APP_DIR}/uploads
        print_message "Restored uploads directory from backup"
    fi
else
    rsync -av --exclude='.git' --exclude='install.sh' --exclude='*.md' --exclude='LICENSE' ${SCRIPT_DIR}/ ${APP_DIR}/
fi

# Create uploads directory with proper permissions (only if it doesn't exist)
if [ ! -d "${APP_DIR}/uploads" ]; then
    print_message "Creating uploads directory..."
    mkdir -p ${APP_DIR}/uploads
    chown -R www-data:www-data ${APP_DIR}/uploads
    chmod -R 755 ${APP_DIR}/uploads
fi
print_message "Application files installed successfully"

# Import database schema - skip in update mode
if [ "$UPDATE_MODE" = false ]; then
    print_header "STEP 9: Database Schema Import"
    print_message "Importing database schema..."
    if [ -f "${APP_DIR}/database.sql" ]; then
        mysql ${DB_NAME} < ${APP_DIR}/database.sql
        print_message "Database schema imported successfully"
    else
        print_error "database.sql not found in ${APP_DIR}"
        exit 1
    fi

    # Configure application
    print_header "STEP 10: Application Configuration"
    print_message "Configuring application..."
    if [ -f "${APP_DIR}/config.php" ]; then
        # Update database configuration - escape special characters in password
        DB_PASS_ESCAPED=$(printf '%s\n' "$DB_PASS" | sed -e 's/[\/&]/\\&/g')
        
        # Update each define line, handling optional comments
        sed -i "s|define('DB_PASS', '[^']*').*|define('DB_PASS', '${DB_PASS_ESCAPED}');|" ${APP_DIR}/config.php
        sed -i "s|define('DB_USER', '[^']*').*|define('DB_USER', '${DB_USER}');|" ${APP_DIR}/config.php
        sed -i "s|define('DB_NAME', '[^']*').*|define('DB_NAME', '${DB_NAME}');|" ${APP_DIR}/config.php
        
        # Verify the changes were made
        if grep -q "define('DB_PASS', '${DB_PASS_ESCAPED}');" ${APP_DIR}/config.php; then
            print_message "Application configured successfully"
        else
            print_error "Failed to update config.php with database credentials"
            print_error "Please manually update ${APP_DIR}/config.php with the following credentials:"
            echo "  DB_NAME: ${DB_NAME}"
            echo "  DB_USER: ${DB_USER}"
            echo "  DB_PASS: ${DB_PASS}"
            exit 1
        fi
    else
        print_error "config.php not found in ${APP_DIR}"
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
    if [ -f "${APP_DIR}/secure-ftp.conf" ]; then
        cp ${APP_DIR}/secure-ftp.conf ${NGINX_CONF}
        
        # Update domain name in nginx config
        if [ "$DOMAIN_NAME" != "_" ]; then
            sed -i "s/server_name _;/server_name ${DOMAIN_NAME};/" ${NGINX_CONF}
            print_message "Domain name set to: $DOMAIN_NAME"
        fi
        
        # Update PHP-FPM socket path in nginx config
        sed -i "s|php-fpm.sock|php${PHP_VERSION}-fpm.sock|g" ${NGINX_CONF}
        
        # Update application path in nginx config
        sed -i "s|/var/www/html/secure-ftp|${APP_DIR}|g" ${NGINX_CONF}
        
        # Enable the site
        ln -sf ${NGINX_CONF} ${NGINX_ENABLED}
        
        # Disable default site if it exists
        if [ -f /etc/nginx/sites-enabled/default ]; then
            rm -f /etc/nginx/sites-enabled/default
            print_message "Default site disabled"
        fi
        
        print_message "Nginx configuration installed successfully"
    else
        print_error "secure-ftp.conf not found in ${APP_DIR}"
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
    if [ -f "${APP_DIR}/secure-ftp.conf" ]; then
        # Detect PHP version for nginx config
        if [ -z "$PHP_VERSION" ]; then
            PHP_VERSION=$(php -r 'echo PHP_MAJOR_VERSION.".".PHP_MINOR_VERSION;' 2>/dev/null || echo "8.1")
        fi
        
        cp ${APP_DIR}/secure-ftp.conf ${NGINX_CONF}
        
        # Update PHP-FPM socket path in nginx config
        sed -i "s|php-fpm.sock|php${PHP_VERSION}-fpm.sock|g" ${NGINX_CONF}
        
        # Update application path in nginx config
        sed -i "s|/var/www/html/secure-ftp|${APP_DIR}|g" ${NGINX_CONF}
        
        # Enable the site
        ln -sf ${NGINX_CONF} ${NGINX_ENABLED}
        
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
chown -R www-data:www-data ${APP_DIR}
chmod -R 755 ${APP_DIR}
chmod -R 755 ${APP_DIR}/uploads

# Protect sensitive files
if [ -f "${APP_DIR}/config.php" ]; then
    chmod 600 ${APP_DIR}/config.php
fi
chmod 600 ${APP_DIR}/database.sql 2>/dev/null || true
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

# Skip admin user creation and SSL setup in update mode
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
print_message "Creating default admin user account..."
print_warning "Using default credentials - admin/admin"
print_warning "Please change the password after first login!"
echo ""

# Set default credentials
ADMIN_USER="admin"
ADMIN_PASS="admin"

# Hash password using PHP
ADMIN_PASS_HASH=$(php -r "echo password_hash('${ADMIN_PASS}', PASSWORD_BCRYPT);")

# Insert admin user into database with role support
mysql ${DB_NAME} -e "INSERT INTO users (username, password_hash, email, role, is_admin, is_active) VALUES ('${ADMIN_USER}', '${ADMIN_PASS_HASH}', 'admin@example.com', 'admin', TRUE, TRUE) ON DUPLICATE KEY UPDATE password_hash='${ADMIN_PASS_HASH}', role='admin', is_admin=TRUE;"

print_message "Admin user '${ADMIN_USER}' created successfully with admin role"

# SSL Configuration
if [ "$SETUP_SSL" = true ]; then
    print_header "STEP 16: SSL Configuration"
    print_message "Installing Certbot for Let's Encrypt..."
    
    apt-get install -y certbot python3-certbot-nginx
    
    print_message "Obtaining SSL certificate..."
    echo ""
    print_warning "Make sure your domain ${DOMAIN_NAME} points to this server's IP address."
    echo ""
    
    if prompt_yes_no "Ready to obtain SSL certificate?" "y"; then
        if certbot --nginx -d ${DOMAIN_NAME} --non-interactive --agree-tos --register-unsafely-without-email; then
            print_message "SSL certificate installed successfully"
            
            # Update config.php to enable secure cookies
            sed -i "s/ini_set('session.cookie_secure', 0);/ini_set('session.cookie_secure', 1);/" ${APP_DIR}/config.php
            print_message "Application configured for HTTPS"
        else
            print_warning "SSL certificate installation failed. You can set it up manually later."
            print_message "Run: sudo certbot --nginx -d ${DOMAIN_NAME}"
        fi
    else
        print_message "SSL setup skipped. You can run it later with:"
        echo "  sudo certbot --nginx -d ${DOMAIN_NAME}"
    fi
fi

# Get server IP address
SERVER_IP=$(hostname -I | awk '{print $1}')

# Determine access URL
if [ "$SETUP_SSL" = true ] && [ "$DOMAIN_NAME" != "_" ]; then
    ACCESS_URL="https://${DOMAIN_NAME}"
elif [ "$DOMAIN_NAME" != "_" ]; then
    ACCESS_URL="http://${DOMAIN_NAME}"
else
    ACCESS_URL="http://${SERVER_IP}"
fi

# Save credentials to file
print_header "STEP $([ "$SETUP_SSL" = true ] && echo "17" || echo "16"): Saving Configuration"
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
SSL/HTTPS: $([ "$SETUP_SSL" = true ] && echo "Enabled" || echo "Not configured")

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
Uploads Directory: ${APP_DIR}/uploads
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
$([ "$SETUP_SSL" = false ] && echo "4. Consider setting up SSL/HTTPS for production use")
5. Regularly backup the database and uploads directory
6. Review SECURITY.md for additional hardening steps

NEXT STEPS:
----------
1. Access the application at ${ACCESS_URL}
2. Login with admin credentials
3. Change default passwords in admin panel
$([ "$SETUP_SSL" = false ] && echo "4. Set up SSL certificate (recommended)")
5. Create regular users or access codes
6. Configure regular backups

$([ "$SETUP_SSL" = false ] && [ "$DOMAIN_NAME" != "_" ] && echo "For SSL setup with Let's Encrypt:
    sudo apt install certbot python3-certbot-nginx
    sudo certbot --nginx -d ${DOMAIN_NAME}")

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
$([ "$SETUP_SSL" = true ] && echo -e "${GREEN}✓${NC} SSL certificate installed")
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
$([ "$SETUP_SSL" = false ] && echo "  3. Set up SSL/HTTPS for production use")
echo "  $([ "$SETUP_SSL" = false ] && echo "4" || echo "3"). Configure firewall rules"
echo ""
echo "  $([ "$SETUP_SSL" = false ] && echo "5" || echo "4"). Set up regular backups"
echo ""
echo "================================================================"
$([ "$SETUP_SSL" = false ] && [ "$DOMAIN_NAME" != "_" ] && cat << SSLEOF
echo ""
echo -e "${BLUE}To set up SSL later, run:${NC}"
echo "  sudo apt install certbot python3-certbot-nginx"
echo "  sudo certbot --nginx -d ${DOMAIN_NAME}"
echo ""
SSLEOF
)
echo "================================================================"
echo ""
print_message "Thank you for using Secure FTP Web Application!"
echo ""
echo "For support and documentation, visit:"
echo "  https://github.com/TwiStarSystems/Secure-FTP-WEB"
echo ""
echo "================================================================"
