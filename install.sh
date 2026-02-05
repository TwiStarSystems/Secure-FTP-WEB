#!/bin/bash

# Secure FTP Web Application - Automated Installation Script for Debian/Ubuntu
# This script installs and configures Nginx, PHP, MySQL/MariaDB, and the application

set -e  # Exit on error

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration variables
APP_DIR="/var/www/html/secure-ftp"
DB_NAME="secure_ftp"
DB_USER="secure_ftp_user"
NGINX_CONF="/etc/nginx/sites-available/secure-ftp.conf"
NGINX_ENABLED="/etc/nginx/sites-enabled/secure-ftp.conf"

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

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    print_error "Please run this script as root or with sudo"
    exit 1
fi

# Check if running on Debian/Ubuntu
if [ ! -f /etc/debian_version ]; then
    print_warning "This script is primarily designed for Debian/Ubuntu. It may not work correctly on other distributions."
    read -p "Do you want to continue anyway? (y/N) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

print_message "Starting installation of Secure FTP Web Application..."
echo ""

# Update system packages
print_message "Updating system packages..."
apt-get update
apt-get upgrade -y

# Install Nginx
print_message "Installing Nginx..."
apt-get install -y nginx

# Install PHP and required extensions
print_message "Installing PHP and required extensions..."
apt-get install -y php-fpm php-mysql php-mbstring php-xml php-curl php-gd php-zip

# Detect PHP version
PHP_VERSION=$(php -r 'echo PHP_MAJOR_VERSION.".".PHP_MINOR_VERSION;')
print_message "Detected PHP version: $PHP_VERSION"

# Install MySQL/MariaDB
print_message "Installing MariaDB..."
apt-get install -y mariadb-server mariadb-client

# Start and enable services
print_message "Starting and enabling services..."
systemctl start mariadb
systemctl enable mariadb
systemctl start nginx
systemctl enable nginx
systemctl start php${PHP_VERSION}-fpm
systemctl enable php${PHP_VERSION}-fpm

# Generate secure database password
print_message "Generating secure database password..."
DB_PASS=$(openssl rand -base64 32)

# Configure MySQL
print_message "Configuring MariaDB database..."
mysql -e "CREATE DATABASE IF NOT EXISTS ${DB_NAME} CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;"
mysql -e "CREATE USER IF NOT EXISTS '${DB_USER}'@'localhost' IDENTIFIED BY '${DB_PASS}';"
mysql -e "GRANT ALL PRIVILEGES ON ${DB_NAME}.* TO '${DB_USER}'@'localhost';"
mysql -e "FLUSH PRIVILEGES;"

# Create application directory if it doesn't exist
print_message "Setting up application directory..."
mkdir -p ${APP_DIR}

# Copy application files to web directory
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
print_message "Copying application files from ${SCRIPT_DIR} to ${APP_DIR}..."

# Copy files (exclude .git, install.sh, and other non-essential files)
rsync -av --exclude='.git' --exclude='install.sh' --exclude='*.md' --exclude='LICENSE' ${SCRIPT_DIR}/ ${APP_DIR}/

# Create uploads directory with proper permissions
print_message "Creating uploads directory..."
mkdir -p ${APP_DIR}/uploads
chown -R www-data:www-data ${APP_DIR}/uploads
chmod -R 755 ${APP_DIR}/uploads

# Import database schema
print_message "Importing database schema..."
if [ -f "${APP_DIR}/database.sql" ]; then
    mysql ${DB_NAME} < ${APP_DIR}/database.sql
    print_message "Database schema imported successfully"
else
    print_error "database.sql not found in ${APP_DIR}"
    exit 1
fi

# Configure application
print_message "Configuring application..."
if [ -f "${APP_DIR}/config.php" ]; then
    # Update database configuration
    sed -i "s/define('DB_PASS', '.*');/define('DB_PASS', '${DB_PASS}');/" ${APP_DIR}/config.php
    sed -i "s/define('DB_USER', '.*');/define('DB_USER', '${DB_USER}');/" ${APP_DIR}/config.php
    sed -i "s/define('DB_NAME', '.*');/define('DB_NAME', '${DB_NAME}');/" ${APP_DIR}/config.php
    print_message "Configuration updated"
else
    print_error "config.php not found in ${APP_DIR}"
    exit 1
fi

# Configure PHP for large file uploads
print_message "Configuring PHP for large file uploads..."
PHP_INI="/etc/php/${PHP_VERSION}/fpm/php.ini"
if [ -f "$PHP_INI" ]; then
    cp "$PHP_INI" "${PHP_INI}.backup"
    sed -i 's/upload_max_filesize = .*/upload_max_filesize = 10G/' "$PHP_INI"
    sed -i 's/post_max_size = .*/post_max_size = 10G/' "$PHP_INI"
    sed -i 's/max_execution_time = .*/max_execution_time = 300/' "$PHP_INI"
    sed -i 's/max_input_time = .*/max_input_time = 300/' "$PHP_INI"
    sed -i 's/memory_limit = .*/memory_limit = 512M/' "$PHP_INI"
    print_message "PHP configuration updated"
fi

# Copy Nginx configuration
print_message "Configuring Nginx..."
if [ -f "${APP_DIR}/secure-ftp.conf" ]; then
    cp ${APP_DIR}/secure-ftp.conf ${NGINX_CONF}
    
    # Update PHP-FPM socket path in nginx config
    sed -i "s|php-fpm.sock|php${PHP_VERSION}-fpm.sock|g" ${NGINX_CONF}
    
    # Enable the site
    ln -sf ${NGINX_CONF} ${NGINX_ENABLED}
    
    # Disable default site if it exists
    if [ -f /etc/nginx/sites-enabled/default ]; then
        rm -f /etc/nginx/sites-enabled/default
    fi
    
    print_message "Nginx configuration installed"
else
    print_error "secure-ftp.conf not found in ${APP_DIR}"
    exit 1
fi

# Test Nginx configuration
print_message "Testing Nginx configuration..."
if nginx -t; then
    print_message "Nginx configuration is valid"
else
    print_error "Nginx configuration test failed"
    exit 1
fi

# Set proper file permissions
print_message "Setting file permissions..."
chown -R www-data:www-data ${APP_DIR}
chmod -R 755 ${APP_DIR}
chmod -R 755 ${APP_DIR}/uploads

# Protect sensitive files
chmod 600 ${APP_DIR}/config.php
chmod 600 ${APP_DIR}/database.sql 2>/dev/null || true

# Restart services
print_message "Restarting services..."
systemctl restart php${PHP_VERSION}-fpm
systemctl restart nginx

# Create admin user
print_message "Creating admin user..."
read -p "Enter admin username [admin]: " ADMIN_USER
ADMIN_USER=${ADMIN_USER:-admin}

read -s -p "Enter admin password: " ADMIN_PASS
echo ""
read -s -p "Confirm admin password: " ADMIN_PASS_CONFIRM
echo ""

if [ "$ADMIN_PASS" != "$ADMIN_PASS_CONFIRM" ]; then
    print_error "Passwords do not match"
    exit 1
fi

# Hash password using PHP
ADMIN_PASS_HASH=$(php -r "echo password_hash('${ADMIN_PASS}', PASSWORD_BCRYPT);")

# Insert admin user into database
mysql ${DB_NAME} -e "INSERT INTO users (username, password_hash, is_admin, is_active) VALUES ('${ADMIN_USER}', '${ADMIN_PASS_HASH}', TRUE, TRUE) ON DUPLICATE KEY UPDATE password_hash='${ADMIN_PASS_HASH}';"

print_message "Admin user created successfully"

# Get server IP address
SERVER_IP=$(hostname -I | awk '{print $1}')

# Save credentials to file
CREDS_FILE="${SCRIPT_DIR}/installation_credentials.txt"
cat > ${CREDS_FILE} << EOF
=================================================
Secure FTP Web Application - Installation Complete
=================================================

Installation Date: $(date)

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
Application URL: http://${SERVER_IP}
                 http://localhost (if accessing locally)

IMPORTANT SECURITY NOTES:
------------------------
1. Keep this file secure and delete it after noting the credentials
2. Change the admin password after first login
3. Configure a firewall to restrict access
4. Consider setting up SSL/HTTPS for production use
5. Regularly backup the database and uploads directory

NEXT STEPS:
----------
1. Access the application at http://${SERVER_IP}
2. Login with admin credentials
3. Change default passwords
4. Configure SSL certificate (recommended)
5. Set up regular backups
6. Review SECURITY.md for additional hardening steps

For SSL setup with Let's Encrypt:
    sudo apt install certbot python3-certbot-nginx
    sudo certbot --nginx -d your-domain.com

=================================================
EOF

chmod 600 ${CREDS_FILE}

echo ""
echo "================================================================"
print_message "Installation completed successfully!"
echo "================================================================"
echo ""
print_message "Application is accessible at: http://${SERVER_IP}"
echo ""
print_warning "Important: Credentials saved to ${CREDS_FILE}"
print_warning "Please save these credentials securely and delete the file!"
echo ""
print_message "Admin Username: ${ADMIN_USER}"
print_message "Database Password saved to: ${CREDS_FILE}"
echo ""
print_message "Next steps:"
echo "  1. Access the application in your web browser"
echo "  2. Login with admin credentials"
echo "  3. Configure SSL certificate (recommended)"
echo "  4. Set up regular backups"
echo ""
print_message "For SSL setup, run:"
echo "  sudo apt install certbot python3-certbot-nginx"
echo "  sudo certbot --nginx -d your-domain.com"
echo ""
print_message "Thank you for using Secure FTP Web Application!"
echo "================================================================"
