# Installation Guide

This guide will walk you through the complete installation process for the Secure File Transfer Web Application.

## Prerequisites

Before beginning installation, ensure you have:

- A web server (Apache 2.4+ or Nginx 1.18+)
- PHP 7.4 or higher with the following extensions:
  - pdo
  - pdo_mysql
  - fileinfo
  - openssl
  - mbstring
- MySQL 5.7+ or MariaDB 10.3+
- Root or sudo access to the server
- Basic knowledge of command line operations

## Step-by-Step Installation

### 1. Prepare the Environment

#### Update System Packages
```bash
sudo apt update
sudo apt upgrade -y
```

#### Install Required Software (Ubuntu/Debian)
```bash
# Install Apache
sudo apt install apache2 -y

# Install PHP and required extensions
sudo apt install php php-mysql php-mbstring php-xml php-curl -y

# Install MySQL
sudo apt install mysql-server -y
```

#### For CentOS/RHEL:
```bash
sudo yum install httpd php php-mysqlnd php-mbstring php-xml -y
sudo yum install mariadb-server mariadb -y
```

### 2. Configure MySQL/MariaDB

#### Secure MySQL Installation
```bash
sudo mysql_secure_installation
```

Follow the prompts to:
- Set root password
- Remove anonymous users
- Disallow root login remotely
- Remove test database
- Reload privilege tables

#### Create Database
```bash
# Log in to MySQL
sudo mysql -u root -p

# Create database and user
CREATE DATABASE secure_ftp CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER 'secure_ftp_user'@'localhost' IDENTIFIED BY 'your_secure_password_here';
GRANT ALL PRIVILEGES ON secure_ftp.* TO 'secure_ftp_user'@'localhost';
FLUSH PRIVILEGES;
EXIT;
```

### 3. Deploy Application Files

#### Clone or Upload Files
```bash
cd /var/www/html
sudo git clone https://github.com/TwiStarSystems/Secure-FTP-WEB.git secure-ftp
cd secure-ftp
```

Or if uploading manually:
```bash
cd /var/www/html
sudo mkdir secure-ftp
# Upload files via FTP/SFTP to /var/www/html/secure-ftp/
```

### 4. Import Database Schema

```bash
mysql -u secure_ftp_user -p secure_ftp < database.sql
```

Enter the database user password when prompted.

### 5. Configure Application

#### Edit Configuration File
```bash
sudo nano config.php
```

Update the database settings:
```php
define('DB_HOST', 'localhost');
define('DB_NAME', 'secure_ftp');
define('DB_USER', 'secure_ftp_user');
define('DB_PASS', 'your_secure_password_here');
```

Save and exit (Ctrl+X, Y, Enter in nano).

### 6. Set File Permissions

```bash
# Create uploads directory
sudo mkdir -p uploads
sudo chmod 755 uploads

# Set ownership to web server user
sudo chown -R www-data:www-data /var/www/html/secure-ftp
# For CentOS/RHEL use: sudo chown -R apache:apache /var/www/html/secure-ftp

# Set appropriate permissions
sudo find /var/www/html/secure-ftp -type d -exec chmod 755 {} \;
sudo find /var/www/html/secure-ftp -type f -exec chmod 644 {} \;
sudo chmod 755 uploads
```

### 7. Configure PHP for Large Files

#### Edit PHP Configuration
```bash
sudo nano /etc/php/7.4/apache2/php.ini
# Or for Nginx: /etc/php/7.4/fpm/php.ini
```

Update these values:
```ini
upload_max_filesize = 10240M
post_max_size = 10240M
max_execution_time = 300
max_input_time = 300
memory_limit = 512M
```

Save and exit.

### 8. Configure Web Server

#### For Apache:

Create a virtual host configuration:
```bash
sudo nano /etc/apache2/sites-available/secure-ftp.conf
```

Add the following:
```apache
<VirtualHost *:80>
    ServerName your-domain.com
    DocumentRoot /var/www/html/secure-ftp
    
    <Directory /var/www/html/secure-ftp>
        Options -Indexes +FollowSymLinks
        AllowOverride All
        Require all granted
    </Directory>
    
    <Directory /var/www/html/secure-ftp/uploads>
        Options -Indexes -ExecCGI
        AllowOverride None
        Require all denied
    </Directory>
    
    ErrorLog ${APACHE_LOG_DIR}/secure-ftp-error.log
    CustomLog ${APACHE_LOG_DIR}/secure-ftp-access.log combined
</VirtualHost>
```

Enable the site and required modules:
```bash
sudo a2ensite secure-ftp
sudo a2enmod rewrite
sudo systemctl restart apache2
```

#### For Nginx:

Create a server block:
```bash
sudo nano /etc/nginx/sites-available/secure-ftp
```

Add the following:
```nginx
server {
    listen 80;
    server_name your-domain.com;
    root /var/www/html/secure-ftp;
    index index.php;
    
    client_max_body_size 10240M;
    
    location / {
        try_files $uri $uri/ /index.php?$query_string;
    }
    
    location ~ \.php$ {
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:/var/run/php/php7.4-fpm.sock;
        fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
        include fastcgi_params;
    }
    
    location /uploads/ {
        deny all;
        return 404;
    }
    
    location ~ /\. {
        deny all;
    }
}
```

Enable the site:
```bash
sudo ln -s /etc/nginx/sites-available/secure-ftp /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl restart nginx
sudo systemctl restart php7.4-fpm
```

### 9. Configure SSL (Recommended)

Using Let's Encrypt (free SSL certificate):

```bash
# Install Certbot
sudo apt install certbot python3-certbot-apache -y
# For Nginx: sudo apt install certbot python3-certbot-nginx -y

# Obtain and install certificate
sudo certbot --apache -d your-domain.com
# For Nginx: sudo certbot --nginx -d your-domain.com
```

Follow the prompts to complete SSL setup.

### 10. Configure Firewall

```bash
# Allow HTTP and HTTPS
sudo ufw allow 'Apache Full'
# For Nginx: sudo ufw allow 'Nginx Full'

# Enable firewall if not already enabled
sudo ufw enable
```

### 11. First Login and Security

1. Navigate to your domain: `https://your-domain.com/login.php`

2. Log in with default credentials:
   - Username: `admin`
   - Password: `admin123`

3. **IMMEDIATELY** change the admin password:
   - Go to Admin Panel
   - Click on the admin user
   - Update password
   - Or use MySQL:
   ```sql
   UPDATE users SET password_hash = '$2y$10$NEW_HASH_HERE' WHERE username = 'admin';
   ```

### 12. Testing

1. **Test file upload:**
   - Log in as admin
   - Try uploading a small file
   - Verify hash is generated
   - Download and verify integrity

2. **Test user creation:**
   - Create a test user
   - Log out and log in as test user
   - Verify quota is enforced

3. **Test access code:**
   - Generate an access code
   - Log out and use access code
   - Verify limited access

### 13. Ongoing Maintenance

#### Set Up Automated Backups

Create a backup script:
```bash
sudo nano /usr/local/bin/backup-secure-ftp.sh
```

Add:
```bash
#!/bin/bash
BACKUP_DIR="/var/backups/secure-ftp"
DATE=$(date +%Y%m%d_%H%M%S)
mkdir -p $BACKUP_DIR

# Backup database
mysqldump -u secure_ftp_user -p'your_password' secure_ftp | gzip > $BACKUP_DIR/db_$DATE.sql.gz

# Backup uploads
tar -czf $BACKUP_DIR/uploads_$DATE.tar.gz /var/www/html/secure-ftp/uploads/

# Remove backups older than 30 days
find $BACKUP_DIR -type f -mtime +30 -delete
```

Make executable and schedule:
```bash
sudo chmod +x /usr/local/bin/backup-secure-ftp.sh
sudo crontab -e
```

Add cron job (daily at 2 AM):
```
0 2 * * * /usr/local/bin/backup-secure-ftp.sh
```

#### Monitor Logs

```bash
# Apache logs
sudo tail -f /var/log/apache2/secure-ftp-error.log

# Nginx logs
sudo tail -f /var/log/nginx/error.log

# PHP logs
sudo tail -f /var/log/php7.4-fpm.log
```

## Troubleshooting

### Issue: Database connection failed
- Verify MySQL is running: `sudo systemctl status mysql`
- Check credentials in `config.php`
- Test connection: `mysql -u secure_ftp_user -p secure_ftp`

### Issue: File uploads fail
- Check PHP settings: `php -i | grep upload_max_filesize`
- Verify directory permissions: `ls -la uploads/`
- Check disk space: `df -h`

### Issue: 403 Forbidden errors
- Check file ownership: `ls -la /var/www/html/secure-ftp/`
- Verify Apache/Nginx configuration
- Check SELinux (CentOS): `sudo setenforce 0` (temporary)

### Issue: Rate limiting not working
- Check system time is correct: `date`
- Verify database table exists: `SHOW TABLES LIKE 'login_attempts';`

## Security Hardening

### Additional Recommendations

1. **Restrict database access:**
   ```sql
   REVOKE ALL PRIVILEGES ON secure_ftp.* FROM 'secure_ftp_user'@'%';
   GRANT SELECT, INSERT, UPDATE, DELETE ON secure_ftp.* TO 'secure_ftp_user'@'localhost';
   ```

2. **Enable PHP security features:**
   ```ini
   expose_php = Off
   display_errors = Off
   log_errors = On
   ```

3. **Install fail2ban for additional protection:**
   ```bash
   sudo apt install fail2ban
   ```

4. **Regular updates:**
   ```bash
   sudo apt update && sudo apt upgrade -y
   ```

## Support

If you encounter issues:
1. Check the troubleshooting section above
2. Review log files for error messages
3. Consult the main README.md
4. Open an issue on GitHub with details

## Complete!

Your Secure File Transfer system is now installed and ready to use!
