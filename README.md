# Secure File Transfer Web Application

A secure, web-based file transfer system built with PHP that provides enterprise-grade file sharing capabilities with comprehensive security features.

## Features

### 🎨 Modern User Interface
- **Professional Design**: Custom-branded TwiStar Systems color scheme
- **Responsive Layout**: Works seamlessly on desktop, tablet, and mobile devices
- **Dark Theme**: Easy on the eyes with a modern dark interface
- **Smooth Animations**: Polished user experience with subtle transitions

### 🔐 Authentication & Access Control
- **Role-Based Access Control (RBAC)**: Comprehensive permission system with three user roles:
  - **Admin**: Full control over all files, users, and system settings
  - **User**: Authenticated users can manage their own files and create share links
  - **Anonymous**: Non-authenticated visitors can only view publicly shared files
- **Admin Login**: Full administrative control with user management capabilities
- **User Management**: Create regular and temporary users with auto-deletion on expiry dates
- **Access Codes**: Generate temporary access codes with limited login counts and expiry dates
- **SMTP Email Settings**: Configure SMTP (TLS/SSL/STARTTLS) from Settings with built-in test email support
- **Multi-Factor Authentication (MFA)**: Per-user enable/disable for TOTP app codes and Email verification codes
- **Tabbed Settings Interface**: User Settings, User Management, Site Settings, and Security Events sections
- **Security Events Viewer**: Admin-accessible audit view for abuse lockouts and suspicious activity
- **Security Events Filtering**: Filter by severity, event type, date range, and free-text search
- **Security Events CSV Export**: Export filtered security events directly from Settings
- **CSRF Protection**: Built-in Cross-Site Request Forgery protection for all forms

### 🔗 File Sharing
- **Public Share Links**: Create shareable links for files accessible to anyone
- **Password Protection**: Optionally password-protect shared files
- **Expiry Dates**: Set automatic expiration for share links
- **Download Limits**: Limit the number of downloads per share link
- **Share Management**: Track and manage all your shared links in one place
- **Public Files Page**: Anonymous users see a curated list of publicly shared files

### 📊 Quota Management
- **Per-User Quotas**: Set individual upload quotas for each user
- **Access Code Quotas**: Configure quotas for access code-based uploads
- **Real-time Tracking**: Monitor quota usage in real-time
- **Large File Support**: Handle files up to 10 GB

### 🔒 Security Features
- **File Integrity**: SHA hashing (SHA-1, SHA-256, SHA-512) for file integrity verification
- **Rate Limiting**: Anti-brute force protection with configurable lockout duration
- **Download Abuse Protection**: Request throttling + lockouts for repeated invalid/forbidden download attempts
- **Share Token Abuse Protection**: Token/password brute-force lockouts with suspicious activity auditing
- **Session Management**: Automatic session timeouts for security
- **Password Hashing**: Industry-standard bcrypt password hashing
- **Input Validation**: Comprehensive input validation and sanitization

### 📁 File Management
- **Secure Upload**: Upload files with automatic hash generation
- **Download Tracking**: Monitor file download counts
- **File Deletion**: Users can delete their own files; admins can delete any file
- **Quota Enforcement**: Automatic quota checking before uploads

## Installation

### Software Requirements

#### Operating System
- **Debian**: 10 (Buster) or higher
- **Ubuntu**: 20.04 LTS or higher
- **Other Linux**: May work but not officially supported

#### Web Server
- **Nginx**: 1.18+ (automatically installed and configured)
- Support for large file uploads (10GB+)
- FastCGI processing capability

#### PHP Requirements
- **Version**: PHP 7.4 or higher (PHP 8.0+ recommended)
- **Required Extensions**:
  - `php-fpm` - FastCGI Process Manager
  - `php-mysql` or `php-pdo` - Database connectivity
  - `php-mbstring` - Multi-byte string handling
  - `php-xml` - XML processing
  - `php-curl` - HTTP requests
  - `php-gd` - Image processing
  - `php-zip` - ZIP file handling
  - `php-fileinfo` - File type detection
  - `php-openssl` - Encryption and hashing

#### Database
- **MariaDB**: 10.3 or higher (recommended)
- **MySQL**: 5.7 or higher
- Minimum 100MB storage (scales with uploaded files database)

#### Server Resources
- **Memory**: Minimum 512MB RAM (1GB+ recommended)
- **Storage**: Minimum 1GB free space (scales with file uploads)
- **Permissions**: Root or sudo access required for installation

#### Network
- Port 80 (HTTP) accessible
- Domain name (optional)
- Static IP or DDNS if self-hosting
- Reverse proxy recommended if exposing publicly (see REVERSE-PROXY-README.md)

### Quick Installation (Recommended)

The easiest way to install is using the automated installation wizard:

1. **Clone the repository**
   ```bash
   git clone https://github.com/TwiStarSystems/Secure-FTP-WEB.git
   cd Secure-FTP-WEB
   ```

2. **Run the installation wizard**
   ```bash
   sudo ./install.sh
   ```

3. **Follow the interactive prompts**
   
   The installer will guide you through:
   - Choosing the installation directory
   - Configuring your domain name
   - Database configuration
   - Creating an admin account
   
4. **Access your application**
   
   After installation completes, you'll receive:
   - Your application URL
   - Admin login credentials
   - Database credentials (saved to `installation_credentials.txt`)

### What the Installer Does

The automated installer (`install.sh`) performs a complete system setup:

#### 1. System Preparation
- ✅ Checks for root/sudo privileges
- ✅ Validates OS compatibility (Debian/Ubuntu)
- ✅ Updates system package repositories
- ✅ Installs system dependencies

#### 2. Web Server Setup
- ✅ Installs Nginx web server (latest stable version)
- ✅ Configures virtual host for the application
- ✅ Sets up FastCGI parameters for PHP
- ✅ Configures large file upload support (10GB limit)
- ✅ Enables gzip compression for better performance
- ✅ Ready for reverse proxy deployment (see REVERSE-PROXY-README.md)

#### 3. PHP Installation & Configuration
- ✅ Installs PHP-FPM with all required extensions
- ✅ Configures PHP settings for large file uploads:
  - `upload_max_filesize = 10G`
  - `post_max_size = 10G`
  - `max_execution_time = 3600`
  - `memory_limit = 512M`
- ✅ Optimizes PHP-FPM pool settings
- ✅ Enables necessary PHP extensions

#### 4. Database Setup
- ✅ Installs MariaDB/MySQL database server
- ✅ Secures database installation
- ✅ Creates dedicated database and user
- ✅ Imports database schema from `database.sql`
- ✅ Sets proper privileges and permissions
- ✅ Tests database connectivity

#### 5. Application Deployment
- ✅ Copies application files to installation directory
- ✅ Creates uploads directory with secure permissions
- ✅ Generates and configures `config.php` with your settings
- ✅ Sets ownership to `www-data` user
- ✅ Applies secure file permissions (644 for files, 755 for directories)
- ✅ Protects uploads directory from direct web access

#### 6. Admin Account Creation
- ✅ Prompts for admin username and password
- ✅ Hashes password with bcrypt
- ✅ Creates initial admin user in database
- ✅ Assigns admin role and permissions

#### 7. Final Configuration
- ✅ Restarts Nginx and PHP-FPM services
- ✅ Validates all services are running
- ✅ Tests application accessibility
- ✅ Generates installation credentials file
- ✅ Displays access URL and credentials

#### Installer Modes
The installer supports three modes:

- **Fresh Install**: `./install.sh` or `./install.sh --fresh`
   - Performs a full clean installation
- **Update**: `./install.sh --update`
   - Updates application files
   - Preserves uploads and configuration
   - Runs safe, idempotent database migrations for new tables/settings
- **Uninstall**: `./install.sh --uninstall`
   - Removes application files and Nginx site configuration
   - Optionally removes database and database user (with extra confirmation)

**Installation time**: ~5-10 minutes (depending on server speed and options selected)

### Manual Installation

For manual installation or other operating systems, see the detailed instructions in [INSTALL.md](INSTALL.md).

## Usage

### Admin Panel
1. Log in with admin credentials
2. Access the Admin Panel from the dashboard
3. Create users or access codes
4. Configure application and SMTP email settings
5. Monitor user activity

### Multi-Factor Authentication (MFA)
1. Go to **Settings** while logged in with a user account
2. In **MFA Settings**, enable either or both methods:
   - **TOTP Authenticator** (6-digit app codes)
   - **Email Codes** (6-digit codes sent by SMTP)
3. During login, choose any enabled method to complete authentication

### Creating Temporary Users
1. In Admin Panel, check "Temporary User"
2. Set an expiry date
3. User will be automatically deleted after expiry

### Generating Access Codes
1. In Admin Panel, use "Create Access Code" form
2. Set maximum uses and quota
3. Share the generated code with users
4. Users can log in using the access code

### Uploading Files
1. Log in to the dashboard
2. Select a file (up to 10 GB)
3. Choose a hash algorithm (SHA-256 recommended)
4. Click "Upload File"
5. Save the file hash for integrity verification

### Downloading Files
1. View your files in the dashboard
2. Click "Download" next to the file
3. Verify file integrity using the displayed hash

### Sharing Files
1. Upload a file to your dashboard
2. Click "Share" next to the file for a quick public share link
3. Or go to "My Shares" for advanced options:
   - Set password protection
   - Set expiry date
   - Limit download count
   - Choose public/private visibility
4. Copy and share the generated link

### User Roles & Permissions

| Feature | Admin | User | Anonymous |
|---------|-------|------|-----------|
| View public files | ✓ | ✓ | ✓ |
| Download shared files | ✓ | ✓ | ✓ |
| Upload files | ✓ | ✓ | ✗ |
| Manage own files | ✓ | ✓ | ✗ |
| Create share links | ✓ | ✓ | ✗ |
| View all files | ✓ | ✗ | ✗ |
| Manage all files | ✓ | ✗ | ✗ |
| Manage users | ✓ | ✗ | ✗ |
| Access admin panel | ✓ | ✗ | ✗ |

## Security Features

### Rate Limiting
- Maximum 5 failed login attempts
- 15-minute lockout after exceeding attempts
- Applies to both username and IP address

### Session Security
- Sessions expire after 1 hour of inactivity
- CSRF tokens protect all forms
- Secure session configuration

### File Security
- Files stored with unique names
- Original filenames preserved in database
- Upload directory protected from direct access

### Password Security
- Bcrypt hashing with cost factor 10
- No password recovery (admin must reset)
- Minimum requirements recommended

## Configuration Options

Edit `config.php` to customize:

```php
// Maximum file size (10 GB default)
define('MAX_FILE_SIZE', 10737418240);

// Session timeout (1 hour default)
define('SESSION_TIMEOUT', 3600);

// Rate limiting
define('MAX_LOGIN_ATTEMPTS', 5);
define('LOCKOUT_DURATION', 900);

// Available hash algorithms
define('HASH_ALGORITHMS', ['sha256', 'sha512', 'sha1']);
define('DEFAULT_HASH_ALGORITHM', 'sha256');
```

## File Structure

```
Secure-FTP-WEB/
├── settings.php        # Settings panel (user & admin)
├── auth.php            # Authentication and rate limiting
├── config.php          # Configuration settings
├── database.sql        # Database schema
├── db.php              # Database connection and helpers
├── download.php        # File download handler
├── files.php           # File management functions
├── index.php           # Main dashboard
├── login.php           # Login handler
├── login_form.php      # Login form template
├── users.php           # User management functions
├── uploads/            # Uploaded files directory
├── install.sh          # Automated installation script
├── secure-ftp.conf     # Nginx configuration file
├── INSTALL.md          # Detailed installation guide
├── SECURITY.md         # Security guidelines
└── README.md           # This file
```

## Post-Installation

### First Login
1. Navigate to your application URL (provided at the end of installation)
2. Login with the admin credentials you created during installation
3. **Important**: Consider changing your admin password in the admin panel

### Recommended Next Steps
1. **Set up a reverse proxy** if exposing publicly (see `REVERSE-PROXY-README.md`)
   - The app is HTTP-only; SSL/TLS should be terminated at the reverse proxy

2. **Set up firewall**
   ```bash
   sudo ufw allow 22/tcp    # SSH
   sudo ufw allow 80/tcp    # HTTP
   sudo ufw enable
   ```

3. **Configure regular backups**
   ```bash
   # Backup database
   mysqldump -u secure_ftp_user -p secure_ftp > backup.sql
   
   # Backup uploads directory
   tar -czf uploads_backup.tar.gz /var/www/html/secure-ftp/uploads
   ```

4. **Review security settings** in `SECURITY.md`

## Proprietary Notice

This repository contains proprietary software owned by TwiStarSystems. All rights are reserved.

**Access and usage are strictly restricted.** Unauthorized copying, modification, distribution, or commercial use is prohibited.

Please refer to the [LICENSE](LICENSE) file for complete terms and conditions.

For licensing inquiries, contact: legal@twistarsystems.com

## Security Disclosure

If you discover a security vulnerability, please email security@twistarsystems.com instead of using the issue tracker.

## Support

For issues and questions:
- GitHub Issues: https://github.com/TwiStarSystems/Secure-FTP-WEB/issues
- Documentation: See INSTALL.md for detailed setup instructions

## Credits

Developed by TwiStar Systems
