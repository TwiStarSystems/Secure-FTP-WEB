# Secure File Transfer Web Application

A secure, web-based file transfer system built with PHP that provides enterprise-grade file sharing capabilities with comprehensive security features.

## Features

### 🎨 Modern User Interface
- **Professional Design**: Custom-branded TwiStar Systems color scheme
- **Responsive Layout**: Works seamlessly on desktop, tablet, and mobile devices
- **Dark Theme**: Easy on the eyes with a modern dark interface
- **Smooth Animations**: Polished user experience with subtle transitions

### 🔐 Authentication & Access Control
- **Admin Login**: Full administrative control with user management capabilities
- **User Management**: Create regular and temporary users with auto-deletion on expiry dates
- **Access Codes**: Generate temporary access codes with limited login counts and expiry dates
- **CSRF Protection**: Built-in Cross-Site Request Forgery protection for all forms

### 📊 Quota Management
- **Per-User Quotas**: Set individual upload quotas for each user
- **Access Code Quotas**: Configure quotas for access code-based uploads
- **Real-time Tracking**: Monitor quota usage in real-time
- **Large File Support**: Handle files up to 10 GB

### 🔒 Security Features
- **File Integrity**: SHA hashing (SHA-1, SHA-256, SHA-512) for file integrity verification
- **Rate Limiting**: Anti-brute force protection with configurable lockout duration
- **Session Management**: Automatic session timeouts for security
- **Password Hashing**: Industry-standard bcrypt password hashing
- **Input Validation**: Comprehensive input validation and sanitization

### 📁 File Management
- **Secure Upload**: Upload files with automatic hash generation
- **Download Tracking**: Monitor file download counts
- **File Deletion**: Users can delete their own files; admins can delete any file
- **Quota Enforcement**: Automatic quota checking before uploads

## Installation

### Requirements
- **Operating System**: Debian 10+ or Ubuntu 20.04+ (primary support)
- **Web Server**: Nginx 1.18+ (configured automatically by installer)
- **PHP**: 7.4 or higher with extensions: PDO, PDO_MySQL, fileinfo, openssl, mbstring, curl, gd, zip
- **Database**: MariaDB 10.3+ or MySQL 5.7+
- **Server**: Root/sudo access required for installation

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
   - Setting up SSL/HTTPS (optional)
   - Database configuration
   - Creating an admin account
   
4. **Access your application**
   
   After installation completes, you'll receive:
   - Your application URL
   - Admin login credentials
   - Database credentials (saved to `installation_credentials.txt`)

### What the Installer Does

The automated installer will:
- ✅ Install and configure Nginx web server
- ✅ Install PHP-FPM with all required extensions
- ✅ Install and configure MariaDB database
- ✅ Create and configure the database
- ✅ Deploy application files
- ✅ Set proper file permissions
- ✅ Configure PHP for large file uploads (10GB)
- ✅ Create your admin user account
- ✅ Optionally set up SSL with Let's Encrypt

**Installation time**: ~5-10 minutes (depending on server speed and options selected)

### Manual Installation

For manual installation or other operating systems, see the detailed instructions in [INSTALL.md](INSTALL.md).

## Usage

### Admin Panel
1. Log in with admin credentials
2. Access the Admin Panel from the dashboard
3. Create users or access codes
4. Manage quotas and permissions
5. Monitor user activity

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
├── admin.php           # Admin panel interface
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
1. **Configure SSL/HTTPS** (if not done during installation)
   ```bash
   sudo apt install certbot python3-certbot-nginx
   sudo certbot --nginx -d your-domain.com
   ```

2. **Set up firewall**
   ```bash
   sudo ufw allow 22/tcp    # SSH
   sudo ufw allow 80/tcp    # HTTP
   sudo ufw allow 443/tcp   # HTTPS
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

## License

MIT License - see LICENSE file for details

## Security Disclosure

If you discover a security vulnerability, please email security@twistarsystems.com instead of using the issue tracker.

## Support

For issues and questions:
- GitHub Issues: https://github.com/TwiStarSystems/Secure-FTP-WEB/issues
- Documentation: See INSTALL.md for detailed setup instructions

## Credits

Developed by TwiStar Systems
