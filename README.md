# Secure File Transfer Web Application

A secure, web-based file transfer system built with PHP that provides enterprise-grade file sharing capabilities with comprehensive security features.

## Features

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
- PHP 7.4 or higher
- MySQL 5.7 or higher
- Apache/Nginx web server
- PHP extensions: PDO, PDO_MySQL, fileinfo, openssl

### Quick Start

1. **Clone the repository**
   ```bash
   git clone https://github.com/TwiStarSystems/Secure-FTP-WEB.git
   cd Secure-FTP-WEB
   ```

2. **Configure the database**
   - Create a MySQL database named `secure_ftp`
   - Import the database schema:
     ```bash
     mysql -u root -p secure_ftp < database.sql
     ```

3. **Configure the application**
   - Edit `config.php` and update the database credentials:
     ```php
     define('DB_HOST', 'localhost');
     define('DB_NAME', 'secure_ftp');
     define('DB_USER', 'your_username');
     define('DB_PASS', 'your_password');
     ```

4. **Set up file permissions**
   ```bash
   chmod 755 uploads
   chown www-data:www-data uploads  # For Apache on Ubuntu/Debian
   ```

5. **Configure PHP settings**
   - Edit your `php.ini` file to support large file uploads:
     ```ini
     upload_max_filesize = 10240M
     post_max_size = 10240M
     max_execution_time = 300
     max_input_time = 300
     memory_limit = 512M
     ```

6. **Access the application**
   - Navigate to `http://your-domain.com/login.php`
   - Default admin credentials:
     - Username: `admin`
     - Password: `admin123`
   - **⚠️ IMPORTANT**: Change the admin password immediately after first login!

For detailed installation instructions, see [INSTALL.md](INSTALL.md).

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
├── INSTALL.md          # Detailed installation guide
└── README.md           # This file
```

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
