# Reverse Proxy Configuration Guide

This guide explains how to deploy the Secure FTP Web Application behind an Nginx reverse proxy.

## Table of Contents
- [Overview](#overview)
- [Architecture](#architecture)
- [Prerequisites](#prerequisites)
- [Quick Start](#quick-start)
- [Detailed Setup](#detailed-setup)
- [Configuration Options](#configuration-options)
- [Testing](#testing)
- [Troubleshooting](#troubleshooting)
- [Security Considerations](#security-considerations)

## Overview

The Secure FTP Web Application can be deployed behind an Nginx reverse proxy for:
- **SSL/TLS Termination**: Handle HTTPS encryption at the proxy level
- **Load Balancing**: Distribute traffic across multiple backend servers
- **Security**: Additional layer of protection and access control
- **Centralized Management**: Manage multiple applications through one proxy
- **Caching**: Cache static assets to improve performance

The application has been designed to work seamlessly behind a reverse proxy by properly handling proxy headers.

## Architecture

```
Internet → Reverse Proxy (Port 443) → Backend App (Port 80/8080)
           Nginx Server                 Nginx + PHP-FPM
           (Public IP)                  (Internal/Private IP)
```

## Prerequisites

### On the Reverse Proxy Server:
- Nginx installed
- Valid SSL certificates (Let's Encrypt recommended)
- Open ports: 80 (HTTP) and 443 (HTTPS)

### On the Backend Application Server:
- Secure FTP Web Application installed and running
- Nginx configured using `secure-ftp.conf`
- PHP-FPM running
- Accessible from the reverse proxy server

## Quick Start

### Step 1: Configure Backend Server

On your backend server (where the app is installed), ensure the application is running:

```bash
# Check Nginx is running
sudo systemctl status nginx

# Check PHP-FPM is running
sudo systemctl status php8.1-fpm  # Adjust version as needed

# Verify app is accessible locally
curl -I http://localhost
```

**Note**: You can configure the backend to listen on a specific port (e.g., 8080) or keep it on port 80. Just ensure the reverse proxy configuration matches.

### Step 2: Set Up Reverse Proxy Server

1. **Copy the example configuration**:
   ```bash
   sudo cp nginx-reverse-proxy.conf.example /etc/nginx/sites-available/secure-ftp-proxy.conf
   ```

2. **Edit the configuration**:
   ```bash
   sudo nano /etc/nginx/sites-available/secure-ftp-proxy.conf
   ```

3. **Update these key values**:
   - `server_name`: Your domain name (e.g., `secure-ftp.example.com`)
   - `upstream secure_ftp_backend`: Backend server IP and port (e.g., `192.168.1.100:80`)
   - SSL certificate paths

4. **Enable the site**:
   ```bash
   sudo ln -s /etc/nginx/sites-available/secure-ftp-proxy.conf /etc/nginx/sites-enabled/
   ```

5. **Test and reload**:
   ```bash
   sudo nginx -t
   sudo systemctl reload nginx
   ```

### Step 3: Configure SSL Certificates

Using Let's Encrypt (recommended):
```bash
sudo apt install certbot python3-certbot-nginx
sudo certbot --nginx -d secure-ftp.example.com
```

Or manually configure your certificates in the configuration file.

## Detailed Setup

### Backend Server Configuration

1. **Verify Application Settings**:
   The application now includes proxy-aware functions in `config.php` that automatically detect:
   - Protocol (HTTP/HTTPS) via `X-Forwarded-Proto` header
   - Host via `X-Forwarded-Host` header
   - Proper URL generation for share links

2. **No Changes Required**:
   The existing `secure-ftp.conf` file should work as-is. The application will automatically adapt when it detects it's behind a proxy.

3. **Optional - Change Backend Port**:
   If you want the backend to listen on a different port:
   ```nginx
   # In secure-ftp.conf
   server {
       listen 8080;  # Change from 80 to 8080
       # ... rest of configuration
   }
   ```

### Reverse Proxy Server Configuration

1. **Upstream Configuration**:
   ```nginx
   upstream secure_ftp_backend {
       server 192.168.1.100:80;  # Backend server IP:PORT
       keepalive 32;
       keepalive_timeout 300s;
   }
   ```

2. **Essential Proxy Headers**:
   These headers are critical for the application to work correctly:
   ```nginx
   proxy_set_header Host $host;
   proxy_set_header X-Real-IP $remote_addr;
   proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
   proxy_set_header X-Forwarded-Proto $scheme;
   proxy_set_header X-Forwarded-Host $host;
   proxy_set_header X-Forwarded-Port $server_port;
   ```

3. **Upload Configuration**:
   ```nginx
   client_max_body_size 10G;  # Must match application MAX_FILE_SIZE
   proxy_request_buffering off;
   proxy_buffering off;
   ```

## Configuration Options

### Load Balancing

To distribute load across multiple backend servers:

```nginx
upstream secure_ftp_backend {
    least_conn;  # Use least connections algorithm
    
    server 192.168.1.100:80 weight=1;
    server 192.168.1.101:80 weight=1;
    server 192.168.1.102:80 backup;  # Backup server
    
    keepalive 32;
}
```

### Rate Limiting

Add rate limiting to protect against abuse:

```nginx
# Add to http block
limit_req_zone $binary_remote_addr zone=login:10m rate=5r/m;
limit_req_zone $binary_remote_addr zone=general:10m rate=100r/s;

# In server block
location /login.php {
    limit_req zone=login burst=10 nodelay;
    proxy_pass http://secure_ftp_backend;
    # ... other proxy settings
}

location / {
    limit_req zone=general burst=200 nodelay;
    proxy_pass http://secure_ftp_backend;
    # ... other proxy settings
}
```

### IP Whitelisting

Restrict access to specific IP ranges:

```nginx
server {
    # ... SSL configuration
    
    # Allow specific IPs or networks
    allow 203.0.113.0/24;    # Office network
    allow 198.51.100.50;     # Specific admin IP
    deny all;                 # Deny everyone else
    
    # ... rest of configuration
}
```

### Caching Static Assets

Enable caching for better performance:

```nginx
# Add to http block
proxy_cache_path /var/cache/nginx/secure-ftp levels=1:2 keys_zone=secure_ftp_cache:10m max_size=1g inactive=60m;

# In server block
location ~* \.(css|js|jpg|jpeg|png|gif|ico|svg|woff|woff2|ttf|eot)$ {
    proxy_cache secure_ftp_cache;
    proxy_cache_valid 200 7d;
    proxy_cache_use_stale error timeout http_500 http_502 http_503 http_504;
    
    proxy_pass http://secure_ftp_backend;
    # ... other proxy settings
}
```

## Testing

### 1. Test Backend Connectivity

From the reverse proxy server:
```bash
# Test HTTP connection
curl -I http://192.168.1.100:80

# Should return 200 OK or redirect
```

### 2. Test Proxy Configuration

```bash
# Test Nginx configuration syntax
sudo nginx -t

# Should return "syntax is ok" and "test is successful"
```

### 3. Test SSL/HTTPS

```bash
# Test SSL certificate
openssl s_client -connect secure-ftp.example.com:443 -servername secure-ftp.example.com

# Check SSL grade
curl https://www.ssllabs.com/ssltest/analyze.html?d=secure-ftp.example.com
```

### 4. Test Application Functionality

1. **Login Test**:
   - Visit `https://secure-ftp.example.com`
   - Log in with valid credentials
   - Verify you can access the dashboard

2. **Upload Test**:
   - Upload a file
   - Verify the file appears in your files list

3. **Share Link Test**:
   - Create a share link for a file
   - Copy the generated URL
   - Verify the URL uses the correct domain (not internal IP)
   - Open the share link in incognito/private browsing
   - Verify you can download the file

4. **Large File Test**:
   - Upload a large file (several GB)
   - Monitor for timeout issues
   - Verify successful upload

### 5. Test Proxy Headers

Create a test PHP file on the backend:
```php
<?php
// test-headers.php
echo "Protocol: " . getProtocol() . "\n";
echo "Host: " . getHost() . "\n";
echo "Base URL: " . getBaseUrl() . "\n";
echo "\nAll Headers:\n";
print_r(getallheaders());
?>
```

Access via proxy:
```bash
curl https://secure-ftp.example.com/test-headers.php
```

Verify output shows correct external domain and HTTPS.

## Troubleshooting

### Share Links Show Internal IP/Wrong Domain

**Problem**: Share links generated show `http://192.168.1.100` instead of `https://secure-ftp.example.com`

**Solution**: 
- Verify proxy headers are set correctly in Nginx configuration
- Check that `X-Forwarded-Proto` and `X-Forwarded-Host` headers are present
- The application's `getBaseUrl()` function should automatically detect these

**Debug**:
```bash
# On backend server, check PHP sees the headers
tail -f /var/log/nginx/secure-ftp-error.log

# Add debug output to share.php temporarily:
error_log("Protocol: " . getProtocol());
error_log("Host: " . getHost());
error_log("Headers: " . print_r(getallheaders(), true));
```

### 502 Bad Gateway Error

**Problem**: Nginx returns 502 Bad Gateway

**Solutions**:
1. **Backend not running**:
   ```bash
   sudo systemctl status nginx
   sudo systemctl status php8.1-fpm
   ```

2. **Wrong backend IP/port**:
   - Verify upstream configuration points to correct server
   - Test connectivity: `curl http://192.168.1.100:80`

3. **Firewall blocking connection**:
   ```bash
   # On backend server, allow connections from proxy
   sudo ufw allow from 192.168.1.50 to any port 80
   ```

4. **PHP-FPM socket issues**:
   ```bash
   # Check PHP-FPM is listening
   sudo netstat -tlnp | grep php-fpm
   ```

### File Upload Fails

**Problem**: Large files fail to upload or timeout

**Solutions**:
1. **Check client_max_body_size** on both proxy and backend
2. **Increase timeouts**:
   ```nginx
   client_body_timeout 600s;
   proxy_connect_timeout 600s;
   proxy_send_timeout 600s;
   proxy_read_timeout 600s;
   ```
3. **Check disk space** on backend server
4. **Verify PHP settings** in php.ini:
   ```ini
   upload_max_filesize = 10G
   post_max_size = 10G
   max_execution_time = 300
   max_input_time = 300
   ```

### SSL Certificate Issues

**Problem**: SSL certificate warnings or errors

**Solutions**:
1. **Verify certificate paths** in Nginx configuration
2. **Check certificate validity**:
   ```bash
   sudo certbot certificates
   ```
3. **Renew Let's Encrypt certificates**:
   ```bash
   sudo certbot renew
   ```
4. **Test SSL configuration**:
   ```bash
   openssl s_client -connect secure-ftp.example.com:443
   ```

### Sessions Not Persisting

**Problem**: Users get logged out frequently

**Solutions**:
1. **Check cookie_secure setting** in config.php:
   ```php
   ini_set('session.cookie_secure', 1);  // Set to 1 for HTTPS
   ```
2. **Verify session storage** permissions
3. **Check session timeout** settings

## Security Considerations

### 1. Network Isolation

- **Best Practice**: Keep backend server on a private network
- Only expose reverse proxy to the internet
- Use firewall rules to restrict backend access to proxy only

```bash
# On backend server
sudo ufw default deny incoming
sudo ufw allow from 192.168.1.50 to any port 80  # Proxy IP only
sudo ufw enable
```

### 2. SSL/TLS Configuration

- Use strong ciphers (see example configuration)
- Enable HSTS (HTTP Strict Transport Security)
- Keep certificates up to date
- Use TLS 1.2 and 1.3 only

### 3. Rate Limiting

Implement rate limiting to prevent:
- Brute force login attempts
- DDoS attacks
- Resource exhaustion

### 4. Access Control

Consider implementing:
- IP whitelisting for admin areas
- Geographic restrictions (if applicable)
- VPN requirement for admin access

### 5. Monitoring and Logging

- Monitor both proxy and backend logs
- Set up alerts for unusual activity
- Regular log rotation
- Consider using fail2ban for automated blocking

```bash
# Monitor proxy logs
tail -f /var/log/nginx/secure-ftp-proxy-access.log

# Monitor backend logs
tail -f /var/log/nginx/secure-ftp-access.log
```

### 6. Regular Updates

Keep all components updated:
```bash
# Update system packages
sudo apt update && sudo apt upgrade

# Renew SSL certificates
sudo certbot renew

# Check for Nginx updates
sudo apt list --upgradable | grep nginx
```

## Advanced Configurations

### Multiple Backend Servers with Session Persistence

For load balancing with session persistence:

```nginx
upstream secure_ftp_backend {
    ip_hash;  # Ensures same IP goes to same backend
    
    server 192.168.1.100:80;
    server 192.168.1.101:80;
}
```

Or use shared session storage (Redis/Memcached) on backend servers.

### WebSocket Support

If you add real-time features in the future:

```nginx
location /ws/ {
    proxy_pass http://secure_ftp_backend;
    proxy_http_version 1.1;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade";
    proxy_set_header Host $host;
    proxy_read_timeout 86400;
}
```

### Custom Error Pages

Create custom error pages on the proxy:

```nginx
error_page 502 503 504 /50x.html;
location = /50x.html {
    root /var/www/error-pages;
}
```

## Getting Help

If you encounter issues not covered in this guide:

1. Check Nginx error logs on both servers
2. Verify PHP error logs on backend
3. Review the application logs
4. Ensure all prerequisites are met
5. Test each component individually before testing the complete setup

For application-specific issues, refer to the main [README.md](README.md) and [SECURITY.md](docs/SECURITY.md) documentation.
