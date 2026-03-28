# Reverse Proxy Setup - Quick Reference

This application is fully compatible with Nginx reverse proxy deployments.

## What Was Added

### 1. Proxy-Aware Helper Functions (`config.php`)
- `getProtocol()` - Detects HTTP/HTTPS from proxy headers
- `getHost()` - Gets correct hostname from proxy headers
- `getBaseUrl()` - Generates correct URLs behind proxy

### 2. Updated Share URL Generation (`share.php`)
- Share links now use `getBaseUrl()` to generate correct URLs
- Works correctly whether behind proxy or direct access

### 3. Dynamic Session Security
- Session cookies automatically set `secure` flag when behind an HTTPS-terminating reverse proxy
- Respects `X-Forwarded-Proto` and `X-Forwarded-SSL` headers

## Files

- **nginx-reverse-proxy.conf.example** - Complete Nginx reverse proxy configuration
- **docs/REVERSE-PROXY.md** - Comprehensive setup and troubleshooting guide

## Quick Start

1. **Deploy your backend server** with the standard `secure-ftp.conf` configuration

2. **Set up reverse proxy server**:
   ```bash
   cp nginx-reverse-proxy.conf.example /etc/nginx/sites-available/secure-ftp-proxy.conf
   ```

3. **Edit the configuration**:
   - Update `server_name` with your domain
   - Update `upstream` with your backend server IP
   - Configure SSL certificates

4. **Enable and test**:
   ```bash
   sudo ln -s /etc/nginx/sites-available/secure-ftp-proxy.conf /etc/nginx/sites-enabled/
   sudo nginx -t
   sudo systemctl reload nginx
   ```

## Key Features

✅ Automatic protocol detection (HTTP/HTTPS)  
✅ Correct share URL generation  
✅ Session cookie security  
✅ Support for X-Forwarded-* headers  
✅ Large file upload support (10GB)  
✅ SSL/TLS termination  
✅ Load balancing ready  

## Important Proxy Headers

The reverse proxy **must** set these headers:

```nginx
proxy_set_header Host $host;
proxy_set_header X-Forwarded-Proto $scheme;
proxy_set_header X-Forwarded-Host $host;
proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
```

## Documentation

For complete setup instructions, configuration options, and troubleshooting:

📖 **See [docs/REVERSE-PROXY.md](docs/REVERSE-PROXY.md)**

## Testing

After setup, verify:

1. ✅ Login works correctly
2. ✅ Files can be uploaded
3. ✅ Share links use correct domain (not internal IP)
4. ✅ Share links are accessible
5. ✅ Sessions persist correctly

## No Changes Required to Existing Setup

The application automatically detects when it's behind a proxy. Your existing `secure-ftp.conf` file does not need to be modified.
