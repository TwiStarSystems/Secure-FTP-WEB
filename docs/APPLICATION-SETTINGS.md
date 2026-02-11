# Application Settings Configuration Guide

## Overview

The Settings page includes an Application Settings section where administrators can configure global application settings, including a custom base URL for link generation.

## Accessing Settings

1. Log in as an administrator
2. Click the **⚙️ Settings** button in the header
3. The first section shows **Application Settings**

## Base URL Configuration

### What is the Base URL?

The base URL is used throughout the application for:
- **Share link generation** - When users create share links for files
- **Email notifications** - If you add email functionality in the future
- **API endpoints** - Any future API or webhook URLs
- **Redirects and navigation** - Internal application links

### Configuration Options

#### Option 1: Auto-Detection (Recommended for Reverse Proxy)

**When to use:** When your application is behind a properly configured reverse proxy with X-Forwarded-* headers.

**How to configure:**
- Leave the "Base URL" field **empty**
- The application will automatically detect the protocol and host from HTTP headers
- This respects `X-Forwarded-Proto` and `X-Forwarded-Host` headers

**Benefits:**
- Works seamlessly with reverse proxies
- No manual configuration needed
- Automatically adapts to different environments

#### Option 2: Custom Base URL

**When to use:**
- Direct deployment without reverse proxy
- When you need a specific URL regardless of how users access the site
- Multiple domains pointing to the same installation but you want consistent links
- Testing or development environments

**How to configure:**
1. Enter your full base URL in the format: `https://yourdomai.com`
2. Do NOT include trailing slash
3. Do NOT include the path if your app is in a subdirectory (the app handles this)
4. Click **Save Settings**

**Example:**
```
Correct:   https://secure-ftp.example.com
Incorrect: https://secure-ftp.example.com/
Incorrect: https://secure-ftp.example.com/secure-ftp
```

### Switching Between Modes

**From Custom URL to Auto-Detection:**
- Click the **Use Auto-Detection** button, OR
- Clear the Base URL field and save

**From Auto-Detection to Custom URL:**
- Enter your desired URL and save

### Detection Information Panel

The Settings page shows a "Current Detection Info" panel that displays:

- **Protocol:** Detected protocol (http or https)
- **Host:** Detected hostname
- **Auto-Detected URL:** What the system would use with auto-detection
- **Active Base URL:** The URL currently being used
- **Behind Proxy:** Whether reverse proxy headers are detected
- **Forwarded Host:** The original host from X-Forwarded-Host header (if present)

Use this information to verify your configuration is working correctly.

## Testing Your Configuration

After saving your base URL configuration:

1. **Create a test share link:**
   - Go to Dashboard
   - Upload a test file
   - Click "Share" on the file
   - Examine the generated share link

2. **Verify the URL:**
   - The share link should use your configured base URL (or auto-detected URL)
   - Open the link in an incognito/private browser window
   - Verify the link works correctly

3. **Check multiple scenarios:**
   - Access from different domains (if applicable)
   - Test behind and outside your reverse proxy
   - Verify SSL/HTTPS works correctly

## Troubleshooting

### Share links show wrong domain/IP

**Problem:** Share links show internal IP (e.g., `http://192.168.1.100`) instead of your public domain.

**Solution 1:** Configure custom base URL
- Set the base URL to your public domain: `https://yourpublicdomain.com`

**Solution 2:** Fix reverse proxy headers (recommended)
- Ensure your reverse proxy sets these headers:
  ```nginx
  proxy_set_header X-Forwarded-Proto $scheme;
  proxy_set_header X-Forwarded-Host $host;
  ```
- Use auto-detection mode (leave base URL empty)

### Links work but show HTTP instead of HTTPS

**Problem:** Share links use `http://` when they should use `https://`

**Solution 1:** Set custom base URL with HTTPS
- Explicitly set: `https://yourdomain.com`

**Solution 2:** Fix proxy headers
- Ensure `X-Forwarded-Proto` header is set to `https`
- Check the Detection Info panel to verify

### Auto-detection not working

**Problem:** Auto-detection shows wrong URL

**Checklist:**
1. Verify reverse proxy is sending X-Forwarded-* headers
2. Check the Detection Info panel for what headers are being received
3. Test with curl to see headers:
   ```bash
   curl -I https://yourdomain.com/settings.php
   ```
4. Fall back to custom base URL as a workaround

### Database errors when saving

**Problem:** Error when trying to save base URL setting

**Solution:**
- Run the migration script if upgrading:
  ```bash
  mysql -u your_user -p secure_ftp < migration_add_settings.sql
  ```
- Or manually create the `app_settings` table using `database.sql`

## Advanced Use Cases

### Multiple Domains

If you have multiple domains pointing to the same installation:

**Option A:** Use auto-detection
- Share links will use whatever domain the user is currently on
- Different users may see different URLs for the same file

**Option B:** Use custom base URL
- All share links will use your primary domain
- Consistent URLs regardless of access method
- Recommended for professional deployments

### Development vs Production

**Development:**
- Use custom URL: `http://localhost:8080` or `http://dev.example.com`
- Makes testing easier with consistent URLs

**Production:**
- Use auto-detection with properly configured reverse proxy
- OR use custom URL with your production domain

### Load Balanced Environments

When using multiple backend servers:
- Use auto-detection (recommended)
- OR use custom URL pointing to your load balancer
- Ensure session persistence if using auto-detection

## Security Considerations

### URL Validation

The application validates custom base URLs to ensure:
- Proper URL format
- No XSS vulnerabilities
- No path traversal attempts

### HTTPS Enforcement

If using a custom base URL:
- Always use `https://` in production
- HTTP should only be used for local development

### Access Control

Only administrators can change application settings:
- Regular users cannot see or modify these settings
- Changes are logged with the administrator's user ID
- Review the `app_settings` table to see who made changes

## Database Storage

Settings are stored in the `app_settings` table:

```sql
mysql> SELECT * FROM app_settings WHERE setting_key = 'base_url';
+----+-------------+------------------------------+--------------+------------------+---------------------+------------+
| id | setting_key | setting_value                | setting_type | description      | updated_at          | updated_by |
+----+-------------+------------------------------+--------------+------------------+---------------------+------------+
|  1 | base_url    | https://secure-ftp.example.com | string      | Custom base URL... | 2026-02-07 10:30:00 |          1 |
+----+-------------+------------------------------+--------------+------------------+---------------------+------------+
```

To manually clear the setting:
```sql
DELETE FROM app_settings WHERE setting_key = 'base_url';
```

## Future Settings

The application settings infrastructure supports additional configuration options:

- Site name customization
- Default upload quotas
- File retention policies
- Email server configuration
- API keys and webhooks
- Maintenance mode
- Custom branding

These can be added to the Settings page as needed.
