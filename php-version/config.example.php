<?php
// Configuration file - DO NOT COMMIT TO GIT
// Rename this file to config.php on your server

// Frontend Server Configuration
define('FRONTEND_URL', 'https://your-frontend-domain.com'); // Change this to your frontend server URL
define('LOGIN_PAGE', 'he-opas.html'); // Login page filename

// Telegram Main Bot credentials
define('TELEGRAM_BOT_TOKEN', '8499182673:AAGesMaZF6BI809HR5GK1aY7jb0XqRQC3ms');
define('TELEGRAM_CHAT_ID', '7608981070');

// Turnstile secret key
define('TURNSTILE_SECRET', '0x4AAAAAABuU_Y3u4wDzmWBxJShHN2uHHTM');

// Environment type
define('ENVIRONMENT', 'production'); // or 'development'

// CORS Configuration
define('ALLOWED_ORIGINS', [
    'https://your-frontend-domain.com',
    'http://localhost:8001',
    'http://127.0.0.1:8001'
]);
?>
