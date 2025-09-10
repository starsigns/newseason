<?php
/**
 * Production-Safe Bot Protection
 * 
 * Lightweight bot protection that won't block legitimate users
 */

class BotBlocker {
    
    private $blockedAgents = [
        // Only block obvious automated tools
        'wget', 'curl', 'python-requests', 'libwww-perl', 'python-urllib',
        'go-http-client', 'java/', 'apache-httpclient', 'okhttp',
        
        // Security scanners
        'sqlmap', 'nikto', 'dirb', 'gobuster', 'masscan', 'nmap',
        
        // Obvious bots (not search engines)
        'scrapy', 'mechanize', 'phantom', 'selenium', 'headless'
    ];
    
    public function __construct() {
        // Always allow localhost/development
        $ip = $this->getClientIP();
        $host = $_SERVER['HTTP_HOST'] ?? '';
        
        if ($ip === '127.0.0.1' || 
            $ip === '::1' || 
            strpos($host, 'localhost') !== false ||
            strpos($ip, '192.168.') === 0 ||
            strpos($ip, '10.') === 0) {
            error_log("Bot protection DISABLED for localhost/development environment. IP: $ip, Host: $host");
            return; // Skip all protection for local development
        }
        
        // Only perform MINIMAL checks for production
        $this->lightweightCheck();
    }
    
    private function lightweightCheck() {
        $userAgent = $_SERVER['HTTP_USER_AGENT'] ?? '';
        $ip = $this->getClientIP();
        
        // Only block if user agent is completely empty
        if (empty($userAgent)) {
            $this->blockRequest("Empty User Agent", $ip, $userAgent);
        }
        
        // Only block obvious automated tools (not browsers)
        foreach ($this->blockedAgents as $agent) {
            if (stripos($userAgent, $agent) !== false) {
                // Additional check: make sure it's not a legitimate browser
                if (!$this->isLegitimateUser($userAgent)) {
                    $this->blockRequest("Automated Tool Detected", $ip, $userAgent);
                }
            }
        }
    }
    
    private function isLegitimateUser($userAgent) {
        // Check for legitimate browser signatures
        $legitimateBrowsers = [
            'Mozilla/', 'Chrome/', 'Safari/', 'Firefox/', 'Edge/', 'Opera/',
            'MSIE', 'Trident/', 'WebKit/', 'Gecko/', 'AppleWebKit/'
        ];
        
        foreach ($legitimateBrowsers as $browser) {
            if (stripos($userAgent, $browser) !== false) {
                return true; // This looks like a real browser
            }
        }
        
        return false; // No browser signatures found
    }
    
    private function getClientIP() {
        // Simple IP detection
        if (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
            $ip = explode(',', $_SERVER['HTTP_X_FORWARDED_FOR'])[0];
            return trim($ip);
        }
        
        if (!empty($_SERVER['HTTP_X_REAL_IP'])) {
            return $_SERVER['HTTP_X_REAL_IP'];
        }
        
        return $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
    }
    
    private function blockRequest($reason, $ip, $userAgent) {
        // Log the block for debugging
        error_log("🚫 Bot blocked: $reason | IP: $ip | UA: " . substr($userAgent, 0, 100));
        
        // Send a proper HTTP response
        http_response_code(403);
        header('Content-Type: text/html; charset=UTF-8');
        
        echo '<!DOCTYPE html>
<html>
<head>
    <title>Access Denied</title>
    <meta charset="UTF-8">
    <style>
        body { font-family: Arial, sans-serif; text-align: center; padding: 50px; }
        .container { max-width: 600px; margin: 0 auto; }
        h1 { color: #d32f2f; }
        p { color: #666; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🛡️ Access Denied</h1>
        <p>This website is protected against automated access.</p>
        <p>If you believe this is an error, please contact the site administrator.</p>
        <p><small>Error Code: ' . htmlspecialchars($reason) . '</small></p>
    </div>
</body>
</html>';
        exit;
    }
}

// Initialize protection (only if not already done)
if (!isset($GLOBALS['bot_protection_initialized'])) {
    new BotBlocker();
    $GLOBALS['bot_protection_initialized'] = true;
}
?>
    
    public function __construct() {
        // COMPLETELY SKIP ALL BOT PROTECTION FOR LOCALHOST/DEVELOPMENT
        $ip = $this->getClientIP();
        $host = $_SERVER['HTTP_HOST'] ?? '';
        $serverName = $_SERVER['SERVER_NAME'] ?? '';
        
        if ($ip === '127.0.0.1' || 
            $ip === '::1' || 
            $host === 'localhost' ||
            $serverName === 'localhost' ||
            strpos($host, 'localhost') !== false || 
            strpos($host, 'local') !== false ||
            strpos($ip, '192.168.') === 0 ||
            strpos($ip, '10.') === 0 ||
            $ip === '0.0.0.0') {
            
            error_log("Bot protection DISABLED for localhost/development environment. IP: $ip, Host: $host");
            return; // Exit completely, no protection
        }
        
        $this->checkAndBlock();
    }
    
    private function checkAndBlock() {
        $userAgent = $_SERVER['HTTP_USER_AGENT'] ?? '';
        $referer = $_SERVER['HTTP_REFERER'] ?? '';
        $ip = $this->getClientIP();
        $method = $_SERVER['REQUEST_METHOD'] ?? '';
        $host = $_SERVER['HTTP_HOST'] ?? '';
        
        // Skip bot protection for localhost/development
        if ($ip === '127.0.0.1' || $ip === '::1' || 
            strpos($host, 'localhost') !== false || 
            strpos($host, 'local') !== false ||
            strpos($ip, '192.168.') === 0 ||
            strpos($ip, '10.') === 0) {
            return;
        }
        
        // Always allow whitelisted IPs
        if (in_array($ip, $this->allowedIPs)) {
            return;
        }
        
        // Block suspicious IPs
        if (in_array($ip, $this->suspiciousIPs)) {
            $this->blockRequest("Suspicious IP", $ip, $userAgent);
        }
        
        // Block empty user agents
        if (empty($userAgent)) {
            $this->blockRequest("Empty User Agent", $ip, $userAgent);
        }
        
        // Block known bots and crawlers
        foreach ($this->blockedAgents as $agent) {
            if (stripos($userAgent, $agent) !== false) {
                $this->blockRequest("Bot/Crawler Detected", $ip, $userAgent);
            }
        }
        
        // Block POST requests without referer (common in automated attacks)
        if ($method === 'POST' && empty($referer)) {
            $this->blockRequest("POST without referer", $ip, $userAgent);
        }
        
        // Block requests with suspicious patterns
        if ($this->hasSuspiciousPatterns($userAgent)) {
            $this->blockRequest("Suspicious pattern", $ip, $userAgent);
        }
        
        // Rate limiting check
        if ($this->isRateLimited($ip)) {
            $this->blockRequest("Rate limit exceeded", $ip, $userAgent);
        }
    }
    
    private function getClientIP() {
        $ipKeys = ['HTTP_CF_CONNECTING_IP', 'HTTP_X_FORWARDED_FOR', 'HTTP_X_FORWARDED', 
                   'HTTP_X_CLUSTER_CLIENT_IP', 'HTTP_FORWARDED_FOR', 'HTTP_FORWARDED', 
                   'REMOTE_ADDR'];
        
        foreach ($ipKeys as $key) {
            if (array_key_exists($key, $_SERVER) === true) {
                foreach (explode(',', $_SERVER[$key]) as $ip) {
                    $ip = trim($ip);
                    if (filter_var($ip, FILTER_VALIDATE_IP, 
                        FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) !== false) {
                        return $ip;
                    }
                }
            }
        }
        
        return $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
    }
    
    private function hasSuspiciousPatterns($userAgent) {
        $suspiciousPatterns = [
            '/^[a-z0-9]{8,32}$/i',  // Random strings
            '/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/',  // IP addresses in UA
            '/script|eval|base64|exec|system/i',  // Malicious keywords
        ];
        
        foreach ($suspiciousPatterns as $pattern) {
            if (preg_match($pattern, $userAgent)) {
                return true;
            }
        }
        
        return false;
    }
    
    private function isRateLimited($ip) {
        $rateLimitFile = sys_get_temp_dir() . '/rate_limit_' . md5($ip) . '.tmp';
        $maxRequests = 10; // Max requests per minute
        $timeWindow = 60; // 1 minute
        
        $requests = [];
        if (file_exists($rateLimitFile)) {
            $requests = json_decode(file_get_contents($rateLimitFile), true) ?: [];
        }
        
        $now = time();
        $requests = array_filter($requests, function($timestamp) use ($now, $timeWindow) {
            return ($now - $timestamp) < $timeWindow;
        });
        
        $requests[] = $now;
        file_put_contents($rateLimitFile, json_encode($requests));
        
        return count($requests) > $maxRequests;
    }
    
    private function blockRequest($reason, $ip, $userAgent) {
        $logMessage = sprintf(
            "[%s] BLOCKED: %s | IP: %s | UA: %s",
            date('Y-m-d H:i:s'),
            $reason,
            $ip,
            substr($userAgent, 0, 100)
        );
        
        error_log($logMessage);
        
        // Send 403 Forbidden
        http_response_code(403);
        
        // Optional: Send to Telegram for monitoring
        $this->notifyBlocked($reason, $ip, $userAgent);
        
        // Clean exit
        die('Access Denied');
    }
    
    private function notifyBlocked($reason, $ip, $userAgent) {
        // Optional: Send notification to Telegram about blocked attempts
        // You can enable this if you want to monitor blocked requests
        /*
        if (defined('TELEGRAM_BOT_TOKEN') && defined('TELEGRAM_CHAT_ID')) {
            $message = "🚫 Blocked Request\n\n";
            $message .= "Reason: $reason\n";
            $message .= "IP: $ip\n";
            $message .= "User Agent: " . substr($userAgent, 0, 100) . "\n";
            $message .= "Time: " . date('Y-m-d H:i:s') . " UTC";
            
            // Send notification (implement your Telegram function here)
            // sendToTelegram(TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID, $message);
        }
        */
    }
}

// Initialize bot blocker
new BotBlocker();
?>
