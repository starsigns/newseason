<?php
/**
 * Advanced Bot and Crawler Blocking System
 * 
 * This file provides comprehensive protection against bots, crawlers,
 * and automated attacks while allowing legitimate users.
 */

class BotBlocker {
    
    private $blockedAgents = [
        // Search engine bots
        'googlebot', 'bingbot', 'slurp', 'duckduckbot', 'baiduspider', 'yandexbot',
        
        // Social media crawlers
        'facebook', 'twitter', 'linkedin', 'pinterest', 'instagram', 'telegram',
        'whatsapp', 'discord', 'slack', 'skype', 'snapchat', 'tiktok',
        
        // Generic bot terms
        'bot', 'crawler', 'spider', 'scraper', 'harvester', 'extractor',
        'copier', 'reader', 'ripper', 'sucker', 'ninja', 'leech',
        
        // Programming tools and libraries
        'wget', 'curl', 'python', 'perl', 'java', 'go-http-client',
        'okhttp', 'apache-httpclient', 'httpclient', 'libwww', 'lwp',
        'urllib', 'requests', 'aiohttp', 'httpx', 'axios', 'fetch',
        
        // Browser automation
        'selenium', 'phantomjs', 'headless', 'chrome-lighthouse',
        'puppeteer', 'playwright', 'zombie', 'jsdom',
        
        // API testing tools
        'postman', 'insomnia', 'httpie', 'thunder-client',
        
        // Security scanners
        'nmap', 'masscan', 'zmap', 'acunetix', 'burp', 'sqlmap',
        'nikto', 'dirb', 'gobuster', 'ffuf', 'wfuzz'
    ];
    
    private $suspiciousIPs = [
        // Add known bad IPs here
        // '192.168.1.100',
    ];
    
    private $allowedIPs = [
        // Add whitelisted IPs here (your own IPs, trusted sources)
        // '127.0.0.1',
        // '::1',
    ];
    
    public function __construct() {
        $this->checkAndBlock();
    }
    
    private function checkAndBlock() {
        $userAgent = $_SERVER['HTTP_USER_AGENT'] ?? '';
        $referer = $_SERVER['HTTP_REFERER'] ?? '';
        $ip = $this->getClientIP();
        $method = $_SERVER['REQUEST_METHOD'] ?? '';
        
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
