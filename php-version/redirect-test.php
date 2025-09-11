<?php
// Simple redirect test
ob_start();

echo "<!-- Debug: Starting redirect test -->";

// Test redirect
$redirectUrl = "https://www.google.com";
error_log("Testing redirect to: $redirectUrl");

// Clear output and redirect
if (ob_get_level()) {
    ob_end_clean();
}

header("HTTP/1.1 302 Found");
header("Location: $redirectUrl");
exit();
?>
