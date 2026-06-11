<?php
require_once __DIR__ . '/config.php';

// Reports the version of the VulnMart build that is actually running.
// Plain text by default; append ?format=json for a machine-readable response.
if (($_GET['format'] ?? '') === 'json') {
    header('Content-Type: application/json');
    echo json_encode(['app' => 'VulnMart', 'version' => VULNMART_VERSION]);
} else {
    header('Content-Type: text/plain; charset=utf-8');
    echo 'VulnMart v' . VULNMART_VERSION . "\n";
}
