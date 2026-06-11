<?php
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}
header('Content-Type: text/html; charset=utf-8');

define('DB_HOST', getenv('DB_HOST') ?: 'db');
define('DB_USER', getenv('DB_USER') ?: 'vulnmart');
define('DB_PASS', getenv('DB_PASS') ?: 'vulnmart123');
define('DB_NAME', getenv('DB_NAME') ?: 'vulnmart');
define('SITE_NAME', 'VulnMart');

// Single source of truth for the app version: bump src/VERSION each release.
define('VULNMART_VERSION', trim(@file_get_contents(__DIR__ . '/VERSION')) ?: 'dev');

function getDifficulty(string $page): string {
    try {
        $conn = getDB();
        $stmt = $conn->prepare("SELECT difficulty FROM settings WHERE page = ?");
        $stmt->bind_param("s", $page);
        $stmt->execute();
        $res = $stmt->get_result();
        if ($row = $res->fetch_assoc()) return $row['difficulty'];
    } catch (Exception $e) {}
    return 'low';
}

function getGlobalSetting(string $column): int {
    try {
        $conn = getDB();
        $res = $conn->query("SELECT `$column` FROM settings WHERE page = 'global'");
        if ($res && $row = $res->fetch_assoc()) return (int)$row[$column];
    } catch (Exception $e) {}
    return 1;
}

function showHints(): bool    { return (bool)getGlobalSetting('show_hints'); }
function showQueryLog(): bool { return (bool)getGlobalSetting('show_query_log'); }

function isLoggedIn(): bool {
    return isset($_SESSION['user_id']);
}

function isAdmin(): bool {
    return isset($_SESSION['role']) && $_SESSION['role'] === 'admin';
}

function redirect(string $url): void {
    header("Location: $url");
    exit();
}

function difficultyBadge(string $difficulty): string {
    $colors = ['low' => '#E53935', 'medium' => '#FB8C00', 'hard' => '#43A047'];
    $color  = $colors[$difficulty] ?? '#999';
    return "<span class='diff-badge' style='background:$color'>" . strtoupper($difficulty) . "</span>";
}
