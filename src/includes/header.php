<?php
require_once __DIR__ . '/../includes/db.php';

// Hardcoded emoji map - avoids DB charset issues entirely
$_cat_icons = [
    'books'        => '📚',
    'clothing'     => '👕',
    'electronics'  => '💻',
    'gaming'       => '🎮',
    'home-kitchen' => '🏠',
    'sports'       => '⚽',
];

$_categories = [];
$_cats = getDB()->query("SELECT * FROM categories ORDER BY name");
if ($_cats) {
    while ($r = $_cats->fetch_assoc()) {
        $r['icon'] = $_cat_icons[$r['slug']] ?? '';
        $_categories[] = $r;
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta http-equiv="Content-Type" content="text/html; charset=utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?= isset($pageTitle) ? htmlspecialchars($pageTitle) . ' – ' : '' ?>VulnMart</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="/assets/css/style.css">
</head>
<body>

<!-- Training Banner -->
<div class="training-banner">
    ⚠️ <strong>VulnMart</strong> — Intentionally Vulnerable Web Application for Web Pentesting Training &nbsp;|&nbsp; For Educational Use Only
    <?php if (isAdmin()): ?>
    &nbsp;|&nbsp; <a href="/admin/settings.php" style="color:#FFD54F;font-weight:600;">⚙ Settings</a>
    <?php endif; ?>
</div>

<!-- Main Header -->
<header class="site-header">
    <div class="header-inner">

        <a href="/" class="site-logo">
            <span class="logo-icon">🛒</span>
            <span>VulnMart</span>
        </a>

        <form action="/search.php" method="GET" class="header-search">
            <select name="cat" class="search-cat-select">
                <option value="">All</option>
                <?php foreach ($_categories as $c): ?>
                <option value="<?= htmlspecialchars($c['slug']) ?>"
                    <?= (isset($_GET['cat']) && $_GET['cat'] === $c['slug']) ? 'selected' : '' ?>>
                    <?= htmlspecialchars($c['name']) ?>
                </option>
                <?php endforeach; ?>
            </select>
            <input type="text" name="q" placeholder="Search VulnMart"
                   value="<?= isset($_GET['q']) ? htmlspecialchars($_GET['q']) : '' ?>"
                   class="search-input" autocomplete="off">
            <button type="submit" class="search-btn">🔍</button>
        </form>

        <div class="header-actions">
            <?php if (isLoggedIn()): ?>
            <a href="/profile.php" class="header-action-link">
                <span class="action-label">Hello, <?= htmlspecialchars($_SESSION['username']) ?></span>
                <span class="action-main">Account</span>
            </a>
            <a href="/orders.php" class="header-action-link">
                <span class="action-label">Returns &amp;</span>
                <span class="action-main">Orders</span>
            </a>
            <a href="/logout.php" class="header-action-link">
                <span class="action-label">Sign</span>
                <span class="action-main">Out</span>
            </a>
            <?php else: ?>
            <a href="/login.php" class="header-action-link">
                <span class="action-label">Hello, sign in</span>
                <span class="action-main">Account &amp; Lists</span>
            </a>
            <?php endif; ?>
            <a href="/cart.php" class="header-cart">
                <span class="cart-qty"><?= array_sum($_SESSION['cart'] ?? []) ?></span>
                <span>Cart</span>
            </a>
        </div>
    </div>
</header>

<!-- Category Nav -->
<nav class="cat-nav">
    <div class="cat-nav-inner">
        <a href="/" class="cat-nav-link">☰ All</a>
        <?php foreach ($_categories as $c): ?>
        <a href="/category.php?slug=<?= htmlspecialchars($c['slug']) ?>" class="cat-nav-link">
            <?= $c['icon'] ?> <?= htmlspecialchars($c['name']) ?>
        </a>
        <?php endforeach; ?>
        <?php if (isAdmin()): ?>
        <a href="/admin/index.php" class="cat-nav-link cat-nav-admin">🛡 Admin Panel</a>
        <?php endif; ?>
    </div>
</nav>

<main class="site-main">
