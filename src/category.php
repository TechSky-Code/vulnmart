<?php
require_once __DIR__ . '/config.php';
require_once __DIR__ . '/includes/db.php';
if (!isLoggedIn()) redirect('/login.php');
$pageTitle = 'Browse Category';

$conn     = getDB();
$diff     = getDifficulty('category');
$slug     = $_GET['slug'] ?? '';
$category = null;
$products = [];
$sqlError = null;
$queryLog = null;

// Get category safely
if ($slug !== '') {
    $stmt = $conn->prepare("SELECT * FROM categories WHERE slug = ?");
    $stmt->bind_param("s", $slug);
    $stmt->execute();
    $category = $stmt->get_result()->fetch_assoc();
}

if ($category) {
    $cat_id = (int)$category['id'];
    $res = $conn->query("SELECT * FROM products WHERE category_id = {$cat_id} ORDER BY review_count DESC");
    if ($res) while ($r = $res->fetch_assoc()) $products[] = $r;
} elseif ($slug === '') {
    // No slug = show all products
    $res = $conn->query("SELECT * FROM products ORDER BY review_count DESC");
    if ($res) while ($r = $res->fetch_assoc()) $products[] = $r;
}

// ================================================================
// HEADER-BASED SQL INJECTION via X-Forwarded-For
//
// The X-Forwarded-For header is logged to activity_logs.
// LOW: Raw header value injected directly into INSERT query.
// Attack via Burp/curl: Set header to:
//   X-Forwarded-For: 1.2.3.4', (SELECT password FROM users WHERE username='admin'), 'page')-- -
//
// The admin panel (admin/index.php) displays these logs — so
// the extracted data becomes visible when admin views activity.
//
// Time-based blind is also possible:
//   X-Forwarded-For: 1.2.3.4' AND SLEEP(5)-- -
// ================================================================

$xff = $_SERVER['HTTP_X_FORWARDED_FOR'] ?? $_SERVER['REMOTE_ADDR'] ?? '127.0.0.1';

if ($diff === 'low') {
    // X-Forwarded-For directly in INSERT — injectable
    $page_name = $slug ?: 'home';
    $sql_log = "INSERT INTO activity_logs (user_agent, ip_address, page, action)
                VALUES ('{$_SERVER['HTTP_USER_AGENT']}', '{$xff}', '{$page_name}', 'browse')";
    $queryLog = $sql_log;
    if (!$conn->query($sql_log)) {
        $sqlError = $conn->error;
    }

} elseif ($diff === 'medium') {
    // IP is validated (basic), but User-Agent is now the injection point
    $ip_safe  = filter_var($xff, FILTER_VALIDATE_IP) ? $xff : '0.0.0.0';
    $ua       = $_SERVER['HTTP_USER_AGENT'] ?? '';
    // User-Agent is raw here
    $sql_log  = "INSERT INTO activity_logs (user_agent, ip_address, page, action)
                 VALUES ('{$ua}', '{$ip_safe}', '{$slug}', 'browse')";
    $queryLog = "[MEDIUM] IP validated. But User-Agent is raw in INSERT query.";
    $conn->query($sql_log);

} else {
    // HARD — both values escaped
    $ip_safe = $conn->real_escape_string($xff);
    $ua_safe = $conn->real_escape_string($_SERVER['HTTP_USER_AGENT'] ?? '');
    $slug_safe = $conn->real_escape_string($slug);
    $conn->query("INSERT INTO activity_logs (user_agent, ip_address, page, action)
                  VALUES ('{$ua_safe}', '{$ip_safe}', '{$slug_safe}', 'browse')");
    $queryLog = "[HARD] Both IP and User-Agent sanitized with real_escape_string";
}

function stars(float $r): string {
    return str_repeat('★', (int)$r) . str_repeat('☆', 5-(int)$r);
}
$icons = ['1'=>'💻','2'=>'📱','3'=>'🎧','4'=>'📺','5'=>'📱','6'=>'📷','7'=>'👕','8'=>'👖','9'=>'🧥','10'=>'👟','11'=>'📖','12'=>'📗','13'=>'📘','14'=>'☕','15'=>'💡','16'=>'🎒','17'=>'🎮','18'=>'🪑','19'=>'🖱','20'=>'🧘','21'=>'⌚'];

include __DIR__ . '/includes/header.php';
?>

<div class="page-header">
    <h1><?= $category ? htmlspecialchars($category['name']) : 'All Categories' ?></h1>
    <?php if (showHints()): ?>
    <div class="vuln-info">
        <span>🎯 Vulnerability: Header-based SQLi (X-Forwarded-For / User-Agent) &nbsp;|&nbsp; Difficulty:</span>
        <?= difficultyBadge($diff) ?>
    </div>
    <?php endif; ?>
</div>

<?php if (showHints() && $diff === 'low'): ?>
<div class="alert alert-warning" style="font-size:12px;">
    🔴 <strong>LOW:</strong> The <code>X-Forwarded-For</code> header is injected directly into an INSERT query.<br>
    Use Burp Suite or curl to inject. Example:<br>
    <code>curl -H "X-Forwarded-For: 1.2.3.4',(SELECT password FROM users WHERE username='admin'),'page')-- -" http://localhost:8080/category.php?slug=<?= htmlspecialchars($slug) ?></code><br>
    <br>
    Results appear in: <a href="/admin/index.php" style="color:#C45500;">Admin Panel → Activity Logs</a>
</div>
<?php elseif (showHints() && $diff === 'medium'): ?>
<div class="alert alert-warning" style="font-size:12px;">
    🟠 <strong>MEDIUM:</strong> IP is validated. Switch injection vector to <code>User-Agent</code> header.
</div>
<?php endif; ?>

<?php if ($sqlError): ?>
<div class="sql-error-box"><span class="sql-label">MySQL Error (INSERT into activity_logs)</span><?= htmlspecialchars($sqlError) ?></div>
<?php endif; ?>

<?php if (!empty($products)): ?>
<div class="product-grid">
    <?php foreach ($products as $p): ?>
    <div class="product-card">
        <a href="/product.php?id=<?= $p['id'] ?>" style="text-decoration:none;color:inherit;display:block;">
        <div class="product-image" style="background:<?= htmlspecialchars($p['image_color'] ?? '#EEE') ?>22">
            <?= $icons[$p['id']] ?? '📦' ?>
            <?php if (!empty($p['badge'])): ?>
            <span class="product-badge"><?= htmlspecialchars($p['badge']) ?></span>
            <?php endif; ?>
        </div>
        <div class="product-info">
            <div class="product-name"><?= htmlspecialchars($p['name']) ?></div>
            <div class="product-stars"><?= stars((float)$p['rating']) ?></div>
            <div class="product-reviews"><?= number_format((int)$p['review_count']) ?> reviews</div>
            <div class="product-price">
                <span class="price-current">$<?= number_format((float)$p['price'], 2) ?></span>
                <?php if ($p['original_price'] > $p['price']): ?>
                <span class="price-original">$<?= number_format((float)$p['original_price'], 2) ?></span>
                <?php endif; ?>
            </div>
        </div>
        </a>
        <form method="POST" action="/cart.php" style="padding:0 12px 12px;">
            <input type="hidden" name="action" value="add">
            <input type="hidden" name="product_id" value="<?= $p['id'] ?>">
            <input type="hidden" name="back" value="/category.php?slug=<?= urlencode($slug) ?>">
            <button type="submit" class="add-to-cart-btn">Add to Cart</button>
        </form>
    </div>
    <?php endforeach; ?>
</div>
<?php else: ?>
<div class="no-results">
    <div class="no-results-icon"><?= $category ? htmlspecialchars($category['icon']) : '🛍' ?></div>
    <h3>No products in this category</h3>
</div>
<?php endif; ?>

<?php if (showQueryLog() && $queryLog && $diff !== 'hard'): ?>
<div class="sql-error-box" style="margin-top:20px;">
    <span class="sql-label">Query Log (INSERT)</span><?= htmlspecialchars($queryLog) ?>
</div>
<?php endif; ?>

<?php include __DIR__ . '/includes/footer.php'; ?>
