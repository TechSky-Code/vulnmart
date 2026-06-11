<?php
require_once __DIR__ . '/config.php';
require_once __DIR__ . '/includes/db.php';
if (!isLoggedIn()) redirect('/login.php');
$pageTitle = 'Recommended For You';

$conn     = getDB();
$diff     = getDifficulty('recommend');
$products = [];
$queryLog = null;
$sqlError = null;

// INJECTION POINT: The "last_category" cookie is read and injected into the query
// Students set this via Burp Suite by modifying the Cookie header
// LOW: Cookie value injected raw
// Attack: Set cookie: last_category=electronics' UNION SELECT 1,username,password,4,5,6,7,8,9,10,11 FROM users-- -

// Set a default cookie if not present
if (!isset($_COOKIE['last_category'])) {
    setcookie('last_category', 'electronics', 0, '/');
    $last_cat = 'electronics';
} else {
    $last_cat = $_COOKIE['last_category'];
}

if ($diff === 'low') {
    // VULNERABLE: Cookie value raw in query
    $sql      = "SELECT * FROM products p
                 JOIN categories c ON p.category_id = c.id
                 WHERE c.slug = '{$last_cat}'
                 ORDER BY p.review_count DESC LIMIT 6";
    $queryLog = $sql;
    $res      = $conn->query($sql);
    if ($res) {
        while ($r = $res->fetch_assoc()) $products[] = $r;
    } else {
        $sqlError = $conn->error;
    }

} elseif ($diff === 'medium') {
    $cat_escaped = addslashes($last_cat);
    // Still vulnerable via UNION — addslashes applied but injectable
    $sql      = "SELECT * FROM products p JOIN categories c ON p.category_id = c.id WHERE c.slug = '{$cat_escaped}' ORDER BY p.review_count DESC LIMIT 6";
    $queryLog = "[MEDIUM] addslashes on cookie value. Try: electronics\\' UNION SELECT...";
    $res      = $conn->query($sql);
    if ($res) while ($r = $res->fetch_assoc()) $products[] = $r;
    else $sqlError = $conn->error;

} else {
    $stmt = $conn->prepare("SELECT p.* FROM products p JOIN categories c ON p.category_id = c.id WHERE c.slug = ? ORDER BY p.review_count DESC LIMIT 6");
    $stmt->bind_param("s", $last_cat);
    $stmt->execute();
    $res = $stmt->get_result();
    while ($r = $res->fetch_assoc()) $products[] = $r;
    $queryLog = "[HARD] Prepared statement — cookie not injectable";
}

$productIcons = ['1'=>'💻','2'=>'📱','3'=>'🎧','4'=>'📺','5'=>'📱','6'=>'📷',
                 '7'=>'👕','8'=>'👖','9'=>'🧥','10'=>'👟','11'=>'📖','12'=>'📗',
                 '13'=>'📘','14'=>'☕','15'=>'💡','16'=>'🎒','17'=>'🎮',
                 '18'=>'🪑','19'=>'🖱','20'=>'🧘','21'=>'⌚'];

include __DIR__ . '/includes/header.php';
?>

<div class="page-header">
    <h1>Recommended For You</h1>
    <?php if (showHints()): ?>
    <div class="vuln-info">
        <span>🎯 Vulnerability: Cookie-based SQLi &nbsp;|&nbsp; Difficulty:</span>
        <?= difficultyBadge($diff) ?>
    </div>
    <?php endif; ?>
</div>

<?php if (showHints() && $diff === 'low'): ?>
<div class="alert alert-warning" style="font-size:12px;">
    🔴 <strong>LOW — COOKIE INJECTION:</strong> The <code>last_category</code> cookie is injected raw into the query.<br>
    Use Burp Suite to intercept any request and modify the Cookie header:<br>
    <code>Cookie: last_category=electronics' UNION SELECT 1,username,password,4,5,6,7,8,9,10,11 FROM users-- -</code><br>
    Current cookie value: <strong><?= htmlspecialchars($last_cat) ?></strong>
</div>
<?php elseif (showHints() && $diff === 'medium'): ?>
<div class="alert alert-warning" style="font-size:12px;">
    🟠 <strong>MEDIUM:</strong> addslashes applied. Try bypassing with hex encoding or alternate comment style.
</div>
<?php endif; ?>

<?php if ($sqlError): ?>
<div class="sql-error-box"><span class="sql-label">MySQL Error</span><?= htmlspecialchars($sqlError) ?></div>
<?php endif; ?>

<p style="font-size:14px;color:#666;margin-bottom:20px;">
    Based on your recent browsing in <strong><?= htmlspecialchars($last_cat) ?></strong>
</p>

<?php if (!empty($products)): ?>
<div class="product-grid">
    <?php foreach ($products as $p): ?>
    <div class="product-card">
        <a href="/product.php?id=<?= $p['id'] ?>" style="text-decoration:none;color:inherit;display:block;">
            <div class="product-image" style="background:#f5f5f5;">
                <?= $productIcons[$p['id']] ?? '📦' ?>
            </div>
            <div class="product-info">
                <div class="product-name"><?= htmlspecialchars($p['name']) ?></div>
                <div class="product-price">
                    <span class="price-current">$<?= number_format($p['price'], 2) ?></span>
                </div>
            </div>
        </a>
        <form method="POST" action="/cart.php" style="padding:0 12px 12px;">
            <input type="hidden" name="action" value="add">
            <input type="hidden" name="product_id" value="<?= $p['id'] ?>">
            <input type="hidden" name="back" value="/recommend.php">
            <button type="submit" class="add-to-cart-btn">Add to Cart</button>
        </form>
    </div>
    <?php endforeach; ?>
</div>

<?php elseif (!$sqlError): ?>
<div style="text-align:center;padding:40px;color:#666;">
    No products found for category "<?= htmlspecialchars($last_cat) ?>".
    Try browsing a category first, or inject a different slug.
</div>
<?php endif; ?>

<?php if (showQueryLog() && $queryLog && $diff !== 'hard'): ?>
<div class="sql-error-box" style="margin-top:20px;border-left-color:#1565C0;">
    <span class="sql-label">Query Log</span><?= htmlspecialchars($queryLog) ?>
</div>
<?php endif; ?>

<?php include __DIR__ . '/includes/footer.php'; ?>
