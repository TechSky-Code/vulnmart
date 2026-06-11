<?php
require_once __DIR__ . '/config.php';
require_once __DIR__ . '/includes/db.php';
if (!isLoggedIn()) redirect('/login.php');

$conn     = getDB();
$diff     = getDifficulty('product');
$diff_xss = getDifficulty('xss');
$id       = $_GET['id'] ?? '1';
$product  = null;
$sqlError = null;
$queryLog = null;

// ================================================================
// LOW — Integer param, no quotes. UNION and Boolean blind work.
// ================================================================
if ($diff === 'low') {
    $sql = "SELECT p.*, c.name AS cat_name FROM products p
            LEFT JOIN categories c ON p.category_id = c.id
            WHERE p.id = {$id}";
    $queryLog = $sql;
    $res = $conn->query($sql);
    if (!$res) {
        $sqlError = $conn->error;
    } elseif ($res->num_rows > 0) {
        $product = $res->fetch_assoc();
    }

// ================================================================
// MEDIUM — id safe, sort param injectable.
// ================================================================
} elseif ($diff === 'medium') {
    $id_safe = intval($id);
    $sort    = $_GET['sort'] ?? 'review_count';
    $stmt = $conn->prepare("SELECT p.*, c.name AS cat_name FROM products p
                            LEFT JOIN categories c ON p.category_id = c.id
                            WHERE p.id = ?");
    $stmt->bind_param("i", $id_safe);
    $stmt->execute();
    $product = $stmt->get_result()->fetch_assoc();
    $related_sql = "SELECT * FROM products WHERE category_id =
                    (SELECT category_id FROM products WHERE id = {$id_safe})
                    AND id != {$id_safe}
                    ORDER BY {$sort} DESC LIMIT 4";
    $queryLog = "[MEDIUM] main id uses intval(), but sort= is raw: ORDER BY {$sort}";
    $conn->query($related_sql);

// ================================================================
// HARD — Fully prepared.
// ================================================================
} else {
    $id_safe = intval($id);
    $stmt = $conn->prepare("SELECT p.*, c.name AS cat_name FROM products p
                            LEFT JOIN categories c ON p.category_id = c.id
                            WHERE p.id = ?");
    $stmt->bind_param("i", $id_safe);
    $stmt->execute();
    $product = $stmt->get_result()->fetch_assoc();
    $queryLog = "[HARD] Prepared statement used for all queries";
}

// ================================================================
// STORED XSS — Review submission
// LOW:  review stored and displayed raw — XSS fires for every visitor
// HARD: htmlspecialchars on output — script rendered as text
// Attack: <script>alert('XSS')</script>
// Attack: <script>alert(document.cookie)</script>
// ================================================================
$reviewSuccess = false;
$reviewError   = null;
$pid_safe      = intval($id);

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['review_text'])) {
    $review_text = $_POST['review_text'] ?? '';
    $rating_val  = max(1, min(5, (int)($_POST['rating'] ?? 5)));
    $uid         = (int)$_SESSION['user_id'];

    if (trim($review_text) === '') {
        $reviewError = "Review cannot be empty.";
    } else {
        // Both Low and Hard store raw — difference is in OUTPUT not storage
        $safe_text = $conn->real_escape_string($review_text);
        $conn->query("INSERT INTO reviews (user_id, product_id, rating, review)
                      VALUES ({$uid}, {$pid_safe}, {$rating_val}, '{$safe_text}')");
        $reviewSuccess = true;
        redirect("/product.php?id={$pid_safe}");
    }
}

// Load reviews for this product
$reviews = [];
$rev_res = $conn->query("SELECT r.review, r.rating, r.created_at, u.username
                          FROM reviews r
                          JOIN users u ON r.user_id = u.id
                          WHERE r.product_id = {$pid_safe}
                          ORDER BY r.created_at DESC
                          LIMIT 10");
if ($rev_res) while ($row = $rev_res->fetch_assoc()) $reviews[] = $row;

// Related products
$relatedProducts = [];
if ($product) {
    $cat_id = (int)$product['category_id'];
    $rel = $conn->query("SELECT * FROM products WHERE category_id = {$cat_id} AND id != {$pid_safe} LIMIT 4");
    if ($rel) while ($r = $rel->fetch_assoc()) $relatedProducts[] = $r;
}

$pageTitle = $product ? $product['name'] : 'Product Not Found';

function stars(float $r): string {
    return str_repeat('★', (int)$r) . str_repeat('☆', 5-(int)$r);
}

$icons = ['1'=>'💻','2'=>'📱','3'=>'🎧','4'=>'📺','5'=>'📱','6'=>'📷',
          '7'=>'👕','8'=>'👖','9'=>'🧥','10'=>'👟','11'=>'📖','12'=>'📗',
          '13'=>'📘','14'=>'☕','15'=>'💡','16'=>'🎒','17'=>'🎮',
          '18'=>'🪑','19'=>'🖱','20'=>'🧘','21'=>'⌚'];

include __DIR__ . '/includes/header.php';
?>

<div class="page-header">
    <h1>Product Detail</h1>
    <?php if (showHints()): ?>
    <div class="vuln-info">
        <span>🎯 Vulnerabilities: UNION SQLi &nbsp;|&nbsp; Stored XSS (reviews) &nbsp;|&nbsp; Difficulty:</span>
        <?= difficultyBadge($diff) ?>
    </div>
    <?php endif; ?>
</div>

<?php if ($sqlError): ?>
<div class="sql-error-box"><span class="sql-label">MySQL Error</span><?= htmlspecialchars($sqlError) ?></div>
<?php endif; ?>

<?php if ($product): ?>

<div class="breadcrumb">
    <a href="/">VulnMart</a> &rsaquo;
    <a href="/category.php?slug=<?= urlencode($product['cat_name'] ?? '') ?>"><?= htmlspecialchars($product['cat_name'] ?? 'Category') ?></a> &rsaquo;
    <span><?= htmlspecialchars($product['name']) ?></span>
</div>

<div class="product-detail">
    <div class="product-detail-image" style="background:<?= htmlspecialchars($product['image_color'] ?? '#EEE') ?>22">
        <?= $icons[$product['id']] ?? '📦' ?>
    </div>

    <div class="product-detail-info">
        <p style="font-size:12px;color:var(--text-muted);margin-bottom:4px;"><?= htmlspecialchars($product['cat_name'] ?? '') ?></p>
        <h1 class="product-title"><?= htmlspecialchars($product['name']) ?></h1>
        <div class="product-stars">
            <?= stars((float)$product['rating']) ?>
            <span style="font-size:13px;color:#007185;margin-left:6px;"><?= number_format((int)$product['review_count']) ?> ratings</span>
        </div>
        <div style="border-top:1px solid var(--border);margin:12px 0;"></div>
        <div class="product-price-large" style="font-size:28px;font-weight:700;color:#B12704;">
            $<?= number_format((float)$product['price'], 2) ?>
            <?php if ($product['original_price'] > $product['price']): ?>
            <span style="font-size:14px;color:var(--text-muted);text-decoration:line-through;font-weight:400;margin-left:10px;">
                $<?= number_format((float)$product['original_price'], 2) ?>
            </span>
            <span style="font-size:14px;color:var(--success);font-weight:600;margin-left:6px;">
                Save $<?= number_format($product['original_price'] - $product['price'], 2) ?>
            </span>
            <?php endif; ?>
        </div>
        <p class="product-desc"><?= htmlspecialchars($product['description']) ?></p>
    </div>

    <div class="buy-box">
        <div class="buy-price">$<?= number_format((float)$product['price'], 2) ?></div>
        <div class="in-stock">✓ In Stock</div>
        <div style="font-size:13px;margin-bottom:12px;">Ships from and sold by <strong>VulnMart</strong></div>
        <form method="POST" action="/cart.php">
            <input type="hidden" name="action" value="add">
            <input type="hidden" name="product_id" value="<?= $product['id'] ?>">
            <input type="hidden" name="back" value="/product.php?id=<?= $product['id'] ?>">
            <div class="form-group">
                <label>Qty:</label>
                <select name="quantity" style="padding:6px;border:1px solid var(--border);border-radius:4px;width:80px;">
                    <option>1</option><option>2</option><option>3</option>
                </select>
            </div>
            <button type="submit" class="add-to-cart-btn">Add to Cart</button>
            <button type="submit" class="btn" style="width:100%;margin-top:8px;background:#FFD814;border:1px solid #C89411;">Buy Now</button>
        </form>
    </div>
</div>

<!-- Related Products -->
<?php if (!empty($relatedProducts)): ?>
<div class="section-header" style="margin-top:24px;">
    <h2 class="section-title">Related Products</h2>
</div>
<div class="product-grid">
    <?php foreach ($relatedProducts as $r): ?>
    <a href="/product.php?id=<?= $r['id'] ?>" class="product-card">
        <div class="product-image" style="background:<?= htmlspecialchars($r['image_color'] ?? '#EEE') ?>22"><?= $icons[$r['id']] ?? '📦' ?></div>
        <div class="product-info">
            <div class="product-name"><?= htmlspecialchars($r['name']) ?></div>
            <div class="product-stars"><?= stars((float)$r['rating']) ?></div>
            <div class="product-price"><span class="price-current">$<?= number_format((float)$r['price'], 2) ?></span></div>
        </div>
    </a>
    <?php endforeach; ?>
</div>
<?php endif; ?>

<!-- ============================================================
     CUSTOMER REVIEWS SECTION
     Stored XSS lives here — review text displayed raw at Low
     ============================================================ -->
<div style="max-width:800px;margin-top:32px;">

    <h2 style="font-size:18px;font-weight:700;margin-bottom:8px;padding-bottom:8px;border-bottom:2px solid var(--border);">
        Customer Reviews
    </h2>

    <?php if (showHints() && $diff_xss === 'low'): ?>
    <div class="alert alert-warning" style="font-size:12px;margin-bottom:16px;">
        🔴 <strong>Stored XSS:</strong> Review text is saved and displayed without sanitization.<br>
        Submit: <code>&lt;script&gt;alert('XSS')&lt;/script&gt;</code> — fires for every visitor who views this page.<br>
        Cookie theft: <code>&lt;script&gt;alert(document.cookie)&lt;/script&gt;</code>
    </div>
    <?php endif; ?>

    <!-- Review submission form -->
    <div style="background:var(--card-bg);border:1px solid var(--border);border-radius:var(--radius);padding:20px;margin-bottom:24px;">
        <h3 style="font-size:15px;font-weight:700;margin-bottom:12px;">Write a Customer Review</h3>
        <?php if ($reviewError): ?>
        <div style="padding:8px 12px;background:#fff3cd;border:1px solid #ffc107;border-radius:4px;font-size:13px;margin-bottom:12px;"><?= htmlspecialchars($reviewError) ?></div>
        <?php endif; ?>
        <form method="POST" action="/product.php?id=<?= $pid_safe ?>">
            <div style="margin-bottom:10px;">
                <label style="font-size:13px;font-weight:600;display:block;margin-bottom:4px;">Rating</label>
                <select name="rating" style="padding:6px 10px;border:1px solid var(--border);border-radius:4px;font-family:inherit;">
                    <option value="5">★★★★★ (5)</option>
                    <option value="4">★★★★☆ (4)</option>
                    <option value="3">★★★☆☆ (3)</option>
                    <option value="2">★★☆☆☆ (2)</option>
                    <option value="1">★☆☆☆☆ (1)</option>
                </select>
            </div>
            <div style="margin-bottom:12px;">
                <label style="font-size:13px;font-weight:600;display:block;margin-bottom:4px;">Review</label>
                <textarea name="review_text" rows="3" placeholder="Share your experience with this product..."
                    style="width:100%;padding:8px 12px;border:1px solid var(--border);border-radius:4px;font-family:inherit;font-size:14px;resize:vertical;"></textarea>
            </div>
            <button type="submit" class="btn btn-primary" style="width:auto;">Submit Review</button>
        </form>
    </div>

    <!-- Display reviews -->
    <?php if (empty($reviews)): ?>
    <p style="color:var(--text-muted);font-size:14px;">No reviews yet. Be the first to review this product.</p>
    <?php else: ?>
    <div>
        <?php foreach ($reviews as $rev): ?>
        <div style="padding:16px;border-bottom:1px solid var(--border);">
            <div style="display:flex;align-items:center;gap:10px;margin-bottom:6px;">
                <span style="font-weight:700;font-size:14px;"><?= htmlspecialchars($rev['username']) ?></span>
                <span style="color:#FF9900;font-size:14px;"><?= stars((float)$rev['rating']) ?></span>
                <span style="font-size:12px;color:var(--text-muted);"><?= htmlspecialchars($rev['created_at']) ?></span>
            </div>
            <div style="font-size:14px;line-height:1.6;">
                <?php if ($diff_xss === 'low'): ?>
                    <?php /* ============================================================
                           STORED XSS OUTPUT — raw, unescaped
                           Script tags stored here execute for every visitor
                           ============================================================ */ ?>
                    <?= $rev['review'] ?>
                <?php else: ?>
                    <?= htmlspecialchars($rev['review'], ENT_QUOTES, 'UTF-8') ?>
                <?php endif; ?>
            </div>
        </div>
        <?php endforeach; ?>
    </div>
    <?php endif; ?>

</div>

<?php else: ?>
<div class="no-results">
    <div class="no-results-icon">🔍</div>
    <h3>Product not found</h3>
    <p>ID: <code><?= htmlspecialchars($id) ?></code></p>
    <?php if ($diff === 'low'): ?>
    <p style="margin-top:8px;font-size:12px;color:var(--text-muted);">
        Try: <code>?id=1 UNION SELECT 1,username,password,4,5,6,7,8,9,10,11 FROM users-- -</code>
    </p>
    <?php endif; ?>
</div>
<?php endif; ?>

<?php if (showQueryLog() && $queryLog && $diff !== 'hard'): ?>
<div class="sql-error-box" style="margin-top:20px;border-left-color:#1565C0;">
    <span class="sql-label">Query Log</span><?= htmlspecialchars($queryLog) ?>
</div>
<?php endif; ?>

<?php include __DIR__ . '/includes/footer.php'; ?>
