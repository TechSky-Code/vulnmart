<?php
require_once __DIR__ . '/config.php';
require_once __DIR__ . '/includes/db.php';
if (!isLoggedIn()) redirect('/login.php');
$pageTitle = 'Search Results';

$conn      = getDB();
$diff      = getDifficulty('search');
$diff_xss  = getDifficulty('xss');
$q         = $_GET['q'] ?? '';
$results   = [];
$sqlError  = null;
$queryLog  = null;

if ($q !== '') {

    // ================================================================
    // LOW — Raw input, errors visible. UNION attack fully works.
    // Attack example: %' UNION SELECT 1,username,password,4,5,6,7,8,9,10,11 FROM users-- -
    // ================================================================
    if ($diff === 'low') {
        $sql = "SELECT * FROM products WHERE name LIKE '%{$q}%' OR description LIKE '%{$q}%'";
        $queryLog = $sql;
        $res = $conn->query($sql);
        if (!$res) {
            $sqlError = $conn->error;
        } else {
            while ($row = $res->fetch_assoc()) $results[] = $row;
        }

    // ================================================================
    // MEDIUM — addslashes() applied, errors suppressed.
    // ================================================================
    } elseif ($diff === 'medium') {
        $q_filtered = addslashes($q);
        $sql = "SELECT * FROM products WHERE name LIKE '%{$q_filtered}%' OR description LIKE '%{$q_filtered}%'";
        $queryLog = "[MEDIUM] Input sanitized with addslashes()";
        $res = $conn->query($sql);
        if ($res) while ($row = $res->fetch_assoc()) $results[] = $row;

    // ================================================================
    // HARD — Prepared statements, input sanitized.
    // ================================================================
    } else {
        $q_clean = preg_replace('/[^a-zA-Z0-9 ]/', '', $q);
        $stmt = $conn->prepare("SELECT * FROM products WHERE name LIKE ? OR description LIKE ?");
        $like = "%{$q_clean}%";
        $stmt->bind_param("ss", $like, $like);
        $stmt->execute();
        $res = $stmt->get_result();
        while ($row = $res->fetch_assoc()) $results[] = $row;
        $queryLog = "[HARD] Prepared statement used — input sanitized to alphanumeric only";
    }
}

function stars(float $r): string {
    return str_repeat('★', (int)$r) . str_repeat('☆', 5-(int)$r);
}

include __DIR__ . '/includes/header.php';
?>

<div class="page-header">
    <h1>Search Results</h1>
    <?php if (showHints()): ?>
    <div class="vuln-info">
        <span>🎯 Vulnerabilities: Error-based + UNION SQLi &nbsp;|&nbsp; Reflected XSS &nbsp;|&nbsp; Difficulty:</span>
        <?= difficultyBadge($diff) ?>
    </div>
    <?php endif; ?>
</div>

<!-- SQL Error (LOW difficulty) -->
<?php if ($sqlError): ?>
<div class="sql-error-box">
    <span class="sql-label">MySQL Error</span>
    <?= htmlspecialchars($sqlError) ?>
</div>
<?php endif; ?>

<?php if ($q !== ''): ?>
<div class="search-header">
    <?php if ($diff_xss === 'low'): ?>
        <?php /* ============================================================
               REFLECTED XSS — search term echoed raw at Low difficulty.
               Attack: <script>alert('XSS')</script>
               Attack: <script>alert(document.cookie)</script>
               Attack: <img src=x onerror="alert('XSS')">
               At Hard: htmlspecialchars() prevents execution.
               ============================================================ */ ?>
        Results for: <strong>"<?= $q ?>"</strong>
    <?php else: ?>
        Results for: <strong>"<?= htmlspecialchars($q) ?>"</strong>
    <?php endif; ?>
    <span>(<?= count($results) ?> result<?= count($results) !== 1 ? 's' : '' ?>)</span>
</div>

<?php if (showHints() && $diff === 'low'): ?>
<div class="alert alert-warning" style="font-size:12px;">
    🔴 <strong>XSS:</strong> The search term is echoed raw into the page.<br>
    Try: <code>&lt;script&gt;alert('XSS')&lt;/script&gt;</code><br>
    Cookie theft: <code>&lt;script&gt;alert(document.cookie)&lt;/script&gt;</code>
</div>
<?php endif; ?>
<?php endif; ?>

<?php if (!empty($results)): ?>
<div class="product-grid">
    <?php foreach ($results as $p): ?>
    <?php $isProduct = isset($p['price']) && is_numeric($p['price']); ?>
    <?php if ($isProduct): ?>
    <div class="product-card">
        <a href="/product.php?id=<?= $p['id'] ?>" style="text-decoration:none;color:inherit;display:block;">
        <div class="product-image" style="background:<?= htmlspecialchars($p['image_color'] ?? '#EEE') ?>22">
            📦
            <?php if (!empty($p['badge'])): ?>
            <span class="product-badge"><?= htmlspecialchars($p['badge']) ?></span>
            <?php endif; ?>
        </div>
        <div class="product-info">
            <div class="product-name"><?= htmlspecialchars($p['name']) ?></div>
            <div class="product-stars"><?= stars((float)($p['rating'] ?? 0)) ?></div>
            <div class="product-price">
                <span class="price-current">$<?= number_format((float)$p['price'], 2) ?></span>
            </div>
        </div>
        </a>
        <form method="POST" action="/cart.php" style="padding:0 12px 12px;">
            <input type="hidden" name="action" value="add">
            <input type="hidden" name="product_id" value="<?= $p['id'] ?>">
            <input type="hidden" name="back" value="/search.php?q=<?= urlencode($q) ?>">
            <button type="submit" class="add-to-cart-btn">Add to Cart</button>
        </form>
    </div>
    <?php else: ?>
    <div class="product-card" style="border:2px solid #E53935;">
        <div class="product-image" style="background:#ffebee;font-size:14px;padding:16px;word-break:break-all;overflow:auto;text-align:left;align-items:flex-start;">
            <strong style="color:#E53935;font-family:monospace;font-size:11px;display:block;margin-bottom:8px;">⚠ INJECTED ROW</strong>
            <?php foreach ($p as $col => $val): ?>
            <div style="font-family:monospace;font-size:12px;margin-bottom:3px;color:#111;">
                <span style="color:#888;"><?= htmlspecialchars($col) ?>:</span>
                <span style="color:#C62828;font-weight:600;"><?= htmlspecialchars((string)$val) ?></span>
            </div>
            <?php endforeach; ?>
        </div>
        <div class="product-info">
            <div class="product-name" style="color:#E53935;font-family:monospace;font-size:12px;">Data extracted via UNION SELECT</div>
        </div>
    </div>
    <?php endif; ?>
    <?php endforeach; ?>
</div>

<?php elseif ($q !== ''): ?>
<div class="no-results">
    <div class="no-results-icon">🔍</div>
    <h3>No results for "<?= htmlspecialchars($q) ?>"</h3>
    <p>Try different keywords, or check the injection syntax.</p>
</div>
<?php else: ?>
<div class="no-results">
    <div class="no-results-icon">🛍</div>
    <h3>Search VulnMart</h3>
    <p>Enter a search term or try an injection payload.</p>
</div>
<?php endif; ?>

<?php if (showQueryLog() && $diff !== 'hard' && $queryLog): ?>
<div class="sql-error-box" style="margin-top:20px;border-left-color:#1565C0;">
    <span class="sql-label">Query Log</span>
    <?= htmlspecialchars($queryLog) ?>
</div>
<?php endif; ?>

<?php include __DIR__ . '/includes/footer.php'; ?>
