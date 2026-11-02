<?php
require_once __DIR__ . '/config.php';
require_once __DIR__ . '/includes/db.php';
$pageTitle = 'Order Details';

if (!isLoggedIn()) redirect('/login.php');

$conn       = getDB();
$diff       = getDifficulty('bac');
$order      = null;
$items      = [];
$denied     = false;
$queryLog   = null;

$order_id   = $_GET['id'] ?? '';
$sessionUid = (int)$_SESSION['user_id'];

// ================================================================
// IDOR — INSECURE DIRECT OBJECT REFERENCE (Broken Access Control)
//
// LOW:    Any order id can be viewed. No ownership check at all.
//         Attack: change ?id=1 to ?id=3 to read another customer's
//         order — their name, email, shipping address and items.
//
// MEDIUM: Ownership is checked against a CLIENT-SUPPLIED uid, not
//         the session. Bypass: add &uid=<owner id> to the URL.
//
// HARD:   Ownership enforced against the SESSION user id with a
//         prepared statement. Other users' orders return "denied".
// ================================================================
if ($order_id !== '') {
    if ($diff === 'low') {
        $oid = (int)$order_id;
        $sql = "SELECT o.id, o.user_id, o.total_amount, o.status, o.created_at,
                       o.shipping_address, u.username, u.full_name, u.email
                FROM orders o JOIN users u ON o.user_id = u.id
                WHERE o.id = {$oid}";
        $queryLog = "[LOW] No ownership check — WHERE o.id = {$oid}";
        $res = $conn->query($sql);
        if ($res) $order = $res->fetch_assoc();

    } elseif ($diff === 'medium') {
        $oid        = (int)$order_id;
        $claimedUid = (int)($_GET['uid'] ?? $sessionUid);
        $sql = "SELECT o.id, o.user_id, o.total_amount, o.status, o.created_at,
                       o.shipping_address, u.username, u.full_name, u.email
                FROM orders o JOIN users u ON o.user_id = u.id
                WHERE o.id = {$oid} AND o.user_id = {$claimedUid}";
        $queryLog = "[MEDIUM] Ownership checked against client-supplied uid={$claimedUid} (tamperable)";
        $res = $conn->query($sql);
        if ($res) $order = $res->fetch_assoc();
        if (!$order) $denied = true;

    } else {
        $stmt = $conn->prepare("SELECT o.id, o.user_id, o.total_amount, o.status, o.created_at,
                                       o.shipping_address, u.username, u.full_name, u.email
                                FROM orders o JOIN users u ON o.user_id = u.id
                                WHERE o.id = ? AND o.user_id = ?");
        $stmt->bind_param("ii", $order_id, $sessionUid);
        $stmt->execute();
        $order = $stmt->get_result()->fetch_assoc();
        if (!$order) $denied = true;
        $queryLog = "[HARD] WHERE o.id = ? AND o.user_id = <session> — ownership enforced";
    }

    // Load line items for the resolved order
    if ($order) {
        $oid2 = (int)$order['id'];
        $ir = $conn->query("SELECT oi.quantity, oi.price, p.name
                            FROM order_items oi JOIN products p ON oi.product_id = p.id
                            WHERE oi.order_id = {$oid2}");
        if ($ir) while ($row = $ir->fetch_assoc()) $items[] = $row;
    }
}

include __DIR__ . '/includes/header.php';
?>

<div class="page-header">
    <h1>Order Details</h1>
    <?php if (showHints()): ?>
    <div class="vuln-info">
        <span>🎯 Vulnerability: IDOR — Broken Access Control &nbsp;|&nbsp; Difficulty:</span>
        <?= difficultyBadge($diff) ?>
    </div>
    <?php endif; ?>
</div>

<?php if (showHints() && $diff === 'low'): ?>
<div class="alert alert-warning" style="font-size:12px;">
    🔴 <strong>IDOR:</strong> This page shows any order by id with no ownership check.
    Change <code>?id=1</code> to <code>?id=3</code> to read another customer's order — their name, address and items.
</div>
<?php elseif (showHints() && $diff === 'medium'): ?>
<div class="alert alert-warning" style="font-size:12px;">
    🟠 <strong>MEDIUM:</strong> Ownership is checked against a <em>client-supplied</em> <code>uid</code>.
    Bypass by adding <code>&amp;uid=&lt;owner id&gt;</code> to match the order's real owner.
</div>
<?php endif; ?>

<?php if ($order): ?>
<div style="background:var(--card-bg);border-radius:var(--radius);box-shadow:var(--shadow);padding:24px;max-width:720px;">
    <div style="display:flex;justify-content:space-between;align-items:center;border-bottom:1px solid var(--border);padding-bottom:10px;margin-bottom:14px;">
        <h2 style="font-size:18px;font-weight:700;margin:0;">Order #<?= htmlspecialchars((string)$order['id']) ?></h2>
        <span class="status-badge status-<?= htmlspecialchars($order['status'] ?? '') ?>"><?= htmlspecialchars($order['status'] ?? '—') ?></span>
    </div>
    <table style="width:100%;font-size:14px;margin-bottom:16px;">
        <tr><td style="color:var(--text-muted);padding:6px 0;width:150px;">Customer</td>
            <td style="font-weight:600;"><?= htmlspecialchars($order['full_name'] ?? $order['username']) ?> (<?= htmlspecialchars($order['username']) ?>)</td></tr>
        <tr><td style="color:var(--text-muted);padding:6px 0;">Email</td>
            <td><?= htmlspecialchars($order['email']) ?></td></tr>
        <tr><td style="color:var(--text-muted);padding:6px 0;">Ship to</td>
            <td><?= htmlspecialchars($order['shipping_address'] ?? '—') ?></td></tr>
        <tr><td style="color:var(--text-muted);padding:6px 0;">Placed</td>
            <td><?= htmlspecialchars($order['created_at'] ?? '—') ?></td></tr>
        <tr><td style="color:var(--text-muted);padding:6px 0;">Total</td>
            <td style="font-weight:700;">$<?= htmlspecialchars(number_format((float)$order['total_amount'], 2)) ?></td></tr>
    </table>

    <?php if (!empty($items)): ?>
    <table class="data-table">
        <thead><tr><th>Item</th><th>Qty</th><th>Price</th></tr></thead>
        <tbody>
        <?php foreach ($items as $it): ?>
            <tr>
                <td><?= htmlspecialchars($it['name']) ?></td>
                <td><?= htmlspecialchars((string)$it['quantity']) ?></td>
                <td>$<?= htmlspecialchars(number_format((float)$it['price'], 2)) ?></td>
            </tr>
        <?php endforeach; ?>
        </tbody>
    </table>
    <?php endif; ?>

    <div style="margin-top:16px;"><a href="/orders.php" style="color:#007185;font-size:13px;">← Back to your orders</a></div>
</div>

<?php elseif ($denied): ?>
<div class="no-results">
    <div class="no-results-icon">🔒</div>
    <h3>Access denied</h3>
    <p>This order doesn't belong to your account.</p>
</div>
<?php elseif ($order_id !== ''): ?>
<div class="no-results">
    <div class="no-results-icon">📦</div>
    <h3>Order not found</h3>
    <p>No order with id <?= htmlspecialchars((string)$order_id) ?>.</p>
</div>
<?php else: ?>
<div class="no-results">
    <div class="no-results-icon">📦</div>
    <h3>No order selected</h3>
    <p>Open an order from <a href="/orders.php">your orders</a>.</p>
</div>
<?php endif; ?>

<?php if (showQueryLog() && $queryLog && $diff !== 'hard'): ?>
<div class="sql-error-box" style="margin-top:16px;">
    <span class="sql-label">Access Log</span><?= htmlspecialchars($queryLog) ?>
</div>
<?php endif; ?>

<?php include __DIR__ . '/includes/footer.php'; ?>
