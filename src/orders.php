<?php
require_once __DIR__ . '/config.php';
require_once __DIR__ . '/includes/db.php';
$pageTitle = 'Your Orders';

if (!isLoggedIn()) redirect('/login.php');

$conn      = getDB();
$diff      = getDifficulty('orders');
$orders    = [];
$queryLog  = null;
$sqlError  = null;

// ================================================================
// SECOND-ORDER SQL INJECTION
//
// The attack happens in two stages:
//
// STAGE 1 — Register with a malicious username:
//   Username: john' UNION SELECT 1,username,password,4,5 FROM users-- -
//   This gets stored SAFELY in the DB (register.php uses real_escape_string).
//
// STAGE 2 — View orders. The username is retrieved FROM the DB (trusted),
//   then re-used in a NEW query WITHOUT escaping. The stored payload fires.
//
// This demonstrates: sanitizing input on the way IN doesn't help if you
// don't sanitize data on the way OUT when re-using it in SQL.
// ================================================================

$username = $_SESSION['username']; // Retrieved from session (came from DB)

if ($diff === 'low') {
    // Username from session is used directly — second-order injection fires
    $sql = "SELECT o.id, o.total_amount, o.status, o.created_at,
                   o.shipping_address
            FROM orders o
            JOIN users u ON o.user_id = u.id
            WHERE u.username = '{$username}'
            ORDER BY o.created_at DESC";

    $queryLog = $sql;
    $res = $conn->query($sql);
    if (!$res) {
        $sqlError = $conn->error;
    } else {
        while ($row = $res->fetch_assoc()) $orders[] = $row;
    }

} elseif ($diff === 'medium') {
    // Username escaped before re-use — but order status not sanitized
    $username_escaped = $conn->real_escape_string($username);
    $status_filter = $_GET['status'] ?? '';

    if ($status_filter) {
        // Status param is directly interpolated (injection point at medium)
        $sql = "SELECT o.id, o.total_amount, o.status, o.created_at, o.shipping_address
                FROM orders o JOIN users u ON o.user_id = u.id
                WHERE u.username = '{$username_escaped}' AND o.status = '{$status_filter}'
                ORDER BY o.created_at DESC";
        $queryLog = "[MEDIUM] username escaped. But ?status= filter is raw: status='{$status_filter}'";
        $res = $conn->query($sql);
        if ($res) while ($row = $res->fetch_assoc()) $orders[] = $row;
    } else {
        $stmt = $conn->prepare("SELECT o.id, o.total_amount, o.status, o.created_at, o.shipping_address
                                FROM orders o JOIN users u ON o.user_id = u.id
                                WHERE u.username = ? ORDER BY o.created_at DESC");
        $stmt->bind_param("s", $username_escaped);
        $stmt->execute();
        $res = $stmt->get_result();
        while ($row = $res->fetch_assoc()) $orders[] = $row;
        $queryLog = "[MEDIUM] Safe query used (no status filter). Try ?status= for injection.";
    }

} else {
    // HARD — fully safe
    $user_id = (int)$_SESSION['user_id'];
    $stmt = $conn->prepare("SELECT id, total_amount, status, created_at, shipping_address
                            FROM orders WHERE user_id = ? ORDER BY created_at DESC");
    $stmt->bind_param("i", $user_id);
    $stmt->execute();
    $res = $stmt->get_result();
    while ($row = $res->fetch_assoc()) $orders[] = $row;
    $queryLog = "[HARD] Query uses user_id (integer) from session — not injectable";
}

include __DIR__ . '/includes/header.php';
?>

<div class="page-header">
    <h1>Your Orders</h1>
    <?php if (showHints()): ?>
    <div class="vuln-info">
        <span>🎯 Vulnerability: Second-Order SQLi &nbsp;|&nbsp; Difficulty:</span>
        <?= difficultyBadge($diff) ?>
    </div>
    <?php endif; ?>
</div>

<?php if (showHints() && $diff === 'low'): ?>
<div class="alert alert-warning" style="font-size:12px;">
    🔴 <strong>SECOND-ORDER SQLi:</strong> Register a new account with a malicious username like:<br>
    <code>test' UNION SELECT 1,username,password,4,5 FROM users-- -</code><br>
    Then log in and visit this page. The stored payload fires when your username is re-used in the query.
</div>
<?php elseif (showHints() && $diff === 'medium'): ?>
<div class="alert alert-warning" style="font-size:12px;">
    🟠 <strong>MEDIUM:</strong> Username is now escaped on re-use. Try <code>?status=delivered' OR '1'='1</code>
</div>
<?php endif; ?>

<?php if ($sqlError): ?>
<div class="sql-error-box"><span class="sql-label">MySQL Error</span><?= htmlspecialchars($sqlError) ?></div>
<?php endif; ?>

<h2 style="font-size:18px;font-weight:700;margin-bottom:16px;">
    Orders for: <code style="font-size:14px;background:#f5f5f5;padding:2px 8px;border-radius:4px;"><?= htmlspecialchars($username) ?></code>
</h2>

<?php if (!empty($orders)): ?>
<table class="data-table">
    <thead>
        <tr>
            <th>Order #</th>
            <th>Total</th>
            <th>Status</th>
            <th>Date</th>
            <th>Ship To</th>
        </tr>
    </thead>
    <tbody>
        <?php foreach ($orders as $o): ?>
        <tr>
            <td><strong>#<?= htmlspecialchars((string)$o['id']) ?></strong></td>
            <td>$<?= htmlspecialchars(number_format((float)($o['total_amount'] ?? 0), 2)) ?></td>
            <td>
                <span class="status-badge status-<?= htmlspecialchars($o['status'] ?? '') ?>">
                    <?= htmlspecialchars($o['status'] ?? '—') ?>
                </span>
            </td>
            <td><?= htmlspecialchars($o['created_at'] ?? '—') ?></td>
            <td style="font-size:12px;color:var(--text-muted);"><?= htmlspecialchars($o['shipping_address'] ?? '—') ?></td>
        </tr>
        <?php endforeach; ?>
    </tbody>
</table>
<?php else: ?>
<div class="no-results">
    <div class="no-results-icon">📦</div>
    <h3>No orders found</h3>
    <p>This account has no orders, or your injection payload returned no rows.</p>
</div>
<?php endif; ?>

<?php if (showQueryLog() && $queryLog && $diff !== 'hard'): ?>
<div class="sql-error-box" style="margin-top:16px;">
    <span class="sql-label">Query Log</span><?= htmlspecialchars($queryLog) ?>
</div>
<?php endif; ?>

<?php include __DIR__ . '/includes/footer.php'; ?>
