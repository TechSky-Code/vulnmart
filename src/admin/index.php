<?php
require_once __DIR__ . '/../config.php';
require_once __DIR__ . '/../includes/db.php';
$pageTitle = 'Admin Panel';

if (!isAdmin()) redirect('/login.php');

$conn      = getDB();
$diff      = getDifficulty('admin');
$sqlError  = null;
$queryLog  = null;
$searchRes = [];
$logResult = [];

// Fetch activity logs (where header injection data lands)
$logs = $conn->query("SELECT id, ip_address, user_agent, page, action, created_at
                      FROM activity_logs ORDER BY id DESC LIMIT 50");
if ($logs) while ($r = $logs->fetch_assoc()) $logResult[] = $r;

// ================================================================
// ADMIN PANEL — Stacked Queries via product search
//
// LOW: The search input is used directly. Stacked queries possible.
// Attack: laptop'; INSERT INTO users (username,password,email,role)
//         VALUES ('hacker','hacked','h@x.com','admin')-- -
//
// Or: laptop'; UPDATE users SET role='admin' WHERE username='john_doe'-- -
//
// Note: mysqli::query() only executes ONE query at a time by default.
// To demo stacked queries, use mysqli::multi_query() at low difficulty.
// ================================================================

$searchMsg = null;
if (isset($_POST['admin_search'])) {
    $term = $_POST['admin_search'];

    if ($diff === 'low') {
        // multi_query allows stacked queries — injection is fully weaponizable
        $sql = "SELECT * FROM products WHERE name LIKE '%{$term}%'";
        $queryLog = $sql;

        if ($conn->multi_query($sql)) {
            $res = $conn->store_result();
            if ($res) {
                while ($row = $res->fetch_assoc()) $searchRes[] = $row;
                while ($conn->more_results()) $conn->next_result(); // consume remaining
            }
        }
        if ($conn->error) $sqlError = $conn->error;

    } elseif ($diff === 'medium') {
        $term_esc = addslashes($term);
        $sql = "SELECT * FROM products WHERE name LIKE '%{$term_esc}%'";
        $queryLog = "[MEDIUM] addslashes applied. Stacked queries blocked but UNION may still work.";
        $res = $conn->query($sql);
        if ($res) while ($row = $res->fetch_assoc()) $searchRes[] = $row;

    } else {
        $stmt = $conn->prepare("SELECT * FROM products WHERE name LIKE ?");
        $like = "%{$term}%";
        $stmt->bind_param("s", $like);
        $stmt->execute();
        $res = $stmt->get_result();
        while ($row = $res->fetch_assoc()) $searchRes[] = $row;
        $queryLog = "[HARD] Prepared statement — no injection possible";
    }
}

// Re-fetch users after potential injection
$users = [];
$res = $conn->query("SELECT id, username, email, role, created_at FROM users ORDER BY id");
if ($res) while ($r = $res->fetch_assoc()) $users[] = $r;

include __DIR__ . '/../includes/header.php';
?>

<div class="page-header">
    <h1>🛡 Admin Panel</h1>
    <div style="display:flex;align-items:center;gap:12px;">
        <?php if (showHints()): ?>
        <div class="vuln-info">
            <span>🎯 Vulnerability: Stacked Queries &nbsp;|&nbsp; Difficulty:</span>
            <?= difficultyBadge($diff) ?>
        </div>
        <?php endif; ?>
        <a href="/admin/settings.php" style="color:#007185;font-size:13px;white-space:nowrap;">⚙ Settings</a>
    </div>
</div>

<?php if ($diff === 'low'): ?>
<div class="alert alert-warning" style="font-size:12px;">
    🔴 <strong>STACKED QUERIES:</strong> Admin search uses <code>multi_query()</code> — stacked statements execute.<br>
    Try: <code>laptop'; INSERT INTO users (username,password,email,role) VALUES ('pwned','pass','p@x.com','admin')-- -</code><br>
    Or: <code>laptop'; UPDATE users SET password='hacked' WHERE username='admin'-- -</code>
</div>
<?php elseif (showHints() && $diff === 'medium'): ?>
<div class="alert alert-warning" style="font-size:12px;">
    🟠 <strong>MEDIUM:</strong> Stacked queries blocked (single query only). Try UNION: <code>%' UNION SELECT 1,username,password,4,5,6,7,8,9,10,11 FROM users-- -</code>
</div>
<?php endif; ?>

<?php if ($sqlError): ?>
<div class="sql-error-box"><span class="sql-label">MySQL Error</span><?= htmlspecialchars($sqlError) ?></div>
<?php endif; ?>

<!-- Admin Search (Stacked Query target) -->
<div style="background:var(--card-bg);border-radius:var(--radius);box-shadow:var(--shadow);padding:20px;margin-bottom:20px;">
    <h2 style="font-size:16px;font-weight:700;margin-bottom:12px;">Product Search</h2>
    <form method="POST" style="display:flex;gap:8px;margin-bottom:12px;">
        <input type="text" name="admin_search" placeholder="Search products (injection point)"
               value="<?= htmlspecialchars($_POST['admin_search'] ?? '') ?>"
               style="flex:1;padding:8px 12px;border:1px solid var(--border);border-radius:4px;font-family:inherit;font-size:14px;">
        <button type="submit" class="btn btn-primary" style="width:auto;">Search</button>
    </form>
    <?php if (!empty($searchRes)): ?>
    <table class="data-table">
        <thead><tr><th>ID</th><th>Name</th><th>Price</th><th>Data (UNION target)</th></tr></thead>
        <tbody>
            <?php foreach ($searchRes as $r): ?>
            <tr>
                <td><?= htmlspecialchars((string)($r['id'] ?? '')) ?></td>
                <td><?= htmlspecialchars((string)($r['name'] ?? '')) ?></td>
                <td><?= htmlspecialchars(isset($r['price']) ? '$'.number_format((float)$r['price'],2) : '—') ?></td>
                <td style="font-family:monospace;font-size:12px;color:#C62828;"><?= htmlspecialchars((string)($r['description'] ?? $r['email'] ?? '')) ?></td>
            </tr>
            <?php endforeach; ?>
        </tbody>
    </table>
    <?php endif; ?>
    <?php if (showQueryLog() && $queryLog): ?>
    <div class="sql-error-box" style="margin-top:12px;border-left-color:#1565C0;">
        <span class="sql-label">Query Log</span><?= htmlspecialchars($queryLog) ?>
    </div>
    <?php endif; ?>
</div>

<!-- Users Table -->
<div style="margin-bottom:20px;">
    <div class="section-header"><h2 class="section-title">User Accounts</h2></div>
    <table class="data-table">
        <thead><tr><th>ID</th><th>Username</th><th>Email</th><th>Role</th><th>Created</th></tr></thead>
        <tbody>
            <?php foreach ($users as $u): ?>
            <tr>
                <td><?= $u['id'] ?></td>
                <td style="font-family:monospace;font-size:13px;<?= strlen($u['username'])>20?'color:#C62828;':'' ?>"><?= htmlspecialchars($u['username']) ?></td>
                <td><?= htmlspecialchars($u['email']) ?></td>
                <td><span class="diff-badge" style="background:<?= $u['role']==='admin'?'#E53935':'#1565C0' ?>"><?= $u['role'] ?></span></td>
                <td style="font-size:12px;"><?= $u['created_at'] ?></td>
            </tr>
            <?php endforeach; ?>
        </tbody>
    </table>
</div>

<!-- Activity Logs (where header injection data lands) -->
<div>
    <div class="section-header">
        <h2 class="section-title">Activity Logs <span style="font-size:13px;font-weight:400;color:var(--text-muted);">(Header injection data appears here)</span></h2>
    </div>
    <?php if (!empty($logResult)): ?>
    <table class="data-table">
        <thead><tr><th>#</th><th>IP Address</th><th>User Agent / Injected Data</th><th>Page</th><th>Time</th></tr></thead>
        <tbody>
            <?php foreach ($logResult as $log): ?>
            <tr>
                <td><?= $log['id'] ?></td>
                <td style="font-family:monospace;font-size:12px;<?= strlen($log['ip_address'])>20?'color:#C62828;font-weight:600;':'' ?>">
                    <?= htmlspecialchars($log['ip_address']) ?>
                </td>
                <td style="font-size:12px;font-family:monospace;max-width:400px;word-break:break-all;<?= strlen($log['user_agent'])>200?'color:#C62828;':'' ?>">
                    <?= htmlspecialchars($log['user_agent']) ?>
                </td>
                <td><?= htmlspecialchars($log['page']) ?></td>
                <td style="font-size:11px;"><?= $log['created_at'] ?></td>
            </tr>
            <?php endforeach; ?>
        </tbody>
    </table>
    <?php else: ?>
    <div class="alert alert-info">No activity logs yet. Browse category pages to generate logs.</div>
    <?php endif; ?>
</div>

<?php include __DIR__ . '/../includes/footer.php'; ?>
