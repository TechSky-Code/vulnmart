<?php
require_once __DIR__ . '/../config.php';
require_once __DIR__ . '/../includes/db.php';
$pageTitle = 'User Management';

if (!isLoggedIn()) redirect('/login.php');

$diff = getDifficulty('bac');

// ================================================================
// FORCED BROWSING / MISSING FUNCTION-LEVEL ACCESS CONTROL
// (Broken Access Control — vertical privilege escalation)
//
// LOW:    No role check. Any logged-in user reaches this admin page
//         directly and can promote themselves to admin. The link is
//         hidden from normal users — but hiding is not protecting.
//
// MEDIUM: Trusts a CLIENT-CONTROLLED signal instead of the session
//         role. Bypass with a cookie role=admin, or append ?admin=1.
//
// HARD:   Proper server-side isAdmin() check — forced browsing blocked
//         with a redirect, exactly like the other admin pages.
// ================================================================
if ($diff === 'hard') {
    if (!isAdmin()) redirect('/login.php');
} elseif ($diff === 'medium') {
    $clientRole = $_COOKIE['role'] ?? ($_GET['admin'] ?? '');
    if ($clientRole !== 'admin' && $clientRole !== '1') redirect('/');
}
// low: no check beyond isLoggedIn()

$conn    = getDB();
$message = null;

// Privileged actions — reachable by anyone who passed the gate above
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (isset($_POST['promote'])) {
        $uid = (int)$_POST['promote'];
        $conn->query("UPDATE users SET role='admin' WHERE id={$uid}");
        if ($uid === (int)$_SESSION['user_id']) $_SESSION['role'] = 'admin';
        $message = "User #{$uid} promoted to ADMIN.";
    } elseif (isset($_POST['demote'])) {
        $uid = (int)$_POST['demote'];
        $conn->query("UPDATE users SET role='user' WHERE id={$uid}");
        if ($uid === (int)$_SESSION['user_id']) $_SESSION['role'] = 'user';
        $message = "User #{$uid} set to USER.";
    } elseif (isset($_POST['delete'])) {
        $uid = (int)$_POST['delete'];
        if ($uid === 1) {
            $message = "Refusing to delete the primary admin account.";
        } else {
            $conn->query("DELETE FROM users WHERE id={$uid}");
            $message = "User #{$uid} deleted.";
        }
    }
}

$users = [];
$res = $conn->query("SELECT id, username, email, role, created_at FROM users ORDER BY id");
if ($res) while ($r = $res->fetch_assoc()) $users[] = $r;

include __DIR__ . '/../includes/header.php';
?>

<div class="page-header">
    <h1>User Management</h1>
    <?php if (showHints()): ?>
    <div class="vuln-info">
        <span>🎯 Vulnerability: Forced Browsing / Function-Level Access Control &nbsp;|&nbsp; Difficulty:</span>
        <?= difficultyBadge($diff) ?>
    </div>
    <?php endif; ?>
</div>

<?php if (showHints() && $diff === 'low'): ?>
<div class="alert alert-warning" style="font-size:12px;">
    🔴 <strong>FORCED BROWSING:</strong> This admin page has no role check. Any logged-in user can open
    <code>/admin/users.php</code> directly and <strong>promote themselves to admin</strong>. Hiding the link isn't protecting the page.
</div>
<?php elseif (showHints() && $diff === 'medium'): ?>
<div class="alert alert-warning" style="font-size:12px;">
    🟠 <strong>MEDIUM:</strong> The page trusts a client-controlled signal. Bypass with a cookie
    <code>role=admin</code>, or append <code>?admin=1</code> to the URL.
</div>
<?php endif; ?>

<?php if ($message): ?>
<div class="alert alert-success"><?= htmlspecialchars($message) ?></div>
<?php endif; ?>

<div class="section-header"><h2 class="section-title">All User Accounts</h2></div>
<table class="data-table">
    <thead><tr><th>ID</th><th>Username</th><th>Email</th><th>Role</th><th>Created</th><th>Actions</th></tr></thead>
    <tbody>
    <?php foreach ($users as $u): ?>
        <tr>
            <td><?= (int)$u['id'] ?></td>
            <td style="font-family:monospace;font-size:13px;">
                <?= htmlspecialchars($u['username']) ?><?php if ((int)$u['id'] === (int)$_SESSION['user_id']): ?> <strong>(you)</strong><?php endif; ?>
            </td>
            <td><?= htmlspecialchars($u['email']) ?></td>
            <td><span class="diff-badge" style="background:<?= $u['role']==='admin'?'#E53935':'#1565C0' ?>"><?= htmlspecialchars($u['role']) ?></span></td>
            <td style="font-size:12px;"><?= htmlspecialchars($u['created_at']) ?></td>
            <td>
                <div style="display:flex;gap:6px;">
                    <?php if ($u['role'] !== 'admin'): ?>
                    <form method="POST"><input type="hidden" name="promote" value="<?= (int)$u['id'] ?>"><button class="btn btn-primary btn-sm">Make admin</button></form>
                    <?php else: ?>
                    <form method="POST"><input type="hidden" name="demote" value="<?= (int)$u['id'] ?>"><button class="btn btn-sm" style="background:#888;color:#fff;">Set user</button></form>
                    <?php endif; ?>
                    <form method="POST" onsubmit="return confirm('Delete this user?');"><input type="hidden" name="delete" value="<?= (int)$u['id'] ?>"><button class="btn btn-sm" style="background:#C62828;color:#fff;">Delete</button></form>
                </div>
            </td>
        </tr>
    <?php endforeach; ?>
    </tbody>
</table>

<?php if (showQueryLog() && $diff !== 'hard'): ?>
<div class="sql-error-box" style="margin-top:16px;">
    <span class="sql-label">Access Log</span><?= htmlspecialchars("[" . strtoupper($diff) . "] /admin/users.php reached by session user_id=" . ((int)$_SESSION['user_id']) . " role=" . ($_SESSION['role'] ?? 'user')) ?>
</div>
<?php endif; ?>

<?php include __DIR__ . '/../includes/footer.php'; ?>
