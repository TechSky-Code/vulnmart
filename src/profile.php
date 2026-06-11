<?php
require_once __DIR__ . '/config.php';
require_once __DIR__ . '/includes/db.php';
if (!isLoggedIn()) redirect('/login.php');
$pageTitle = 'Your Account';

$conn         = getDB();
$diff         = getDifficulty('profile');
$diff_csrf    = getDifficulty('csrf');
$diff_upload  = getDifficulty('upload');
$queryLog     = null;
$sqlError     = null;
$userData     = null;
$accessDenied = false;
$updateMsg    = null;
$updateOk     = false;
$uploadMsg    = null;
$uploadOk     = false;

// ================================================================
// PROFILE LOOKUP (IDOR + SQL Injection)
// ================================================================
$lookupUser = $_GET['user'] ?? ($_SESSION['username'] ?? null);

if ($lookupUser) {
    if ($diff === 'low') {
        $sql = "SELECT id, username, email, full_name, address, phone, role, created_at
                FROM users WHERE username = '{$lookupUser}'";
        $queryLog = $sql;
        $res = $conn->query($sql);
        if (!$res) {
            $sqlError = $conn->error;
        } elseif ($res->num_rows > 0) {
            $userData = $res->fetch_assoc();
        }
    } elseif ($diff === 'medium') {
        $escaped = $conn->real_escape_string($lookupUser);
        $sql = "SELECT id, username, email, full_name, address, phone, role, created_at
                FROM users WHERE username = '{$escaped}'";
        $queryLog = "[MEDIUM] real_escape_string applied on ?user=";
        $res = $conn->query($sql);
        if ($res) $userData = $res->fetch_assoc();
    } else {
        // HARD — prepared statement kills SQLi AND an authorization check kills the IDOR:
        // a user may only view their own profile; admins may view anyone.
        if ($lookupUser !== ($_SESSION['username'] ?? null) && !isAdmin()) {
            $accessDenied = true;
            $queryLog = "[HARD] Access denied — IDOR blocked: you may only view your own profile";
        } else {
            $stmt = $conn->prepare("SELECT id, username, email, full_name, address, phone, role, created_at
                                    FROM users WHERE username = ?");
            $stmt->bind_param("s", $lookupUser);
            $stmt->execute();
            $userData = $stmt->get_result()->fetch_assoc();
            $queryLog = "[HARD] Prepared statement + authorization check — SQLi and IDOR both blocked";
        }
    }
}

// ================================================================
// EMAIL CHANGE — CSRF Vulnerability
//
// LOW:  No CSRF token. Any page can POST to this endpoint and
//       change the logged-in user's email silently.
//       Attack: Generate CSRF PoC in Burp Suite → Engagement Tools
//               → Generate CSRF PoC. Open the HTML file in browser.
//               The email changes without the user knowing.
//
// HARD: CSRF token validated. Cross-origin POST rejected.
// ================================================================
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'update_email') {
    $new_email = trim($_POST['email'] ?? '');
    $valid = true;

    if ($diff_csrf !== 'low') {
        $submitted_token = $_POST['csrf_token'] ?? '';
        $session_token   = $_SESSION['csrf_token'] ?? '';
        if (!$session_token || !hash_equals($session_token, $submitted_token)) {
            $valid      = false;
            $updateMsg  = "Invalid CSRF token. Request blocked.";
            $updateOk   = false;
        }
    }

    if ($valid) {
        if (!filter_var($new_email, FILTER_VALIDATE_EMAIL)) {
            $updateMsg = "Please enter a valid email address.";
            $updateOk  = false;
        } else {
            $uid        = (int)$_SESSION['user_id'];
            $safe_email = $conn->real_escape_string($new_email);
            $conn->query("UPDATE users SET email = '{$safe_email}' WHERE id = {$uid}");
            $updateMsg = "Email updated successfully to: " . htmlspecialchars($new_email);
            $updateOk  = true;
            // Refresh userData
            $res2 = $conn->query("SELECT id, username, email, full_name, address, phone, role, created_at FROM users WHERE id = {$uid}");
            if ($res2) $userData = $res2->fetch_assoc();
        }
    }
}

// Generate CSRF token for hard mode
$csrf_token = bin2hex(random_bytes(16));
$_SESSION['csrf_token'] = $csrf_token;

// ================================================================
// PROFILE PHOTO UPLOAD — File Upload Vulnerability
//
// LOW:  Browser accept=".jpg,.png" is the ONLY restriction.
//       Intercepting in Burp and changing filename to .php
//       bypasses it entirely. Server accepts any file type.
//       Uploaded files land in /uploads/ inside web root.
//
// HARD: Server-side MIME check + extension whitelist +
//       random filename. PHP execution blocked by .htaccess.
// ================================================================
$upload_dir     = __DIR__ . '/uploads/';
$upload_web_dir = '/uploads/';

if (!is_dir($upload_dir)) {
    mkdir($upload_dir, 0755, true);
    // Block PHP execution in uploads folder
    file_put_contents($upload_dir . '.htaccess', "php_flag engine off\nOptions -ExecCGI\n");
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_FILES['photo']) && $_FILES['photo']['error'] === UPLOAD_ERR_OK) {
    $file     = $_FILES['photo'];
    $filename = basename($file['name']);
    $tmp      = $file['tmp_name'];
    $ext      = strtolower(pathinfo($filename, PATHINFO_EXTENSION));

    if ($diff_upload === 'low') {
        // VULNERABLE — no server-side validation whatsoever
        // Browser accept=".jpg,.png,.gif" is the only gatekeeper
        // Bypass: intercept upload in Burp, change filename to shell.php
        $dest = $upload_dir . $filename;
        if (move_uploaded_file($tmp, $dest)) {
            $uploadMsg = "Profile photo uploaded: " . htmlspecialchars($filename);
            $uploadOk  = true;
        } else {
            $uploadMsg = "Upload failed — check folder permissions.";
        }

    } else {
        // HARD — server-side MIME + extension + random rename
        $allowed_ext  = ['jpg', 'jpeg', 'png', 'gif'];
        $allowed_mime = ['image/jpeg', 'image/png', 'image/gif'];
        $finfo        = finfo_open(FILEINFO_MIME_TYPE);
        $mime         = finfo_file($finfo, $tmp);
        finfo_close($finfo);

        if (in_array($ext, $allowed_ext) && in_array($mime, $allowed_mime)) {
            $new_name = bin2hex(random_bytes(8)) . '.' . $ext;
            $dest     = $upload_dir . $new_name;
            if (move_uploaded_file($tmp, $dest)) {
                $uploadMsg = "Photo uploaded securely as: " . htmlspecialchars($new_name);
                $uploadOk  = true;
            }
        } else {
            $uploadMsg = "Blocked — invalid file type. Server-side validation rejected: " . htmlspecialchars($filename);
            $uploadOk  = false;
        }
    }
}

// Load current user data if not already loaded
if (!$userData && !$accessDenied && isset($_SESSION['user_id'])) {
    $uid2 = (int)$_SESSION['user_id'];
    $res3 = $conn->query("SELECT id, username, email, full_name, address, phone, role, created_at FROM users WHERE id = {$uid2}");
    if ($res3) $userData = $res3->fetch_assoc();
}

include __DIR__ . '/includes/header.php';
?>

<div class="page-header">
    <h1>Your Account</h1>
    <?php if (showHints()): ?>
    <div class="vuln-info">
        <span>🎯 Vulnerabilities: IDOR &nbsp;|&nbsp; Time-based SQLi &nbsp;|&nbsp; CSRF &nbsp;|&nbsp; File Upload &nbsp;|&nbsp; Difficulty:</span>
        <?= difficultyBadge($diff) ?>
    </div>
    <?php endif; ?>
</div>

<?php if (showHints() && $diff === 'low'): ?>
<div class="alert alert-warning" style="font-size:12px;margin-bottom:12px;">
    🔴 <strong>IDOR:</strong> <code>?user=admin</code> shows any user's profile without authorization.<br>
    🔴 <strong>SQLi:</strong> <code>?user=admin' AND SLEEP(5)-- -</code> confirms blind injection.
</div>
<?php endif; ?>

<?php if ($sqlError): ?>
<div class="sql-error-box"><span class="sql-label">MySQL Error</span><?= htmlspecialchars($sqlError) ?></div>
<?php endif; ?>

<?php if ($userData): ?>

<!-- Profile + Address grid -->
<div style="display:grid;grid-template-columns:1fr 1fr;gap:16px;max-width:800px;">

    <div style="background:var(--card-bg);border-radius:var(--radius);box-shadow:var(--shadow);padding:24px;">
        <h2 style="font-size:16px;font-weight:700;margin-bottom:16px;border-bottom:1px solid var(--border);padding-bottom:8px;">Profile Information</h2>
        <table style="width:100%;font-size:14px;">
            <tr><td style="color:var(--text-muted);padding:6px 0;width:120px;">Username</td>
                <td style="font-weight:600;"><?= htmlspecialchars($userData['username']) ?></td></tr>
            <tr><td style="color:var(--text-muted);padding:6px 0;">Full Name</td>
                <td><?= htmlspecialchars($userData['full_name'] ?? '—') ?></td></tr>
            <tr><td style="color:var(--text-muted);padding:6px 0;">Email</td>
                <td><?= htmlspecialchars($userData['email']) ?></td></tr>
            <tr><td style="color:var(--text-muted);padding:6px 0;">Phone</td>
                <td><?= htmlspecialchars($userData['phone'] ?? '—') ?></td></tr>
            <tr><td style="color:var(--text-muted);padding:6px 0;">Role</td>
                <td><span class="diff-badge" style="background:<?= $userData['role']==='admin'?'#E53935':'#1565C0' ?>"><?= htmlspecialchars($userData['role']) ?></span></td></tr>
            <tr><td style="color:var(--text-muted);padding:6px 0;">Member since</td>
                <td><?= htmlspecialchars($userData['created_at']) ?></td></tr>
        </table>
    </div>

    <div style="background:var(--card-bg);border-radius:var(--radius);box-shadow:var(--shadow);padding:24px;">
        <h2 style="font-size:16px;font-weight:700;margin-bottom:16px;border-bottom:1px solid var(--border);padding-bottom:8px;">Shipping Address</h2>
        <p style="font-size:14px;color:var(--text-muted);line-height:1.8;">
            <?= nl2br(htmlspecialchars($userData['address'] ?? 'No address on file.')) ?>
        </p>
        <div style="margin-top:16px;">
            <a href="/orders.php" style="color:#007185;font-size:13px;">View your orders →</a>
        </div>
    </div>

</div>

<!-- ============================================================
     ACCOUNT SETTINGS — Email change (CSRF) + Photo upload
     Only shown when viewing own profile
     ============================================================ -->
<?php if (!isset($_GET['user']) || $_GET['user'] === $_SESSION['username']): ?>

<div style="max-width:800px;margin-top:20px;display:grid;grid-template-columns:1fr 1fr;gap:16px;">

    <!-- EMAIL CHANGE — CSRF vulnerability -->
    <div style="background:var(--card-bg);border-radius:var(--radius);box-shadow:var(--shadow);padding:24px;">
        <h2 style="font-size:16px;font-weight:700;margin-bottom:6px;border-bottom:1px solid var(--border);padding-bottom:8px;">
            Change Email
        </h2>

        <?php if (showHints()): ?>
        <div style="font-size:11px;padding:6px 10px;border-radius:4px;margin-bottom:10px;
                    background:<?= $diff_csrf==='low'?'#fff3cd':'#d4edda' ?>;
                    border:1px solid <?= $diff_csrf==='low'?'#ffc107':'#c3e6cb' ?>;">
            <?php if ($diff_csrf === 'low'): ?>
                🔴 <strong>CSRF — No token.</strong> Burp: right-click this request → Engagement Tools → Generate CSRF PoC
            <?php else: ?>
                🟢 <strong>CSRF token present.</strong> Cross-origin POST will be rejected.
            <?php endif; ?>
        </div>
        <?php endif; ?>

        <?php if ($updateMsg): ?>
        <div style="padding:8px 12px;border-radius:4px;font-size:13px;margin-bottom:12px;
                    background:<?= $updateOk?'#d4edda':'#f8d7da' ?>;
                    border:1px solid <?= $updateOk?'#c3e6cb':'#f5c6cb' ?>;">
            <?= htmlspecialchars($updateMsg) ?>
        </div>
        <?php endif; ?>

        <form method="POST" action="/profile.php" id="email-form">
            <input type="hidden" name="action" value="update_email">
            <?php if ($diff_csrf !== 'low'): ?>
            <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrf_token) ?>">
            <?php endif; ?>
            <div style="margin-bottom:12px;">
                <label style="font-size:13px;font-weight:600;display:block;margin-bottom:4px;">New Email Address</label>
                <input type="email" name="email" placeholder="new@example.com"
                       value="<?= htmlspecialchars($userData['email']) ?>"
                       style="width:100%;padding:8px 12px;border:1px solid var(--border);border-radius:4px;font-family:inherit;font-size:14px;">
            </div>
            <button type="submit" class="btn btn-primary" style="width:auto;">Update Email</button>
        </form>
    </div>

    <!-- PROFILE PHOTO UPLOAD — File upload vulnerability -->
    <div style="background:var(--card-bg);border-radius:var(--radius);box-shadow:var(--shadow);padding:24px;">
        <h2 style="font-size:16px;font-weight:700;margin-bottom:6px;border-bottom:1px solid var(--border);padding-bottom:8px;">
            Profile Photo
        </h2>

        <?php if (showHints()): ?>
        <div style="font-size:11px;padding:6px 10px;border-radius:4px;margin-bottom:10px;
                    background:<?= $diff_upload==='low'?'#fff3cd':'#d4edda' ?>;
                    border:1px solid <?= $diff_upload==='low'?'#ffc107':'#c3e6cb' ?>;">
            <?php if ($diff_upload === 'low'): ?>
                🔴 <strong>File Upload — No server validation.</strong> Intercept in Burp, change filename to <code>shell.php</code>
            <?php else: ?>
                🟢 <strong>Server-side validation active.</strong> MIME check + extension whitelist + random rename.
            <?php endif; ?>
        </div>
        <?php endif; ?>

        <?php if ($uploadMsg): ?>
        <div style="padding:8px 12px;border-radius:4px;font-size:13px;margin-bottom:12px;
                    background:<?= $uploadOk?'#d4edda':'#f8d7da' ?>;
                    border:1px solid <?= $uploadOk?'#c3e6cb':'#f5c6cb' ?>;">
            <?= htmlspecialchars($uploadMsg) ?>
        </div>
        <?php endif; ?>

        <form method="POST" action="/profile.php" enctype="multipart/form-data">
            <div style="margin-bottom:12px;">
                <label style="font-size:13px;font-weight:600;display:block;margin-bottom:4px;">Upload Photo</label>
                <?php if ($diff_upload === 'low'): ?>
                <input type="file" name="photo" accept=".jpg,.png,.gif"
                       style="font-size:13px;display:block;margin-bottom:4px;">
                <p style="font-size:11px;color:var(--text-muted);">Client-side filter only — bypassable via Burp</p>
                <?php else: ?>
                <input type="file" name="photo" style="font-size:13px;display:block;margin-bottom:4px;">
                <p style="font-size:11px;color:var(--text-muted);">Accepts JPG, PNG, GIF only (server-validated)</p>
                <?php endif; ?>
            </div>
            <button type="submit" class="btn btn-primary" style="width:auto;">Upload Photo</button>
        </form>
    </div>

</div>
<?php endif; ?>

<?php else: ?>
<div class="no-results">
    <?php if ($accessDenied): ?>
    <div class="no-results-icon">🔒</div>
    <h3>Access denied</h3>
    <p>You don't have permission to view this profile. You may only view your own account.</p>
    <?php else: ?>
    <div class="no-results-icon">👤</div>
    <h3>User not found: <?= htmlspecialchars($lookupUser ?? '') ?></h3>
    <?php endif; ?>
</div>
<?php endif; ?>

<!-- Profile lookup form -->
<div style="background:var(--card-bg);border-radius:var(--radius);box-shadow:var(--shadow);padding:20px;max-width:400px;margin-top:16px;">
    <h3 style="font-size:15px;font-weight:700;margin-bottom:12px;">Look up a profile</h3>
    <form method="GET" action="/profile.php" style="display:flex;gap:8px;">
        <input type="text" name="user" placeholder="Enter username"
               value="<?= htmlspecialchars($lookupUser ?? '') ?>"
               style="flex:1;padding:8px 12px;border:1px solid var(--border);border-radius:4px;font-family:inherit;font-size:14px;">
        <button type="submit" class="btn btn-primary" style="width:auto;">Search</button>
    </form>
</div>

<?php if (showQueryLog() && $queryLog && $diff !== 'hard'): ?>
<div class="sql-error-box" style="max-width:800px;margin-top:16px;">
    <span class="sql-label">Query Log</span><?= htmlspecialchars($queryLog) ?>
</div>
<?php endif; ?>

<?php include __DIR__ . '/includes/footer.php'; ?>
