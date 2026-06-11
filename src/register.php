<?php
require_once __DIR__ . '/config.php';
require_once __DIR__ . '/includes/db.php';
$pageTitle = 'Create Account';

if (isLoggedIn()) redirect('/');

$conn  = getDB();
$error = null;
$success = null;

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = trim($_POST['username'] ?? '');
    $password = $_POST['password'] ?? '';
    $email    = trim($_POST['email'] ?? '');
    $fullname = trim($_POST['full_name'] ?? '');

    if (!$username || !$password || !$email) {
        $error = "All required fields must be filled.";
    } else {
        // ================================================================
        // REGISTER — Input is properly escaped here (safe INSERT).
        // The malicious username is STORED SAFELY, but will fire later
        // when orders.php re-uses it WITHOUT escaping (second-order).
        // This teaches: safe input != safe re-use.
        // ================================================================
        $u_safe = $conn->real_escape_string($username);
        $p_safe = $conn->real_escape_string($password);
        $e_safe = $conn->real_escape_string($email);
        $f_safe = $conn->real_escape_string($fullname);

        $check = $conn->query("SELECT id FROM users WHERE username = '{$u_safe}' OR email = '{$e_safe}'");
        if ($check && $check->num_rows > 0) {
            $error = "Username or email already taken.";
        } else {
            $insert = $conn->query("INSERT INTO users (username, password, email, full_name, role)
                                    VALUES ('{$u_safe}', '{$p_safe}', '{$e_safe}', '{$f_safe}', 'user')");
            if ($insert) {
                $success = "Account created! You can now sign in.";
            } else {
                $error = "Registration failed: " . $conn->error;
            }
        }
    }
}

$diff = getDifficulty('orders');
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Create Account – VulnMart</title>
    <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="/assets/css/style.css">
    <style>
        body { background: #f3f3f3; display: flex; flex-direction: column; min-height: 100vh; }
        .login-wrap { flex: 1; display: flex; flex-direction: column; align-items: center; padding: 40px 16px; }
        .login-logo { font-size: 28px; font-weight: 700; color: var(--text); text-decoration: none; margin-bottom: 24px; display: flex; align-items: center; gap: 8px; }
        .login-box { background: #fff; border: 1px solid var(--border); border-radius: var(--radius); padding: 28px; width: 100%; max-width: 420px; box-shadow: var(--shadow); }
        .login-box h1 { font-size: 22px; font-weight: 700; margin-bottom: 20px; }
        .login-box .form-group { margin-bottom: 14px; }
        .login-box label { font-size: 13px; font-weight: 600; display: block; margin-bottom: 4px; }
        .login-box input { width: 100%; padding: 8px 10px; border: 1px solid var(--border); border-radius: 4px; font-size: 14px; font-family: inherit; }
        .login-box input:focus { outline: none; border-color: #FF9900; box-shadow: 0 0 0 2px rgba(255,153,0,.2); }
        .login-btn { width: 100%; padding: 10px; background: #FF9900; border: 1px solid #C89411; border-radius: 4px; font-size: 14px; font-weight: 600; cursor: pointer; margin-top: 8px; }
        .login-btn:hover { background: #e88a00; }
        .training-note { font-size: 11px; color: #999; text-align: center; margin-top: 20px; max-width: 420px; }
    </style>
</head>
<body>
<div class="login-wrap">
    <a href="/login.php" class="login-logo">🛒 VulnMart</a>
    <div class="login-box">
        <h1>Create account</h1>

<?php if ($diff === 'low'): ?>
<div class="alert alert-info" style="font-size:12px;">
    💡 <strong>Second-Order Stage 1:</strong> Register with a malicious username.<br>
    The username is safely stored (escaped), but will fire when <code>orders.php</code> re-uses it raw.<br>
    Try username: <code>x' UNION SELECT 1,username,password,4,5 FROM users-- -</code><br>
    After registering, log in and visit <a href="/orders.php" style="color:#007185;">Orders</a>.
</div>
<?php endif; ?>

<?php if ($error): ?>
<div class="alert alert-error"><?= htmlspecialchars($error) ?></div>
<?php endif; ?>

<?php if ($success): ?>
<div class="alert alert-success">
    <?= htmlspecialchars($success) ?> <a href="/login.php" style="color:#1B5E20;">Sign in →</a>
</div>
<?php endif; ?>

<form method="POST" action="/register.php">
        <div class="form-group">
            <label>Username *</label>
            <input type="text" name="username" placeholder="Username" autocomplete="off"
                   value="<?= htmlspecialchars($_POST['username'] ?? '') ?>">
        </div>
        <div class="form-group">
            <label>Email *</label>
            <input type="email" name="email" placeholder="email@example.com"
                   value="<?= htmlspecialchars($_POST['email'] ?? '') ?>">
        </div>
        <div class="form-group">
            <label>Full Name</label>
            <input type="text" name="full_name" placeholder="Your name"
                   value="<?= htmlspecialchars($_POST['full_name'] ?? '') ?>">
        </div>
        <div class="form-group">
            <label>Password *</label>
            <input type="password" name="password" placeholder="Create a password">
        </div>
        <button type="submit" class="btn btn-primary">Create Account</button>
    </form>
        <div style="margin-top:16px;font-size:13px;border-top:1px solid var(--border);padding-top:12px;">
            Already have an account? <a href="/login.php" style="color:#007185;">Sign in</a>
        </div>
    </div>
    <p class="training-note">⚠️ VulnMart — Intentionally Vulnerable Web Application for Web Pentesting Training</p>
</div>
</body>
</html>
