<?php
require_once __DIR__ . '/config.php';
require_once __DIR__ . '/includes/db.php';

if (isLoggedIn()) redirect('/');

$diff     = getDifficulty('login');
$error    = null;
$queryLog = null;

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = $_POST['username'] ?? '';
    $password = $_POST['password'] ?? '';

    if ($diff === 'low') {
        $sql = "SELECT * FROM users WHERE username = '{$username}' AND password = MD5('{$password}')";
        $queryLog = $sql;
        $res = getDB()->query($sql);
        if ($res && $res->num_rows > 0) {
            $user = $res->fetch_assoc();
            $_SESSION['user_id']  = $user['id'];
            $_SESSION['username'] = $user['username'];
            $_SESSION['role']     = $user['role'];
            redirect('/');
        } else {
            $sqlError = getDB()->error;
            if ($sqlError) {
                $error = "MySQL Error: " . htmlspecialchars($sqlError);
            } else {
                // ================================================================
                // USERNAME ENUMERATION VULNERABILITY — Low difficulty only
                // Check if username exists separately to return different messages
                // Attack: Try "wronguser" → "No account found with that username."
                //         Try "admin" with wrong password → "Incorrect password."
                // This lets attackers confirm valid usernames before brute forcing
                // Medium and Hard always return generic message — correct behavior
                // ================================================================
                $check_sql = "SELECT id FROM users WHERE username = '{$username}'";
                $check_res = getDB()->query($check_sql);
                if (!$check_res || $check_res->num_rows === 0) {
                    $error = "No account found with that username.";
                } else {
                    $error = "Incorrect password. Please try again.";
                }
            }
        }

    } elseif ($diff === 'medium') {
        $pwd_hash = md5($password);
        $sql = "SELECT * FROM users WHERE username = '{$username}' AND password = '{$pwd_hash}'";
        $queryLog = "[MEDIUM] password = MD5(input). Username field still injectable.";
        $res = getDB()->query($sql);
        if ($res && $res->num_rows > 0) {
            $user = $res->fetch_assoc();
            $_SESSION['user_id']  = $user['id'];
            $_SESSION['username'] = $user['username'];
            $_SESSION['role']     = $user['role'];
            redirect('/');
        } else {
            $error = "Invalid username or password.";
        }

    } else {
        $stmt = getDB()->prepare("SELECT * FROM users WHERE username = ? AND password = MD5(?)");
        $stmt->bind_param("ss", $username, $password);
        $stmt->execute();
        $res = $stmt->get_result();
        if ($res && $res->num_rows > 0) {
            $user = $res->fetch_assoc();
            $_SESSION['user_id']  = $user['id'];
            $_SESSION['username'] = $user['username'];
            $_SESSION['role']     = $user['role'];
            redirect('/');
        } else {
            $error = "Invalid username or password.";
        }
        $queryLog = "[HARD] Prepared statement used — no injection possible";
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Sign In – VulnMart</title>
    <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="/assets/css/style.css">
    <style>
        body { background: #f3f3f3; display: flex; flex-direction: column; min-height: 100vh; }
        .login-wrap { flex: 1; display: flex; flex-direction: column; align-items: center; padding: 40px 16px; }
        .login-logo { font-size: 28px; font-weight: 700; color: var(--text); text-decoration: none; margin-bottom: 24px; display: flex; align-items: center; gap: 8px; }
        .login-box { background: #fff; border: 1px solid var(--border); border-radius: var(--radius); padding: 28px; width: 100%; max-width: 360px; box-shadow: var(--shadow); }
        .login-box h1 { font-size: 22px; font-weight: 700; margin-bottom: 20px; }
        .login-box .form-group { margin-bottom: 14px; }
        .login-box label { font-size: 13px; font-weight: 600; display: block; margin-bottom: 4px; }
        .login-box input { width: 100%; padding: 8px 10px; border: 1px solid var(--border); border-radius: 4px; font-size: 14px; font-family: inherit; }
        .login-box input:focus { outline: none; border-color: #FF9900; box-shadow: 0 0 0 2px rgba(255,153,0,.2); }
        .login-btn { width: 100%; padding: 10px; background: #FF9900; border: 1px solid #C89411; border-radius: 4px; font-size: 14px; font-weight: 600; cursor: pointer; margin-top: 8px; }
        .login-btn:hover { background: #e88a00; }
        .divider { border: none; border-top: 1px solid var(--border); margin: 20px 0; }
        .register-box { background: #fff; border: 1px solid var(--border); border-radius: var(--radius); padding: 16px; width: 100%; max-width: 360px; text-align: center; margin-top: 14px; font-size: 13px; }
        .register-box a { color: #007185; }
        .training-note { font-size: 11px; color: #999; text-align: center; margin-top: 20px; max-width: 360px; }
    </style>
</head>
<body>
<div class="login-wrap">

    <a href="/login.php" class="login-logo">🛒 VulnMart</a>

    <div class="login-box">
        <h1>Sign In</h1>

        <?php if ($error): ?>
        <div style="background:#FFEBEE;border:1px solid #EF9A9A;color:#C62828;padding:10px 12px;border-radius:4px;font-size:13px;margin-bottom:14px;">
            <?= htmlspecialchars($error) ?>
        </div>
        <?php endif; ?>

        <?php if (showHints() && $diff !== 'hard'): ?>
        <div class="alert alert-warning" style="font-size:12px;margin-bottom:14px;">
            🔴 <strong>LOW — USERNAME ENUMERATION:</strong> Different errors for wrong user vs wrong password<br>
            🔴 <strong>LOW — AUTH BYPASS:</strong> Try username: <code>admin'-- -</code> (any password)<br>
            Or: <code>' OR '1'='1'-- -</code>
        </div>
        <?php endif; ?>

        <form method="POST">
            <div class="form-group">
                <label for="username">Email or username</label>
                <input type="text" id="username" name="username" autocomplete="username"
                       value="<?= isset($_POST['username']) ? htmlspecialchars($_POST['username']) : '' ?>">
            </div>
            <div class="form-group">
                <label for="password">Password</label>
                <input type="password" id="password" name="password" autocomplete="current-password">
            </div>
            <button type="submit" class="login-btn">Sign in</button>
        </form>

        <?php if (showQueryLog() && $queryLog && $diff !== 'hard'): ?>
        <div class="sql-error-box" style="margin-top:14px;">
            <span class="sql-label">Query Log</span><?= htmlspecialchars($queryLog) ?>
        </div>
        <?php endif; ?>

        <div class="divider"></div>
        <p style="font-size:12px;text-align:center;">
            New customer? <a href="/register.php" style="color:#007185;">Create account</a>
        </p>
    </div>

    <div class="register-box">
        <strong>Test accounts:</strong> admin / admin123 &nbsp;|&nbsp; john_doe / password123
    </div>

    <p class="training-note">⚠️ VulnMart — Intentionally Vulnerable Web Application for Web Pentesting Training</p>

</div>
</body>
</html>
