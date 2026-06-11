<?php
require_once __DIR__ . '/../config.php';
require_once __DIR__ . '/../includes/db.php';
$pageTitle = 'Training Settings';

if (!isAdmin()) redirect('/login.php');

$conn    = getDB();
$message = null;

// Handle difficulty update
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['page'], $_POST['difficulty'])) {
    $page = $conn->real_escape_string($_POST['page']);
    $diff = $conn->real_escape_string($_POST['difficulty']);
    if (in_array($diff, ['low', 'medium', 'hard'])) {
        $conn->query("UPDATE settings SET difficulty = '{$diff}' WHERE page = '{$page}'");
        $message = "Updated {$page} to " . strtoupper($diff) . ".";
    }
}

// Handle toggle updates
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['toggle'])) {
    $col = $_POST['toggle'];
    if (in_array($col, ['show_hints', 'show_query_log'])) {
        $val = isset($_POST['toggle_value']) && $_POST['toggle_value'] === '1' ? 1 : 0;
        $conn->query("UPDATE settings SET `{$col}` = {$val} WHERE page = 'global'");
        $label = $col === 'show_hints' ? 'Vulnerability Hints' : 'Query Log';
        $message = "{$label} turned " . ($val ? 'ON' : 'OFF') . ".";
    }
}

// Handle reset all
if (isset($_POST['reset_all'])) {
    $conn->query("UPDATE settings SET difficulty = 'low'");
    $message = "All pages reset to LOW difficulty.";
}

// Handle clear logs
if (isset($_POST['clear_logs'])) {
    $conn->query("DELETE FROM activity_logs");
    $message = "Activity logs cleared.";
}

// Fetch current settings
$settings = [];
$res = $conn->query("SELECT * FROM settings ORDER BY page");
if ($res) while ($r = $res->fetch_assoc()) $settings[$r['page']] = $r;

$hints_on = (int)($settings['global']['show_hints']     ?? 1);
$qlog_on  = (int)($settings['global']['show_query_log'] ?? 1);

$vuln_info = [
    'search'   => ['icon'=>'🔍', 'title'=>'Search Page',        'type'=>'GET ?q=',         'technique'=>'Error-based + UNION-based'],
    'product'  => ['icon'=>'📦', 'title'=>'Product Detail',     'type'=>'GET ?id=',         'technique'=>'UNION-based + Boolean Blind'],
    'login'    => ['icon'=>'🔐', 'title'=>'Login Page',         'type'=>'POST username=',   'technique'=>'Authentication Bypass'],
    'profile'  => ['icon'=>'👤', 'title'=>'Profile Page',       'type'=>'GET ?user=',       'technique'=>'Time-based Blind'],
    'orders'   => ['icon'=>'📋', 'title'=>'Orders Page',        'type'=>'Session username', 'technique'=>'Second-Order SQLi'],
    'category' => ['icon'=>'🏷', 'title'=>'Category Page',      'type'=>'X-Forwarded-For',  'technique'=>'Header-based Injection'],
    'admin'    => ['icon'=>'🛡', 'title'=>'Admin Panel Search', 'type'=>'POST search=',     'technique'=>'Stacked Queries'],
    'fileops'  => ['icon'=>'📁', 'title'=>'File Operations',     'type'=>'GET receipt=',     'technique'=>'LOAD_FILE + INTO OUTFILE'],
    'api_search'=>['icon'=>'🔌', 'title'=>'API Search Endpoint', 'type'=>'POST JSON body',   'technique'=>'JSON Injection'],
    'recommend' =>['icon'=>'🍪', 'title'=>'Recommendations',     'type'=>'Cookie header',     'technique'=>'Cookie-based Injection'],
    'xss'       =>['icon'=>'💥', 'title'=>'Product Reviews',     'type'=>'GET search= / POST', 'technique'=>'XSS (Reflected + Stored)'],
    'csrf'      =>['icon'=>'🔄', 'title'=>'Account Settings',    'type'=>'POST (no token)',    'technique'=>'CSRF'],
    'upload'    =>['icon'=>'📎', 'title'=>'File Upload',          'type'=>'POST multipart',     'technique'=>'Insecure File Upload'],
    'checkout'  =>['icon'=>'💳', 'title'=>'Checkout',            'type'=>'POST hidden fields',  'technique'=>'Business Logic Flaws'],
];

include __DIR__ . '/../includes/header.php';
?>

<style>
.toggle-row {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 18px 20px;
    border-bottom: 1px solid #eee;
}
.toggle-row:last-child { border-bottom: none; }
.toggle-label h3 { font-size: 15px; font-weight: 700; margin: 0 0 3px; }
.toggle-label p  { font-size: 12px; color: #666; margin: 0; max-width: 520px; }
.toggle-wrap { display: flex; align-items: center; gap: 10px; flex-shrink: 0; }
.toggle-switch { position: relative; display: inline-block; width: 52px; height: 28px; }
.toggle-switch input { opacity: 0; width: 0; height: 0; }
.toggle-slider {
    position: absolute; cursor: pointer; inset: 0;
    background: #ccc; border-radius: 28px; transition: .3s;
}
.toggle-slider:before {
    content: ''; position: absolute;
    width: 20px; height: 20px; left: 4px; bottom: 4px;
    background: #fff; border-radius: 50%; transition: .3s;
}
.toggle-switch input:checked + .toggle-slider            { background: #FF9900; }
.toggle-switch input:checked + .toggle-slider:before     { transform: translateX(24px); }
.toggle-status-on  { font-size: 12px; font-weight: 700; color: #FF9900; }
.toggle-status-off { font-size: 12px; font-weight: 700; color: #aaa; }
</style>

<div class="page-header">
    <h1>Training Settings</h1>
    <div class="vuln-info">
        <span>Configure difficulty levels and display options for VulnMart &nbsp;|&nbsp; <strong>v<?= htmlspecialchars(VULNMART_VERSION) ?></strong></span>
    </div>
</div>

<?php if ($message): ?>
<div class="alert alert-success"><?= htmlspecialchars($message) ?></div>
<?php endif; ?>

<!-- DISPLAY TOGGLES -->
<div style="background:var(--card-bg);border-radius:var(--radius);box-shadow:var(--shadow);margin-bottom:24px;">
    <div style="padding:16px 20px;border-bottom:1px solid #eee;">
        <h2 style="font-size:15px;font-weight:700;margin:0 0 2px;">Display Options</h2>
        <p style="font-size:12px;color:#666;margin:0;">Turn both off for a clean, realistic site with no training aids visible.</p>
    </div>

    <!-- Hints toggle -->
    <div class="toggle-row">
        <div class="toggle-label">
            <h3>Vulnerability Hints</h3>
            <p>Shows the hint banner on each page — explains the vulnerability type, injection point, and a ready-to-use attack example.</p>
        </div>
        <form method="POST">
            <input type="hidden" name="toggle" value="show_hints">
            <input type="hidden" name="toggle_value" value="<?= $hints_on ? '0' : '1' ?>">
            <div class="toggle-wrap">
                <label class="toggle-switch">
                    <input type="checkbox" <?= $hints_on ? 'checked' : '' ?> onchange="this.closest('form').submit()">
                    <span class="toggle-slider"></span>
                </label>
                <span class="<?= $hints_on ? 'toggle-status-on' : 'toggle-status-off' ?>">
                    <?= $hints_on ? 'ON' : 'OFF' ?>
                </span>
            </div>
        </form>
    </div>

    <!-- Query Log toggle -->
    <div class="toggle-row">
        <div class="toggle-label">
            <h3>Query Log</h3>
            <p>Shows the exact SQL query that executed at the bottom of each page — lets students see what their input produced in the database in real time.</p>
        </div>
        <form method="POST">
            <input type="hidden" name="toggle" value="show_query_log">
            <input type="hidden" name="toggle_value" value="<?= $qlog_on ? '0' : '1' ?>">
            <div class="toggle-wrap">
                <label class="toggle-switch">
                    <input type="checkbox" <?= $qlog_on ? 'checked' : '' ?> onchange="this.closest('form').submit()">
                    <span class="toggle-slider"></span>
                </label>
                <span class="<?= $qlog_on ? 'toggle-status-on' : 'toggle-status-off' ?>">
                    <?= $qlog_on ? 'ON' : 'OFF' ?>
                </span>
            </div>
        </form>
    </div>

    <!-- Mode label -->
    <div style="padding:12px 20px;background:#f9f9f9;border-radius:0 0 var(--radius) var(--radius);font-size:12px;color:#555;">
        <?php if ($hints_on && $qlog_on): ?>
            ✅ <strong>Training Mode</strong> — All aids visible. Best for beginner walkthroughs.
        <?php elseif (!$hints_on && !$qlog_on): ?>
            🌐 <strong>Realistic Mode</strong> — Clean site, no training aids. Best for advanced students and live demos.
        <?php elseif ($hints_on && !$qlog_on): ?>
            📖 <strong>Guided Mode</strong> — Hints visible, query log hidden. Good for conceptual explanations.
        <?php else: ?>
            🔬 <strong>Debug Mode</strong> — Query log visible, hints hidden. Good for technical deep-dives.
        <?php endif; ?>
    </div>
</div>

<!-- DIFFICULTY LEGEND -->
<div style="background:var(--card-bg);border-radius:var(--radius);box-shadow:var(--shadow);padding:20px;margin-bottom:20px;">
    <h2 style="font-size:15px;font-weight:700;margin-bottom:12px;">Difficulty Levels</h2>
    <div style="display:grid;grid-template-columns:repeat(3,1fr);gap:12px;font-size:13px;">
        <div style="padding:12px;background:#FFEBEE;border-radius:6px;border-left:4px solid #E53935;">
            <strong style="color:#E53935;">LOW</strong><br>
            Raw input, no filtering. Errors visible. Full attack surface exposed.
        </div>
        <div style="padding:12px;background:#FFF8E1;border-radius:6px;border-left:4px solid #FB8C00;">
            <strong style="color:#FB8C00;">MEDIUM</strong><br>
            Basic filtering (addslashes / intval). Errors hidden. Requires evasion.
        </div>
        <div style="padding:12px;background:#E8F5E9;border-radius:6px;border-left:4px solid #43A047;">
            <strong style="color:#43A047;">HARD</strong><br>
            Prepared statements. No injection possible. Use for secure solution demo.
        </div>
    </div>
</div>

<!-- PER-PAGE DIFFICULTY -->
<div class="admin-grid">
    <?php foreach ($vuln_info as $page => $info): ?>
    <?php $current = $settings[$page]['difficulty'] ?? 'low'; ?>
    <div class="admin-card">
        <div style="display:flex;align-items:center;gap:8px;margin-bottom:6px;">
            <span style="font-size:20px;"><?= $info['icon'] ?></span>
            <h3><?= $info['title'] ?></h3>
            <?= difficultyBadge($current) ?>
        </div>
        <div class="admin-card-meta">
            <span style="background:#f0f0f0;padding:2px 6px;border-radius:3px;font-family:monospace;font-size:11px;"><?= $info['type'] ?></span>
            &nbsp;<?= $info['technique'] ?>
        </div>
        <form method="POST" style="display:flex;gap:8px;align-items:center;">
            <input type="hidden" name="page" value="<?= htmlspecialchars($page) ?>">
            <select name="difficulty" class="diff-select" style="margin:0;flex:1;">
                <option value="low"    <?= $current==='low'    ?'selected':'' ?>>Low — Raw (No Filter)</option>
                <option value="medium" <?= $current==='medium' ?'selected':'' ?>>Medium — Basic Filter</option>
                <option value="hard"   <?= $current==='hard'   ?'selected':'' ?>>Hard — Prepared Stmt</option>
            </select>
            <button type="submit" class="btn btn-primary btn-sm">Set</button>
        </form>
    </div>
    <?php endforeach; ?>
</div>

<!-- QUICK ACTIONS -->
<div style="background:var(--card-bg);border-radius:var(--radius);box-shadow:var(--shadow);padding:20px;margin-top:20px;">
    <h2 style="font-size:15px;font-weight:700;margin-bottom:16px;">Quick Actions</h2>
    <div style="display:flex;gap:12px;flex-wrap:wrap;">
        <form method="POST" style="display:inline;">
            <button type="submit" name="reset_all" class="btn btn-primary"
                    onclick="return confirm('Reset all pages to LOW difficulty?')">
                Reset All to LOW
            </button>
        </form>
        <form method="POST" style="display:inline;">
            <button type="submit" name="clear_logs" class="btn btn-danger"
                    onclick="return confirm('Clear all activity logs?')">
                Clear Activity Logs
            </button>
        </form>
        <a href="/admin/index.php" class="btn" style="background:#232F3E;color:#FFF;">
            View Admin Panel
        </a>
    </div>
</div>

<!-- CONFIG SUMMARY TABLE -->
<div style="background:var(--card-bg);border-radius:var(--radius);box-shadow:var(--shadow);padding:20px;margin-top:20px;margin-bottom:40px;">
    <h2 style="font-size:15px;font-weight:700;margin-bottom:12px;">Current Configuration</h2>
    <table class="data-table">
        <thead><tr><th>Page</th><th>Vulnerability Type</th><th>Injection Point</th><th>Difficulty</th></tr></thead>
        <tbody>
            <?php foreach ($vuln_info as $page => $info): ?>
            <?php $current = $settings[$page]['difficulty'] ?? 'low'; ?>
            <tr>
                <td><strong><?= $info['icon'] ?> <?= $info['title'] ?></strong></td>
                <td><?= $info['technique'] ?></td>
                <td><code style="font-size:12px;background:#f5f5f5;padding:2px 6px;border-radius:3px;"><?= $info['type'] ?></code></td>
                <td><?= difficultyBadge($current) ?></td>
            </tr>
            <?php endforeach; ?>
        </tbody>
    </table>
</div>

<?php include __DIR__ . '/../includes/footer.php'; ?>
