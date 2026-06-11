<?php
require_once __DIR__ . '/config.php';
require_once __DIR__ . '/includes/db.php';
if (!isLoggedIn()) redirect('/login.php');
$pageTitle = 'Order Receipt Lookup';

$conn     = getDB();
$diff     = getDifficulty('fileops');
$result   = null;
$queryLog = null;
$sqlError = null;
$fileResult = null;

// Handle receipt file lookup (LOAD_FILE injection vector)
if (isset($_GET['receipt'])) {
    $receipt = $_GET['receipt'];

    if ($diff === 'low') {
        // VULNERABLE: receipt filename injected raw into LOAD_FILE()
        // Attack: ?receipt=/etc/passwd
        // Attack: ?receipt=' UNION SELECT LOAD_FILE('/etc/passwd'),2,3,4-- -
        $sql = "SELECT order_ref, amount, status, LOAD_FILE('{$receipt}') as file_content
                FROM receipts WHERE order_ref = '{$receipt}'";
        $queryLog = $sql;
        mysqli_report(MYSQLI_REPORT_OFF);
        $res = @$conn->query($sql);
        if ($res) {
            $result = $res->fetch_assoc();
        } else {
            $err = $conn->error;
            if (strpos($err, 'FILE') !== false || strpos($err, 'Access denied') !== false) {
                $sqlError = "LOAD_FILE() returned an error. The file may not exist or may not be readable by the MySQL process. Query attempted: " . htmlspecialchars($sql);
            } else {
                $sqlError = $err;
            }
        }
        mysqli_report(MYSQLI_REPORT_ERROR | MYSQLI_REPORT_STRICT);

    } elseif ($diff === 'medium') {
        // STILL VULNERABLE via UNION: addslashes on receipt but LOAD_FILE path injectable via UNION
        $receipt_escaped = addslashes($receipt);
        $sql = "SELECT order_ref, amount, status FROM receipts WHERE order_ref = '{$receipt_escaped}'";
        $queryLog = "[MEDIUM] addslashes applied to receipt param. Try UNION: ' UNION SELECT LOAD_FILE('/etc/passwd'),2,3-- -";
        $res = $conn->query($sql);
        if ($res) $result = $res->fetch_assoc();
        else $sqlError = $conn->error;

    } else {
        // HARD: prepared statement
        $stmt = $conn->prepare("SELECT order_ref, amount, status FROM receipts WHERE order_ref = ?");
        $stmt->bind_param("s", $receipt);
        $stmt->execute();
        $res = $stmt->get_result();
        if ($res) $result = $res->fetch_assoc();
        $queryLog = "[HARD] Prepared statement — LOAD_FILE not injectable";
    }
}

// Handle outfile write (separate input)
$writeMsg = null;
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['export_data']) && $diff === 'low') {
    $export_path = $_POST['export_path'] ?? '/tmp/export.txt';
    // VULNERABLE: path injected raw into INTO OUTFILE
    $sql = "SELECT username, password, email FROM users INTO OUTFILE '{$export_path}'";
    $queryLog = $sql;
    // Suppress fatal mysqli errors — FILE privilege not granted in Docker
    $conn->query("SET sql_mode=''");
    mysqli_report(MYSQLI_REPORT_OFF);
    $res = @$conn->query($sql);
    if ($res) {
        $writeMsg = "Export written to: " . htmlspecialchars($export_path);
    } else {
        $err = $conn->error;
        if (strpos($err, 'FILE') !== false || strpos($err, 'Access denied') !== false) {
            $writeMsg = "INTO OUTFILE failed — the target file likely already exists (MySQL refuses to overwrite) or the path isn't writable by the MySQL process. Tried: " . htmlspecialchars($export_path) . ". Pick a fresh filename and retry.";
        } else {
            $writeMsg = "Error: " . htmlspecialchars($err);
        }
    }
    mysqli_report(MYSQLI_REPORT_ERROR | MYSQLI_REPORT_STRICT);
}

include __DIR__ . '/includes/header.php';
?>

<div class="page-header">
    <h1>Order Receipt Lookup</h1>
    <?php if (showHints()): ?>
    <div class="vuln-info">
        <span>🎯 Vulnerability: MySQL LOAD_FILE + INTO OUTFILE &nbsp;|&nbsp; Difficulty:</span>
        <?= difficultyBadge($diff) ?>
    </div>
    <?php endif; ?>
</div>

<?php if (showHints() && $diff === 'low'): ?>
<div class="alert alert-warning" style="font-size:12px;">
    🔴 <strong>LOW — FILE READ:</strong> The <code>receipt</code> parameter is injected raw into <code>LOAD_FILE()</code>.<br>
    Try: <code>?receipt=/etc/passwd</code><br>
    Or UNION: <code>' UNION SELECT LOAD_FILE('/etc/passwd'),2,3,4-- -</code><br><br>
    🔴 <strong>LOW — FILE WRITE:</strong> The export path is injected raw into <code>INTO OUTFILE</code>.<br>
    Write data to the DB host filesystem: <code>/tmp/orders_export.txt</code><br><br>
    ⚠️ <strong>Lab note:</strong> The <code>FILE</code> privilege and <code>secure_file_priv=</code> are enabled, so <code>LOAD_FILE()</code> reads work here. <code>INTO OUTFILE</code> writes to the <em>database container's</em> filesystem, which is separate from the web container in this compose setup — so a classic OUTFILE→webroot webshell only lands when MySQL and the web server share a host. Use OUTFILE here to demonstrate the arbitrary-write primitive.
</div>
<?php elseif (showHints() && $diff === 'medium'): ?>
<div class="alert alert-warning" style="font-size:12px;">
    🟠 <strong>MEDIUM:</strong> Direct injection blocked by addslashes. Try UNION with LOAD_FILE:<br>
    <code>' UNION SELECT LOAD_FILE('/etc/passwd'),2,3-- -</code>
</div>
<?php endif; ?>

<?php if ($sqlError): ?>
<div class="sql-error-box"><span class="sql-label">MySQL Error</span><?= htmlspecialchars($sqlError) ?></div>
<?php endif; ?>

<!-- Receipt lookup form -->
<div style="display:grid;grid-template-columns:1fr 1fr;gap:20px;margin-bottom:20px;">

    <div style="background:var(--card-bg);border-radius:var(--radius);box-shadow:var(--shadow);padding:24px;">
        <h2 style="font-size:16px;font-weight:700;margin-bottom:4px;">Receipt Lookup</h2>
        <p style="font-size:13px;color:#666;margin-bottom:16px;">Enter your order receipt number to view details.</p>
        <form method="GET">
            <div class="form-group">
                <label>Receipt Number</label>
                <input type="text" name="receipt" class="form-input"
                       placeholder="e.g. RCP-2024-001"
                       value="<?= isset($_GET['receipt']) ? htmlspecialchars($_GET['receipt']) : '' ?>">
            </div>
            <button type="submit" class="btn btn-primary" style="width:100%;">Look Up Receipt</button>
        </form>

        <?php if ($result && !empty($result['file_content'])): ?>
        <div class="sql-error-box" style="margin-top:16px;border-left-color:#E53935;">
            <span class="sql-label" style="background:#E53935;">LOAD_FILE() Output</span>
            <pre style="white-space:pre-wrap;word-break:break-all;font-size:11px;max-height:200px;overflow-y:auto;"><?= htmlspecialchars($result['file_content']) ?></pre>
        </div>
        <?php elseif ($result): ?>
        <div style="margin-top:16px;padding:12px;background:#f9f9f9;border-radius:6px;font-size:13px;">
            No file content returned — receipt not found or LOAD_FILE() returned NULL (file may not exist or MySQL FILE privilege not granted).
        </div>
        <?php endif; ?>
    </div>

    <!-- Outfile export (LOW only demo) -->
    <div style="background:var(--card-bg);border-radius:var(--radius);box-shadow:var(--shadow);padding:24px;">
        <h2 style="font-size:16px;font-weight:700;margin-bottom:4px;">Export Order Data</h2>
        <p style="font-size:13px;color:#666;margin-bottom:16px;">Export your order history to a file on the server.</p>
        <form method="POST">
            <div class="form-group">
                <label>Export File Path</label>
                <input type="text" name="export_path" class="form-input"
                       value="/tmp/orders_export.txt"
                       <?= $diff !== 'low' ? 'disabled' : '' ?>>
                <?php if ($diff !== 'low'): ?>
                <small style="color:#999;">Export disabled at <?= strtoupper($diff) ?> difficulty</small>
                <?php endif; ?>
            </div>
            <input type="hidden" name="export_data" value="1">
            <button type="submit" class="btn btn-primary" style="width:100%;"
                    <?= $diff !== 'low' ? 'disabled' : '' ?>>
                Export Data
            </button>
        </form>

        <?php if ($writeMsg): ?>
        <div class="sql-error-box" style="margin-top:16px;border-left-color:<?= strpos($writeMsg,'Error')===false ? '#43A047' : '#E53935' ?>;">
            <span class="sql-label">INTO OUTFILE Result</span>
            <?= htmlspecialchars($writeMsg) ?>
        </div>
        <?php endif; ?>

        <?php if (showHints() && $diff === 'low'): ?>
        <div style="margin-top:12px;padding:10px;background:#fff3e0;border-radius:6px;font-size:12px;color:#854F0B;">
            <strong>Arbitrary file write</strong> — lands on the DB container filesystem.<br>
            Demo path: <code>/tmp/orders_export.txt</code><br>
            A webshell to <code>/var/www/html/shell.php</code> only works when MySQL shares a filesystem with the web server (single-host LAMP), not in this split-container lab.
        </div>
        <?php endif; ?>
    </div>
</div>

<?php if (showQueryLog() && $queryLog && $diff !== 'hard'): ?>
<div class="sql-error-box" style="margin-top:20px;border-left-color:#1565C0;">
    <span class="sql-label">Query Log</span><?= htmlspecialchars($queryLog) ?>
</div>
<?php endif; ?>

<?php include __DIR__ . '/includes/footer.php'; ?>
