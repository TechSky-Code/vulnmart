<?php
require_once __DIR__ . '/../config.php';
require_once __DIR__ . '/../includes/db.php';

// JSON API — returns application/json
// No HTML output — this is a pure API endpoint for Burp Suite / curl demos
header('Content-Type: application/json; charset=utf-8');

// Auth check — return JSON error instead of redirect
if (!isLoggedIn()) {
    http_response_code(401);
    echo json_encode(['error' => 'Unauthorized', 'message' => 'Login required']);
    exit();
}

$conn = getDB();
$diff = getDifficulty('api_search');

// Only accept POST with JSON body
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    echo json_encode(['error' => 'Method not allowed', 'message' => 'POST only. Send JSON: {"q":"laptop"}']);
    exit();
}

// Parse JSON body
$body  = file_get_contents('php://input');
$input = json_decode($body, true);

if (!$input || !isset($input['q'])) {
    http_response_code(400);
    echo json_encode([
        'error'   => 'Bad request',
        'message' => 'Send JSON body: {"q":"laptop"}',
        'example' => 'curl -X POST http://localhost:8080/api/search.php -H "Content-Type: application/json" -d \'{"q":"laptop"}\''
    ]);
    exit();
}

$q        = $input['q'];
$queryLog = null;
$sqlError = null;
$products = [];

if ($diff === 'low') {
    // VULNERABLE: JSON value injected raw into SQL
    // Attack: {"q":"laptop' UNION SELECT 1,username,password,4,5,6,7,8,9,10,11 FROM users-- -"}
    // Attack: {"q":"' OR '1'='1"}
    $sql      = "SELECT id, name, price, rating, badge FROM products WHERE name LIKE '%{$q}%' OR description LIKE '%{$q}%'";
    $queryLog = $sql;
    $res      = $conn->query($sql);
    if ($res) {
        while ($r = $res->fetch_assoc()) $products[] = $r;
    } else {
        $sqlError = $conn->error;
    }

} elseif ($diff === 'medium') {
    $q_escaped = addslashes($q);
    $sql       = "SELECT id, name, price, rating, badge FROM products WHERE name LIKE '%{$q_escaped}%'";
    $queryLog  = "[MEDIUM] addslashes applied to JSON q value";
    $res       = $conn->query($sql);
    if ($res) while ($r = $res->fetch_assoc()) $products[] = $r;
    else $sqlError = $conn->error;

} else {
    $stmt = $conn->prepare("SELECT id, name, price, rating, badge FROM products WHERE name LIKE ? OR description LIKE ?");
    $like = "%{$q}%";
    $stmt->bind_param("ss", $like, $like);
    $stmt->execute();
    $res = $stmt->get_result();
    while ($r = $res->fetch_assoc()) $products[] = $r;
    $queryLog = "[HARD] Prepared statement";
}

// Build response
$response = [
    'query'    => $q,
    'count'    => count($products),
    'products' => $products,
];

// Include debug info at LOW/MEDIUM (training aid)
if (showQueryLog() && $diff !== 'hard' && $queryLog) {
    $response['_debug'] = ['query' => $queryLog];
}
if ($sqlError) {
    $response['_error'] = $sqlError;
}
if (showHints() && $diff === 'low') {
    $response['_hint'] = [
        'vulnerability' => 'JSON body injection — the q value is injected raw into SQL',
        'attack_union'  => '{"q":"laptop\' UNION SELECT 1,username,password,4,5,6,7,8,9,10,11 FROM users-- -"}',
        'attack_dump'   => '{"q":"\' OR \'1\'=\'1"}',
        'burp_tip'      => 'Intercept this POST request in Burp Repeater and modify the JSON body'
    ];
}

echo json_encode($response, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE);
