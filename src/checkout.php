<?php
require_once __DIR__ . '/config.php';
require_once __DIR__ . '/includes/db.php';
if (!isLoggedIn()) redirect('/login.php');
$pageTitle = 'Checkout';

$conn        = getDB();
$diff        = getDifficulty('checkout');
$cart        = $_SESSION['cart'] ?? [];
$orderPlaced = false;
$orderMsg    = null;
$orderTotal  = 0;
$items       = [];

// ================================================================
// BUSINESS LOGIC VULNERABILITIES
//
// LOW difficulty exposes four exploitable flaws:
//
// FLAW 1 — Price from client (hidden field)
//   The unit price for each cart item is sent as a hidden form
//   field. The server trusts this value instead of fetching from DB.
//   Attack: Intercept POST in Burp, change price_1=999.99 to price_1=0.01
//
// FLAW 2 — Coupon reuse
//   Coupon SAVE10 gives 10% discount. No server-side check prevents
//   applying it multiple times in the same session.
//   Attack: Apply coupon, note discount. Remove and reapply — applies again.
//
// FLAW 3 — Negative quantity
//   Quantity field is not validated server-side at checkout.
//   Attack: Intercept POST, change qty_1=1 to qty_1=-5.
//   Order total becomes negative — effectively earning money.
//
// FLAW 4 — Skip payment step
//   Order confirmation page /checkout.php?step=confirm&order_id=X
//   is accessible directly without completing payment step.
//   Attack: Browse directly to confirmation URL without paying.
//
// HARD difficulty:
//   Prices fetched server-side only.
//   Coupon tracked in session, one-time use enforced.
//   Quantities validated server-side.
//   Step verified server-side via session token.
// ================================================================

// Load cart items with prices
if (!empty($cart)) {
    $ids = implode(',', array_map('intval', array_keys($cart)));
    $res = $conn->query("SELECT id, name, price FROM products WHERE id IN ($ids)");
    if ($res) {
        while ($r = $res->fetch_assoc()) {
            $r['qty']      = $cart[$r['id']];
            $r['subtotal'] = $r['price'] * $r['qty'];
            $orderTotal   += $r['subtotal'];
            $items[]       = $r;
        }
    }
}

// Handle coupon
$couponDiscount = 0;
$couponMsg      = null;
$validCoupons   = ['SAVE10' => 0.10, 'HACK20' => 0.20];

if (isset($_POST['coupon_code'])) {
    $code = strtoupper(trim($_POST['coupon_code']));
    if ($diff === 'low') {
        // FLAW 2 — No reuse prevention, no session tracking
        if (isset($validCoupons[$code])) {
            $_SESSION['coupon']      = $code;
            $_SESSION['coupon_rate'] = $validCoupons[$code];
            $couponMsg = "Coupon applied: " . ($validCoupons[$code] * 100) . "% off";
        } else {
            $couponMsg = "Invalid coupon code.";
        }
    } else {
        // HARD — one-time use per session
        if (isset($validCoupons[$code]) && !isset($_SESSION['coupon_used'])) {
            $_SESSION['coupon']      = $code;
            $_SESSION['coupon_rate'] = $validCoupons[$code];
            $couponMsg = "Coupon applied: " . ($validCoupons[$code] * 100) . "% off";
        } elseif (isset($_SESSION['coupon_used'])) {
            $couponMsg = "Coupon already used. One coupon per order.";
        } else {
            $couponMsg = "Invalid coupon code.";
        }
    }
}

if (isset($_SESSION['coupon_rate'])) {
    $couponDiscount = $orderTotal * $_SESSION['coupon_rate'];
}

$finalTotal = $orderTotal - $couponDiscount;

// Handle order placement
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['place_order'])) {
    $shipping = trim($_POST['shipping_address'] ?? '');

    if ($diff === 'low') {
        // FLAW 1 — Prices and quantities from POST, not database
        $calculatedTotal = 0;
        $lineItems       = [];

        foreach ($cart as $pid => $qty) {
            $pid = (int)$pid;
            // VULNERABLE: trusting client-supplied price and quantity
            $client_price = (float)($_POST["price_{$pid}"] ?? 0);
            $client_qty   = (int)($_POST["qty_{$pid}"] ?? 1);
            // FLAW 3 — Negative quantity not validated
            $subtotal          = $client_price * $client_qty;
            $calculatedTotal  += $subtotal;
            $lineItems[]       = ['pid' => $pid, 'qty' => $client_qty, 'price' => $client_price];
        }

        // Apply coupon from session
        $coupon_rate     = $_SESSION['coupon_rate'] ?? 0;
        $calculatedTotal = $calculatedTotal - ($calculatedTotal * $coupon_rate);

        // Place order at whatever total the client sent
        $uid        = (int)$_SESSION['user_id'];
        $safe_addr  = $conn->real_escape_string($shipping);
        $conn->query("INSERT INTO orders (user_id, total_amount, status, shipping_address)
                      VALUES ({$uid}, {$calculatedTotal}, 'pending', '{$safe_addr}')");
        $order_id = $conn->insert_id;

        foreach ($lineItems as $li) {
            $conn->query("INSERT INTO order_items (order_id, product_id, quantity, price)
                          VALUES ({$order_id}, {$li['pid']}, {$li['qty']}, {$li['price']})");
        }

        $_SESSION['cart']           = [];
        $_SESSION['coupon']         = null;
        $_SESSION['coupon_rate']    = null;
        $_SESSION['last_order_id']  = $order_id;
        $_SESSION['last_order_total'] = $calculatedTotal;
        $orderPlaced = true;

    } else {
        // HARD — all prices and quantities from database only
        $calculatedTotal = 0;
        $uid             = (int)$_SESSION['user_id'];
        $safe_addr       = $conn->real_escape_string($shipping);

        foreach ($items as $item) {
            $qty              = max(1, (int)$item['qty']);
            $calculatedTotal += $item['price'] * $qty;
        }

        $coupon_rate     = $_SESSION['coupon_rate'] ?? 0;
        $calculatedTotal = $calculatedTotal - ($calculatedTotal * $coupon_rate);

        $conn->query("INSERT INTO orders (user_id, total_amount, status, shipping_address)
                      VALUES ({$uid}, {$calculatedTotal}, 'pending', '{$safe_addr}')");
        $order_id = $conn->insert_id;

        foreach ($items as $item) {
            $qty = max(1, (int)$item['qty']);
            $conn->query("INSERT INTO order_items (order_id, product_id, quantity, price)
                          VALUES ({$order_id}, {$item['id']}, {$qty}, {$item['price']})");
        }

        $_SESSION['cart']        = [];
        $_SESSION['coupon']      = null;
        $_SESSION['coupon_rate'] = null;
        $_SESSION['coupon_used'] = true;
        $_SESSION['last_order_id']    = $order_id;
        $_SESSION['last_order_total'] = $calculatedTotal;
        $orderPlaced = true;
    }
}

// FLAW 4 — Step skip: confirmation accessible directly
$step = $_GET['step'] ?? 'checkout';
if ($step === 'confirm') {
    $order_id    = (int)($_GET['order_id'] ?? $_SESSION['last_order_id'] ?? 0);
    $order_total = $_SESSION['last_order_total'] ?? 0;

    include __DIR__ . '/includes/header.php';
    ?>
    <div class="page-header">
        <h1>Order Confirmed</h1>
        <?php if (showHints()): ?>
        <div class="vuln-info">
            <span>🎯 Vulnerability: Step Skip — This page accessible without completing payment &nbsp;|&nbsp; Difficulty:</span>
            <?= difficultyBadge($diff) ?>
        </div>
        <?php endif; ?>
    </div>
    <div style="max-width:600px;margin:40px auto;text-align:center;background:var(--card-bg);padding:40px;border-radius:var(--radius);box-shadow:var(--shadow);">
        <div style="font-size:64px;margin-bottom:16px;">✅</div>
        <h2 style="font-size:24px;font-weight:700;margin-bottom:8px;">Thank you for your order!</h2>
        <p style="color:var(--text-muted);margin-bottom:16px;">Order #<?= $order_id ?> has been placed.</p>
        <p style="font-size:24px;font-weight:700;color:<?= $order_total < 0 ? '#E53935' : '#2E7D32' ?>;">
            Total: $<?= number_format($order_total, 2) ?>
        </p>
        <?php if ($order_total < 0): ?>
        <div style="margin-top:12px;padding:10px;background:#ffebee;border:1px solid #E53935;border-radius:4px;font-size:13px;">
            ⚠️ Negative order total — business logic flaw exploited successfully
        </div>
        <?php endif; ?>
        <?php if (showHints() && $diff === 'low'): ?>
        <div class="alert alert-warning" style="margin-top:20px;font-size:12px;text-align:left;">
            🔴 <strong>Step Skip:</strong> You accessed this confirmation page directly via URL without completing payment.<br>
            In a real application this would bypass the payment gateway entirely.
        </div>
        <?php endif; ?>
        <a href="/" style="display:inline-block;margin-top:20px;" class="btn btn-primary">Continue Shopping</a>
    </div>
    <?php
    include __DIR__ . '/includes/footer.php';
    exit();
}

include __DIR__ . '/includes/header.php';
?>

<div class="page-header">
    <h1>Checkout</h1>
    <?php if (showHints()): ?>
    <div class="vuln-info">
        <span>🎯 Vulnerabilities: Price Manipulation &nbsp;|&nbsp; Coupon Reuse &nbsp;|&nbsp; Negative Quantity &nbsp;|&nbsp; Step Skip &nbsp;|&nbsp; Difficulty:</span>
        <?= difficultyBadge($diff) ?>
    </div>
    <?php endif; ?>
</div>

<?php if (showHints() && $diff === 'low'): ?>
<div class="alert alert-warning" style="font-size:12px;margin-bottom:16px;">
    🔴 <strong>Business Logic Flaws — 4 vulnerabilities on this page:</strong><br>
    1. <strong>Price manipulation:</strong> Intercept POST in Burp — change <code>price_X=99.99</code> to <code>price_X=0.01</code><br>
    2. <strong>Coupon reuse:</strong> Apply coupon SAVE10, remove it, apply again — discount stacks<br>
    3. <strong>Negative quantity:</strong> Intercept POST — change <code>qty_X=1</code> to <code>qty_X=-999</code><br>
    4. <strong>Step skip:</strong> Browse directly to <code>/checkout.php?step=confirm&amp;order_id=1</code>
</div>
<?php endif; ?>

<?php if (empty($items)): ?>
<div class="no-results">
    <div class="no-results-icon">🛒</div>
    <h3>Your cart is empty</h3>
    <p><a href="/" style="color:#007185;">Continue shopping</a></p>
</div>
<?php else: ?>

<div style="display:grid;grid-template-columns:1fr 380px;gap:20px;max-width:1000px;">

    <!-- Order form -->
    <div>
        <div style="background:var(--card-bg);border:1px solid var(--border);border-radius:var(--radius);padding:20px;margin-bottom:16px;">
            <h2 style="font-size:16px;font-weight:700;margin-bottom:16px;border-bottom:1px solid var(--border);padding-bottom:8px;">Shipping Address</h2>
            <form method="POST" action="/checkout.php" id="checkout-form">
                <textarea name="shipping_address" rows="3" placeholder="Enter your shipping address..."
                    style="width:100%;padding:8px 12px;border:1px solid var(--border);border-radius:4px;font-family:inherit;font-size:14px;resize:vertical;margin-bottom:12px;"
                    required></textarea>

                <!-- Order items with hidden price fields -->
                <div style="margin-bottom:12px;">
                    <h3 style="font-size:14px;font-weight:700;margin-bottom:8px;">Order Items</h3>
                    <?php foreach ($items as $item): ?>
                    <div style="display:flex;justify-content:space-between;align-items:center;padding:8px 0;border-bottom:1px solid var(--border);font-size:14px;">
                        <span><?= htmlspecialchars($item['name']) ?> × <?= $item['qty'] ?></span>
                        <span>$<?= number_format($item['subtotal'], 2) ?></span>
                        <?php if ($diff === 'low'): ?>
                        <!-- FLAW 1 + 3: Price and quantity sent as hidden fields — client controls these values -->
                        <input type="hidden" name="price_<?= $item['id'] ?>" value="<?= $item['price'] ?>">
                        <input type="hidden" name="qty_<?= $item['id'] ?>" value="<?= $item['qty'] ?>">
                        <?php endif; ?>
                    </div>
                    <?php endforeach; ?>
                </div>

                <button type="submit" name="place_order" value="1" class="btn btn-primary" style="width:100%;padding:12px;">
                    Place Order — $<?= number_format(max(0, $finalTotal), 2) ?>
                </button>
            </form>
        </div>
    </div>

    <!-- Order summary -->
    <div>
        <div style="background:var(--card-bg);border:1px solid var(--border);border-radius:var(--radius);padding:20px;margin-bottom:16px;">
            <h2 style="font-size:16px;font-weight:700;margin-bottom:16px;border-bottom:1px solid var(--border);padding-bottom:8px;">Order Summary</h2>
            <?php foreach ($items as $item): ?>
            <div style="display:flex;justify-content:space-between;font-size:14px;margin-bottom:8px;">
                <span><?= htmlspecialchars($item['name']) ?> (<?= $item['qty'] ?>)</span>
                <span>$<?= number_format($item['subtotal'], 2) ?></span>
            </div>
            <?php endforeach; ?>
            <div style="border-top:1px solid var(--border);margin:12px 0;padding-top:12px;">
                <div style="display:flex;justify-content:space-between;font-size:14px;margin-bottom:6px;">
                    <span>Subtotal</span>
                    <span>$<?= number_format($orderTotal, 2) ?></span>
                </div>
                <?php if ($couponDiscount > 0): ?>
                <div style="display:flex;justify-content:space-between;font-size:14px;margin-bottom:6px;color:var(--success);">
                    <span>Coupon (<?= htmlspecialchars($_SESSION['coupon'] ?? '') ?>)</span>
                    <span>-$<?= number_format($couponDiscount, 2) ?></span>
                </div>
                <?php endif; ?>
                <div style="display:flex;justify-content:space-between;font-size:16px;font-weight:700;margin-top:8px;">
                    <span>Total</span>
                    <span>$<?= number_format($finalTotal, 2) ?></span>
                </div>
            </div>
        </div>

        <!-- Coupon form -->
        <div style="background:var(--card-bg);border:1px solid var(--border);border-radius:var(--radius);padding:20px;">
            <h3 style="font-size:15px;font-weight:700;margin-bottom:12px;">Coupon Code</h3>
            <?php if ($couponMsg): ?>
            <div style="padding:8px 12px;border-radius:4px;font-size:13px;margin-bottom:10px;
                        background:<?= str_contains($couponMsg, 'applied') ? '#d4edda' : '#f8d7da' ?>;
                        border:1px solid <?= str_contains($couponMsg, 'applied') ? '#c3e6cb' : '#f5c6cb' ?>;">
                <?= htmlspecialchars($couponMsg) ?>
            </div>
            <?php endif; ?>
            <form method="POST" action="/checkout.php" style="display:flex;gap:8px;">
                <input type="text" name="coupon_code" placeholder="Enter code"
                       style="flex:1;padding:8px 12px;border:1px solid var(--border);border-radius:4px;font-family:inherit;font-size:14px;">
                <button type="submit" class="btn" style="width:auto;">Apply</button>
            </form>
            <?php if (showHints() && $diff === 'low'): ?>
            <p style="font-size:11px;color:var(--text-muted);margin-top:6px;">
                Try: <code>SAVE10</code> or <code>HACK20</code> — apply multiple times to stack discounts
            </p>
            <?php endif; ?>
        </div>
    </div>

</div>

<?php if ($orderPlaced): ?>
<script>
    window.location.href = '/checkout.php?step=confirm&order_id=<?= $_SESSION['last_order_id'] ?? 0 ?>';
</script>
<?php endif; ?>

<?php endif; ?>

<?php include __DIR__ . '/includes/footer.php'; ?>
