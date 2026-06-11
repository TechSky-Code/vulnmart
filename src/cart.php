<?php
require_once __DIR__ . '/config.php';
require_once __DIR__ . '/includes/db.php';
if (!isLoggedIn()) redirect('/login.php');
$pageTitle = 'Shopping Cart';

$conn = getDB();

// Handle actions
$action = $_POST['action'] ?? $_GET['action'] ?? '';

if ($action === 'add' && isset($_POST['product_id'])) {
    $pid = (int)$_POST['product_id'];
    $qty = max(1, (int)($_POST['quantity'] ?? 1));
    if (!isset($_SESSION['cart'])) $_SESSION['cart'] = [];
    if (isset($_SESSION['cart'][$pid])) {
        $_SESSION['cart'][$pid] += $qty;
    } else {
        $_SESSION['cart'][$pid] = $qty;
    }
    // Redirect back to product page or cart
    $back = $_POST['back'] ?? '/cart.php';
    redirect($back);
}

if ($action === 'remove' && isset($_GET['id'])) {
    $pid = (int)$_GET['id'];
    unset($_SESSION['cart'][$pid]);
    redirect('/cart.php');
}

if ($action === 'update' && isset($_POST['quantities'])) {
    foreach ($_POST['quantities'] as $pid => $qty) {
        $pid = (int)$pid; $qty = (int)$qty;
        if ($qty <= 0) unset($_SESSION['cart'][$pid]);
        else $_SESSION['cart'][$pid] = $qty;
    }
    redirect('/cart.php');
}

if ($action === 'clear') {
    $_SESSION['cart'] = [];
    redirect('/cart.php');
}

// Load cart items
$cart    = $_SESSION['cart'] ?? [];
$items   = [];
$total   = 0;

if (!empty($cart)) {
    $ids = implode(',', array_map('intval', array_keys($cart)));
    $res = $conn->query("SELECT * FROM products WHERE id IN ($ids)");
    if ($res) while ($r = $res->fetch_assoc()) {
        $r['qty']      = $cart[$r['id']];
        $r['subtotal'] = $r['price'] * $r['qty'];
        $total        += $r['subtotal'];
        $items[]       = $r;
    }
}

$productIcons = ['1'=>'💻','2'=>'📱','3'=>'🎧','4'=>'📺','5'=>'📱','6'=>'📷',
                 '7'=>'👕','8'=>'👖','9'=>'🧥','10'=>'👟','11'=>'📖','12'=>'📗',
                 '13'=>'📘','14'=>'☕','15'=>'💡','16'=>'🎒','17'=>'🎮',
                 '18'=>'🪑','19'=>'🖱','20'=>'🧘','21'=>'⌚'];

include __DIR__ . '/includes/header.php';
?>

<div class="page-header">
    <h1>Shopping Cart</h1>
</div>

<?php if (empty($items)): ?>
<div style="background:var(--card-bg);border-radius:var(--radius);box-shadow:var(--shadow);padding:40px;text-align:center;">
    <div style="font-size:48px;margin-bottom:16px;">🛒</div>
    <h2 style="font-size:20px;margin-bottom:8px;">Your cart is empty</h2>
    <p style="color:#666;margin-bottom:20px;">Add items to get started.</p>
    <a href="/search.php?q=" class="btn btn-primary">Continue Shopping</a>
</div>

<?php else: ?>
<div style="display:grid;grid-template-columns:1fr 300px;gap:20px;align-items:start;">

    <!-- Cart Items -->
    <div style="background:var(--card-bg);border-radius:var(--radius);box-shadow:var(--shadow);padding:20px;">
        <form method="POST">
            <input type="hidden" name="action" value="update">
            <?php foreach ($items as $item): ?>
            <div style="display:flex;gap:16px;padding:16px 0;border-bottom:1px solid var(--border);align-items:center;">
                <div style="font-size:48px;width:80px;text-align:center;background:#f5f5f5;border-radius:8px;padding:8px;">
                    <?= $productIcons[$item['id']] ?? '📦' ?>
                </div>
                <div style="flex:1;">
                    <div style="font-weight:600;font-size:15px;margin-bottom:4px;">
                        <a href="/product.php?id=<?= $item['id'] ?>" style="color:var(--text);text-decoration:none;">
                            <?= htmlspecialchars($item['name']) ?>
                        </a>
                    </div>
                    <div style="color:#067D62;font-size:13px;margin-bottom:8px;">In Stock</div>
                    <div style="display:flex;align-items:center;gap:12px;">
                        <label style="font-size:13px;">Qty:</label>
                        <select name="quantities[<?= $item['id'] ?>]"
                                style="padding:4px 8px;border:1px solid var(--border);border-radius:4px;font-size:13px;"
                                onchange="this.form.submit()">
                            <?php for ($q = 1; $q <= 10; $q++): ?>
                            <option value="<?= $q ?>" <?= $item['qty']==$q?'selected':'' ?>><?= $q ?></option>
                            <?php endfor; ?>
                            <option value="0" <?= $item['qty']==0?'selected':'' ?>>0 (Remove)</option>
                        </select>
                        <a href="/cart.php?action=remove&id=<?= $item['id'] ?>"
                           style="font-size:13px;color:#E53935;text-decoration:none;">Remove</a>
                    </div>
                </div>
                <div style="font-size:18px;font-weight:700;color:var(--text);min-width:80px;text-align:right;">
                    $<?= number_format($item['subtotal'], 2) ?>
                </div>
            </div>
            <?php endforeach; ?>

            <div style="display:flex;justify-content:space-between;align-items:center;padding-top:16px;">
                <a href="/cart.php?action=clear" style="font-size:13px;color:#E53935;text-decoration:none;">
                    Clear cart
                </a>
                <div style="font-size:16px;">
                    Subtotal (<?= array_sum(array_column($items,'qty')) ?> items):
                    <strong>$<?= number_format($total, 2) ?></strong>
                </div>
            </div>
        </form>
    </div>

    <!-- Order Summary -->
    <div style="background:var(--card-bg);border-radius:var(--radius);box-shadow:var(--shadow);padding:20px;">
        <h2 style="font-size:16px;font-weight:700;margin-bottom:16px;">Order Summary</h2>
        <div style="display:flex;justify-content:space-between;margin-bottom:8px;font-size:14px;">
            <span>Subtotal</span><span>$<?= number_format($total, 2) ?></span>
        </div>
        <div style="display:flex;justify-content:space-between;margin-bottom:8px;font-size:14px;">
            <span>Shipping</span><span style="color:#067D62;">FREE</span>
        </div>
        <div style="border-top:1px solid var(--border);margin:12px 0;padding-top:12px;display:flex;justify-content:space-between;font-size:16px;font-weight:700;">
            <span>Order Total</span><span>$<?= number_format($total, 2) ?></span>
        </div>
        <a href="/checkout.php" class="btn btn-primary" style="width:100%;padding:12px;font-size:16px;margin-bottom:8px;display:block;text-align:center;text-decoration:none;">Proceed to Checkout</a>
        <a href="/search.php?q=" style="display:block;text-align:center;font-size:13px;color:#007185;">
            Continue Shopping
        </a>
    </div>
</div>
<?php endif; ?>

<?php include __DIR__ . '/includes/footer.php'; ?>
