<?php
require_once __DIR__ . '/config.php';
require_once __DIR__ . '/includes/db.php';
if (!isLoggedIn()) redirect('/login.php');
$pageTitle = 'Online Shopping for Electronics, Clothing, Books & More';

$conn = getDB();

$featured = $conn->query("SELECT * FROM products ORDER BY review_count DESC LIMIT 8");
$featuredProducts = [];
if ($featured) while ($r = $featured->fetch_assoc()) $featuredProducts[] = $r;

$cats = $conn->query("SELECT * FROM categories ORDER BY name");
$categories = [];
if ($cats) while ($r = $cats->fetch_assoc()) $categories[] = $r;

$catIcons = ['electronics'=>'💻','clothing'=>'👕','books'=>'📚','home-kitchen'=>'🏠','gaming'=>'🎮','sports'=>'⚽'];

function stars(float $rating): string {
    $full = floor($rating);
    $half = ($rating - $full) >= 0.5 ? 1 : 0;
    return str_repeat('★', $full) . ($half ? '☆' : '') . str_repeat('☆', 5 - $full - $half);
}

include __DIR__ . '/includes/header.php';
?>

<!-- Hero Banner -->
<div class="hero">
    <div class="hero-content">
        <p class="hero-eyebrow">🔴 Training Platform</p>
        <h1 class="hero-title">Welcome to <span>VulnMart</span></h1>
        <p class="hero-subtitle">A realistic e-commerce application intentionally vulnerable to multiple web security flaws — built for web pentesting training.</p>
        <a href="/search.php?q=" class="hero-btn">Shop Now →</a>
    </div>
</div>

<!-- Categories -->
<div class="section-header">
    <h2 class="section-title">Shop by Category</h2>
</div>
<div class="category-grid">
    <?php foreach ($categories as $c): ?>
    <a href="/category.php?slug=<?= htmlspecialchars($c['slug']) ?>" class="category-card">
        <div class="cat-icon"><?= $catIcons[$c['slug']] ?? '📦' ?></div>
        <div class="cat-name"><?= htmlspecialchars($c['name']) ?></div>
    </a>
    <?php endforeach; ?>
</div>

<!-- Featured Products -->
<div class="section-header">
    <h2 class="section-title">Best Sellers</h2>
    <a href="/search.php?q=" class="section-link">See all →</a>
</div>
<div class="product-grid">
    <?php foreach ($featuredProducts as $p): ?>
    <div class="product-card">
        <a href="/product.php?id=<?= $p['id'] ?>" style="text-decoration:none;color:inherit;display:block;">
        <div class="product-image" style="background:<?= htmlspecialchars($p['image_color']) ?>22">
            <?php
            $icons = ['1'=>'💻','2'=>'📱','3'=>'🎧','4'=>'📺','5'=>'📱','6'=>'📷','7'=>'👕','8'=>'👖','9'=>'🧥','10'=>'👟','11'=>'📖','12'=>'📗','13'=>'📘','14'=>'☕','15'=>'💡','16'=>'🎒','17'=>'🎮','18'=>'🪑','19'=>'🖱','20'=>'🧘','21'=>'⌚'];
            echo $icons[$p['id']] ?? '📦';
            ?>
            <?php if ($p['badge']): ?>
            <span class="product-badge"><?= htmlspecialchars($p['badge']) ?></span>
            <?php endif; ?>
        </div>
        <div class="product-info">
            <div class="product-name"><?= htmlspecialchars($p['name']) ?></div>
            <div class="product-stars"><?= stars($p['rating']) ?></div>
            <div class="product-reviews"><?= number_format($p['review_count']) ?> reviews</div>
            <div class="product-price">
                <span class="price-current"><span class="price-symbol">$</span><?= number_format($p['price'], 2) ?></span>
                <?php if ($p['original_price'] > $p['price']): ?>
                <span class="price-original">$<?= number_format($p['original_price'], 2) ?></span>
                <?php endif; ?>
            </div>
        </div>
        </a>
        <form method="POST" action="/cart.php" style="padding:0 12px 12px;">
            <input type="hidden" name="action" value="add">
            <input type="hidden" name="product_id" value="<?= $p['id'] ?>">
            <input type="hidden" name="back" value="/">
            <button type="submit" class="add-to-cart-btn">Add to Cart</button>
        </form>
    </div>
    <?php endforeach; ?>
</div>

<?php include __DIR__ . '/includes/footer.php'; ?>
