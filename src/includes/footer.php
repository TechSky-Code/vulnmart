</main>

<footer class="site-footer">
    <div class="footer-top">
        <div class="footer-col">
            <h4>Get to Know Us</h4>
            <a href="#">About VulnMart</a>
            <a href="#">Careers</a>
            <a href="#">Press Releases</a>
        </div>
        <div class="footer-col">
            <h4>Make Money with Us</h4>
            <a href="#">Sell products on VulnMart</a>
            <a href="#">Affiliate Program</a>
        </div>
        <div class="footer-col">
            <h4>Let Us Help You</h4>
            <a href="/profile.php">Your Account</a>
            <a href="/orders.php">Your Orders</a>
            <a href="/cart.php">Cart</a>
            <a href="/checkout.php">Checkout</a>
            <a href="/fileops.php">Receipt Lookup</a>
            <a href="/recommend.php">Recommended</a>
            <a href="#">Returns &amp; Replacements</a>
        </div>
    </div>
    <div class="footer-bottom">
        <span class="site-logo-sm">🛒 VulnMart</span>
        <p>⚠️ This is an intentionally vulnerable web application for security training.</p>
        <p>Do not deploy on a public network. For educational use only.</p>
        <p style="opacity:.6;font-size:12px;margin-top:6px;">VulnMart v<?= htmlspecialchars(defined('VULNMART_VERSION') ? VULNMART_VERSION : 'dev') ?></p>
    </div>
</footer>

<script src="/assets/js/app.js"></script>
</body>
</html>
