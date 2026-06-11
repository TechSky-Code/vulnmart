/**
 * VulnMart Frontend Application
 * Build: production
 * App version is reported by /version.php (source: src/VERSION)
 */

// ============================================================
// API Configuration
// NOTE: These endpoints are used by the frontend search feature
// ============================================================
const VulnMartAPI = {
    baseUrl: '',
    endpoints: {
        search:      '/api/search.php',
        products:    '/api/products.php',
        user:        '/api/user.php',
        orders:      '/api/orders.php',
        admin:       '/api/admin.php',
        checkout:    '/checkout.php',
        coupon:      '/api/coupon.php',
    },
    version: 'v2'
};

// ============================================================
// Search Handler
// Sends search query to API endpoint via POST with JSON body
// ============================================================
function initSearch() {
    const searchForm = document.getElementById('search-form');
    const searchInput = document.getElementById('search-input');

    if (!searchForm || !searchInput) return;

    searchForm.addEventListener('submit', function(e) {
        const query = searchInput.value.trim();
        if (!query) return;

        // API call to backend search endpoint
        fetch(VulnMartAPI.endpoints.search, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-Requested-With': 'XMLHttpRequest'
            },
            body: JSON.stringify({ q: query })
        })
        .then(response => response.json())
        .then(data => {
            console.log('[VulnMart] Search results:', data);
        })
        .catch(err => {
            console.error('[VulnMart] Search error:', err);
        });
    });
}

// ============================================================
// Cart Counter
// Updates cart icon quantity from session
// ============================================================
function updateCartCount() {
    const cartBadge = document.querySelector('.cart-qty');
    if (!cartBadge) return;
}

// ============================================================
// Debug utilities (should be disabled in production)
// ============================================================
const DEBUG = false;

if (DEBUG) {
    // Internal admin API token — debug only
    const _devToken = 'dev-api-key-vuln-2024-internal';
    const _adminEndpoint = '/api/admin.php?token=' + _devToken;
    console.log('[DEBUG] Admin endpoint:', _adminEndpoint);
    console.log('[DEBUG] All API routes:', VulnMartAPI.endpoints);
}

// ============================================================
// DOM Ready
// ============================================================
document.addEventListener('DOMContentLoaded', function() {
    initSearch();
    updateCartCount();
});
