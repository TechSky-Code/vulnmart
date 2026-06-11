-- VulnMart Database Initialization
-- Intentionally vulnerable platform for SQL Injection training

CREATE DATABASE IF NOT EXISTS vulnmart CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE vulnmart;

-- ============================================================
-- TABLES
-- ============================================================

CREATE TABLE categories (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(50) NOT NULL,
    slug VARCHAR(50) UNIQUE NOT NULL,
    icon VARCHAR(10)
);

CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(255) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
    email VARCHAR(100) UNIQUE NOT NULL,
    full_name VARCHAR(100),
    address TEXT,
    phone VARCHAR(20),
    role ENUM('user', 'admin') DEFAULT 'user',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE products (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(200) NOT NULL,
    description TEXT,
    price DECIMAL(10,2) NOT NULL,
    original_price DECIMAL(10,2),
    category_id INT,
    stock INT DEFAULT 100,
    rating DECIMAL(2,1) DEFAULT 4.0,
    review_count INT DEFAULT 0,
    badge VARCHAR(30),
    image_color VARCHAR(7) DEFAULT '#FF9900',
    FOREIGN KEY (category_id) REFERENCES categories(id)
);

CREATE TABLE orders (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT,
    total_amount DECIMAL(10,2) NOT NULL,
    status ENUM('pending','processing','shipped','delivered','cancelled') DEFAULT 'pending',
    shipping_address TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE TABLE order_items (
    id INT AUTO_INCREMENT PRIMARY KEY,
    order_id INT,
    product_id INT,
    quantity INT NOT NULL,
    price DECIMAL(10,2) NOT NULL,
    FOREIGN KEY (order_id) REFERENCES orders(id),
    FOREIGN KEY (product_id) REFERENCES products(id)
);

CREATE TABLE activity_logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_agent TEXT,
    ip_address VARCHAR(100),
    page VARCHAR(100),
    action VARCHAR(200),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE receipts (
    id INT AUTO_INCREMENT PRIMARY KEY,
    order_ref VARCHAR(50) UNIQUE NOT NULL,
    amount DECIMAL(10,2),
    status VARCHAR(20),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE reviews (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    product_id INT NOT NULL,
    rating TINYINT DEFAULT 5,
    review TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id),
    FOREIGN KEY (product_id) REFERENCES products(id)
);

CREATE TABLE user_preferences (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT UNIQUE,
    theme VARCHAR(20) DEFAULT 'light',
    newsletter TINYINT DEFAULT 1,
    FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE TABLE settings (
    page VARCHAR(50) PRIMARY KEY,
    difficulty ENUM('low','medium','hard') DEFAULT 'low',
    description VARCHAR(200),
    show_hints TINYINT(1) DEFAULT 1,
    show_query_log TINYINT(1) DEFAULT 1,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

-- ============================================================
-- SEED DATA: Categories
-- ============================================================

INSERT INTO categories (name, slug, icon) VALUES
('Electronics',   'electronics',   'laptop'),
('Clothing',      'clothing',      'shirt'),
('Books',         'books',         'book'),
('Home & Kitchen','home-kitchen',  'home'),
('Gaming',        'gaming',        'gamepad'),
('Sports',        'sports',        'sports');

-- ============================================================
-- SEED DATA: Products
-- ============================================================

INSERT INTO products (name, description, price, original_price, category_id, stock, rating, review_count, badge, image_color) VALUES
-- Electronics
('ProBook Laptop 15"',       'High-performance laptop with Intel Core i7, 16GB RAM, 512GB NVMe SSD. Backlit keyboard, fingerprint reader, 10-hour battery life. Perfect for professionals and developers.',    899.99, 1199.99, 1, 45, 4.5, 2341, 'Best Seller', '#1565C0'),
('UltraPhone X12',           '6.7" AMOLED display, Snapdragon 8 Gen 2, 5G, 256GB storage, 108MP triple camera. Includes 65W fast charger.',                                                                 699.99,  849.99, 1, 120, 4.3, 5672, '#1 New Release', '#6A1B9A'),
('SoundMax Pro Headphones',  'Premium ANC wireless headphones. 40-hour battery, hi-res audio certified, multipoint pairing. Includes carrying case.',                                                         149.99,  249.99, 1, 200, 4.7, 8934, 'Amazons Choice', '#BF360C'),
('ViewSmart 55" 4K TV',      'Crystal 4K UHD, HDR10+, 120Hz refresh, built-in Alexa, 4x HDMI 2.1. Incredibly thin bezel design.',                                                                           549.99,  799.99, 1,  30, 4.4, 3211, NULL,            '#37474F'),
('TabPro 10.5"',             '10.5" Retina display, A15 chip, 128GB, Face ID, all-day battery. Supports stylus and keyboard accessories.',                                                                   399.99,  499.99, 1,  80, 4.2, 1876, NULL,            '#00838F'),
('SnapShot DSLR Camera',     '24.2MP APS-C sensor, 4K/60fps video, Dual Pixel CMOS AF, weather-sealed body. Kit includes 18-55mm IS lens and 64GB memory card.',                                            649.99,  849.99, 1,  25, 4.6,  967, 'Limited Deal',  '#4E342E'),
-- Clothing
('Classic Fit Cotton Tee',   '100% GOTS-certified organic cotton. Pre-shrunk, tag-free, reinforced seams. Available in 18 colors. Machine wash cold.',                                                        19.99,   29.99, 2, 500, 4.4,12045, 'Best Seller', '#2E7D32'),
('SlimFit Stretch Jeans',    'Premium Japanese denim with 2% elastane. 5-pocket styling, YKK zipper, slim through thigh. Available in dark wash and black.',                                                  59.99,   89.99, 2, 300, 4.3, 6732, NULL,          '#283593'),
('Packable Windbreaker',     'Lightweight ripstop nylon, DWR coating, fully packable into chest pocket. 3 zippered pockets, adjustable hem and cuffs.',                                                       79.99,  119.99, 2, 150, 4.5, 3421, NULL,          '#C62828'),
('Trail Running Shoes',      'Carbon fiber plate, nitrogen-infused foam midsole, Vibram megagrip outsole. 8mm stack height. Ships same day.',                                                                  89.99,  129.99, 2, 200, 4.6, 4567, 'Hot Pick',    '#E65100'),
-- Books
('The Web App Hacker Handbook', 'The definitive guide to finding and exploiting security flaws in web applications. Covers SQLi, XSS, CSRF, IDOR and more. Essential reading for bug bounty hunters.',       49.99,   69.99, 3,1000, 4.8, 2341, 'Best Seller', '#546E7A'),
('Python Crash Course, 3rd Ed', 'Hands-on, project-based Python introduction. Projects include a game, data visualizations, and a web app. Ideal for complete beginners.',                                   34.99,   44.99, 3, 800, 4.7, 8923, NULL,          '#F9A825'),
('Network Security Essentials',  'Comprehensive guide to protecting networks. Covers TCP/IP threats, IDS/IPS, VPNs, firewalls, and incident response. Includes lab exercises.',                              44.99,   59.99, 3, 600, 4.5, 1234, NULL,          '#AD1457'),
-- Home & Kitchen
('BrewMaster 12-Cup Coffee Maker','Thermal carafe keeps coffee hot 4 hours. Built-in grinder, programmable 24hr timer, strength control, pause-and-pour. Stainless steel finish.',                          129.99,  179.99, 4, 100, 4.4, 5678, NULL,          '#5D4037'),
('TechDesk LED Lamp',            'Touch-dimming, 5 color temperatures (2700K-6500K), USB-C and USB-A charging ports, auto-timer, memory function. 50,000hr LED lifespan.',                                   39.99,   59.99, 4, 300, 4.5, 3456, 'Top Rated',   '#F57F17'),
('Carry-On Backpack 40L',        'TSA laptop-compatible main compartment, hidden anti-theft pocket, USB passthrough, luggage sleeve. Fits 15.6" laptops. Lifetime warranty.',                                69.99,   99.99, 4, 250, 4.6, 7890, NULL,          '#546E7A'),
-- Gaming
('GamePad Pro Wireless Controller','Haptic feedback, adaptive triggers, 3D audio via built-in speaker, rechargeable 1560mAh battery. Includes USB-C cable. Compatible with PC.',                            69.99,   89.99, 5, 180, 4.7, 9234, 'Best Seller', '#212121'),
('ErgoPro Gaming Chair',           'Class 4 gas lift, 4D armrests, lumbar + headrest pillows, 165° recline, cold-cure foam seat. BIFMA certified. Ships fully assembled.',                                 299.99,  449.99, 5,  50, 4.4, 2341, NULL,          '#B71C1C'),
('Viper V3 Pro Gaming Mouse',      '30K DPI optical sensor, 95g ultralight, 6 programmable buttons, per-RGB, 90-hour battery. Includes grip tape and extra skates.',                                         79.99,  119.99, 5, 200, 4.6, 4567, 'Top Rated',   '#4A148C'),
-- Sports
('YogaFlex Premium Mat',           'Extra-thick 6mm TPE foam, non-slip microfiber top, alignment lines, carrying strap. Eco-friendly, latex-free. Sweat-resistant surface.',                                 29.99,   49.99, 6, 400, 4.5, 6789, NULL,          '#1B5E20'),
('FitTrack Pro Smart Watch',       'GPS, continuous heart rate & SpO2, sleep tracking, 7-day battery, IP68 water resistant, 100+ workout modes. Compatible with iOS & Android.',                            159.99,  229.99, 6, 150, 4.3, 3456, 'New Release', '#0D47A1');

-- ============================================================
-- SEED DATA: Users
-- Passwords stored in plaintext intentionally for LOW difficulty
-- ============================================================

INSERT INTO users (username, password, email, full_name, address, phone, role) VALUES
-- Passwords stored as MD5 hashes (intentionally weak for training)
-- admin123     = 0192023a7bbd73250516f069df18b500
-- password123  = 482c811da5d5b4bc6d497ffa98491e38
-- letmein      = 0d107d09f5bbe40cade3de5c71e9e9b7
-- qwerty123    = 507b3b1c44bbaeb4bfcbf1e745e5de78
('admin',       '0192023a7bbd73250516f069df18b500', 'admin@vulnmart.com',  'Admin User',    '1 VulnMart HQ, Server City, SC 00001', '555-0001', 'admin'),
('john_doe',    '482c811da5d5b4bc6d497ffa98491e38', 'john@example.com',    'John Doe',      '456 Main St, Springfield, IL 62701',   '555-0002', 'user'),
('alice_smith', '0d107d09f5bbe40cade3de5c71e9e9b7', 'alice@example.com',   'Alice Smith',   '789 Oak Ave, Portland, OR 97201',      '555-0003', 'user'),
('bob_jones',   '507b3b1c44bbaeb4bfcbf1e745e5de78', 'bob@example.com',     'Bob Jones',     '321 Pine Rd, Austin, TX 78701',        '555-0004', 'user');

-- ============================================================
-- SEED DATA: Orders
-- ============================================================

INSERT INTO orders (user_id, total_amount, status, shipping_address) VALUES
(2, 1049.98, 'delivered',  '456 Main St, Springfield, IL 62701'),
(2,  149.99, 'shipped',    '456 Main St, Springfield, IL 62701'),
(3,  699.99, 'delivered',  '789 Oak Ave, Portland, OR 97201'),
(4,  369.98, 'processing', '321 Pine Rd, Austin, TX 78701');

INSERT INTO order_items (order_id, product_id, quantity, price) VALUES
(1,  1, 1, 899.99),
(1,  8, 1,  59.99),
(2,  3, 1, 149.99),
(3,  2, 1, 699.99),
(4, 17, 1, 299.99),
(4,  9, 1,  79.99);

-- ============================================================
-- SEED DATA: Preferences
-- ============================================================

INSERT INTO receipts (order_ref, amount, status) VALUES
('RCP-2024-001', 1049.98, 'delivered'),
('RCP-2024-002',  149.99, 'shipped'),
('RCP-2024-003',  699.99, 'delivered'),
('RCP-2024-004',  369.98, 'processing');

INSERT INTO user_preferences (user_id, theme, newsletter) VALUES
(2, 'light', 1),
(3, 'dark',  0),
(4, 'light', 1);

-- ============================================================
-- SEED DATA: Difficulty settings
-- ============================================================

INSERT INTO settings (page, difficulty, description, show_hints, show_query_log) VALUES
('search',    'low', 'GET ?q= — Error-based + UNION-based SQLi',         1, 1),
('product',   'low', 'GET ?id= — UNION-based + Boolean Blind SQLi',      1, 1),
('login',     'low', 'POST — Authentication Bypass SQLi',                 1, 1),
('profile',   'low', 'GET ?user= — Time-based Blind SQLi',               1, 1),
('orders',    'low', 'Session — Second-Order SQLi',                       1, 1),
('category',  'low', 'Header — X-Forwarded-For Injection',               1, 1),
('admin',     'low', 'Admin Panel — Stacked Queries',                     1, 1),
('global',    'low', 'Global UI settings — show_hints and show_query_log',0, 0),
('fileops',   'low', 'GET receipt= — LOAD_FILE + INTO OUTFILE injection', 1, 1),
('api_search','low', 'POST JSON body — JSON injection via API endpoint',  1, 1),
('recommend', 'low', 'Cookie last_category — Cookie-based injection',     1, 1),
('xss',       'low', 'GET search= + POST review — Reflected + Stored XSS',  1, 1),
('csrf',      'low', 'POST profile update — No CSRF token protection',       1, 1),
('upload',    'low', 'POST file — No server-side file type validation',      1, 1),
('checkout',  'low', 'POST checkout — Price manipulation, coupon reuse, negative qty', 1, 0);

-- ============================================================
-- FILE privilege for the fileops.php training exercise
-- (LOAD_FILE + INTO OUTFILE). Combined with --secure-file-priv=
-- on the server, this makes the file read/write demos actually
-- work inside the lab. This is intentional and only safe because
-- VulnMart is a deliberately vulnerable app never exposed publicly.
-- ============================================================
GRANT FILE ON *.* TO 'vulnmart'@'%';
FLUSH PRIVILEGES;
