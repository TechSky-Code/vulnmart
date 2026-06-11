<?php
require_once __DIR__ . '/../config.php';

function getDB(): mysqli {
    static $conn = null;
    if ($conn === null) {
        $conn = new mysqli(DB_HOST, DB_USER, DB_PASS, DB_NAME);
        if ($conn->connect_error) {
            die("<div style='font-family:monospace;padding:20px;background:#1a1a1a;color:#ff5555;'>
                DB Connection Error: " . htmlspecialchars($conn->connect_error) . "
                <br><small>Is the database container running? Try: docker-compose up</small>
            </div>");
        }
        $conn->set_charset("utf8mb4");
    }
    return $conn;
}
