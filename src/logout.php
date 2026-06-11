<?php
require_once __DIR__ . '/config.php';
session_destroy();
redirect('/login.php');
