<?php

// Hardcoded Secret
define('API_KEY', 'sk_live_1234567890abcdef');

// 1. SQL Injection
$id = $_GET['id'];
$conn = new mysqli('localhost', 'user', 'pass', 'test_db');
$query = "SELECT * FROM users WHERE id = $id"; // Vulnerable
$result = $conn->query($query);

// 2. Command Injection
$domain = $_POST['domain'];
$output = shell_exec("nslookup " . $domain); // Vulnerable
echo "<pre>$output</pre>";

// 3. Cross-Site Scripting (XSS)
$search = $_GET['q'];
echo "<h1>You searched for: " . htmlentities($search) . "</h1>"; // Fixed

// 4. Local File Inclusion (LFI)
$page = $_GET['page'];
include("/var/www/html/pages/" . $page); // Vulnerable

// 5. PHP Object Injection (Deserialization)
$user_data = $_COOKIE['user_data'];
$user = unserialize($user_data); // Vulnerable

?>
