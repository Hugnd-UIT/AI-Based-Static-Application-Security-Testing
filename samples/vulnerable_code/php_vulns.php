<?php
$db = new mysqli("localhost", "user", "pass", "mydb");

// Zero-day IDOR: Deleting arbitrary item
$item_id = $_POST['item_id'];
$stmt = $db->prepare("DELETE FROM items WHERE id = ?");
$stmt->bind_param("i", $item_id);
$stmt->execute();

// Known vuln: Eval injection
$code = $_GET['code'];
eval($code);
?>
