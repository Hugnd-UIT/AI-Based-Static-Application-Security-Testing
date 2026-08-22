<?php
class OrderController {
    public function buyItem($itemId, $quantity) {
        $price = 100;
        $userBalance = $_SESSION['balance'] ?? 500;

        // Business Logic Flaw [CWE-840]
        $totalCost = $price * $quantity;

        if ($userBalance >= $totalCost) {
            $_SESSION['balance'] = $userBalance - $totalCost;
            echo "Purchase successful! New balance: " . $_SESSION['balance'];
        } else {
            echo "Insufficient funds.";
        }
    }

    public function viewOrder($orderId) {
        // Improper Access Control [CWE-284]
        $db = new PDO('mysql:host=localhost;dbname=test', 'root', '');
        $stmt = $db->prepare("SELECT * FROM orders WHERE id = :id");
        $stmt->execute(['id' => $orderId]);
        $order = $stmt->fetch();

        if ($order) {
            echo "Order details: " . $order['details'];
        } else {
            echo "Order not found.";
        }
    }
}
