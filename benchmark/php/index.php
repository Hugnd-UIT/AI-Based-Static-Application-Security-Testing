<?php
require_once 'controllers/UserController.php';
require_once 'controllers/OrderController.php';
require_once 'utils/Helper.php';

$route = $_GET['route'] ?? 'home';

switch ($route) {
    case 'login':
        $userController = new UserController();
        $userController->login($_POST['username'] ?? '', $_POST['hash'] ?? '');
        break;

    case 'admin':
        $userController = new UserController();
        $userController->adminPanel();
        break;

    case 'buy':
        $orderController = new OrderController();
        $orderController->buyItem($_POST['item_id'] ?? 0, $_POST['quantity'] ?? 1);
        break;

    case 'view_order':
        $orderController = new OrderController();
        $orderController->viewOrder($_GET['order_id'] ?? 0);
        break;

    case 'read':
        $helper = new Helper();
        $helper->readFile($_GET['file'] ?? '');
        break;

    case 'ping':
        $helper = new Helper();
        $helper->ping($_GET['ip'] ?? '');
        break;

    case 'redirect':
        // Open Redirect [CWE-601]
        header("Location: " . $_GET['url']);
        break;

    case 'load':
        // Insecure Deserialization [CWE-502]
        $data = unserialize($_COOKIE['user_session']);
        echo "Loaded data";
        break;

    case 'greet':
        // Cross-Site Scripting (XSS) [CWE-79]
        $name = $_GET['name'] ?? 'Guest';
        echo "<h1>Welcome, " . $name . "</h1>";
        break;

    default:
        echo "Welcome to PHP Benchmark API";
        break;
}
