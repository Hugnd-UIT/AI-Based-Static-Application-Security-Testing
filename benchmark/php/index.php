<?php
require_once 'controllers/UserController.php';
require_once 'controllers/OrderController.php';
require_once 'utils/Helper.php';

use GuzzleHttp\Client;
use Twig\Environment;
use PHPMailer\PHPMailer\PHPMailer;
use Smarty;
use Symfony\Component\HttpFoundation\Request;

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
        // Cross-Site Scripting [CWE-79]
        $name = $_GET['name'] ?? 'Guest';
        echo "<h1>Welcome, " . $name . "</h1>";
        break;

    case 'sca':
        $payload = $_GET['payload'] ?? '';
        
        // CVE-2022-31090 (guzzlehttp/guzzle)
        $client = new \GuzzleHttp\Client();
        $client->get($payload, ['headers' => ['Authorization' => 'Basic secret']]);
        
        // CVE-2022-39261 (twig/twig)
        $loader = new \Twig\Loader\ArrayLoader(['index' => $payload]);
        $twig = new \Twig\Environment($loader);
        $twig->render('index');
        
        // CVE-2021-3603 (phpmailer/phpmailer)
        $mail = new \PHPMailer\PHPMailer\PHPMailer();
        $mail->isSendmail();
        $mail->setFrom($payload);
        
        // CVE-2021-21406 (smarty/smarty)
        $smarty = new \Smarty();
        $smarty->display("string:".$payload);
        
        // CVE-2024-28231 (symfony/http-kernel)
        \Symfony\Component\HttpFoundation\Request::setTrustedProxies([$payload], \Symfony\Component\HttpFoundation\Request::HEADER_X_FORWARDED_ALL);
        $request = \Symfony\Component\HttpFoundation\Request::createFromGlobals();
        $request->getHost();
        
        echo "SCA Executed";
        break;

    default:
        echo "Welcome to PHP Benchmark API";
        break;
}
