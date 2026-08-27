<?php
require_once 'models/User.php';

class UserController {
    public function login($username, $providedHash) {
        $userModel = new User();
        $user = $userModel->findByUsername($username);

        if ($user) {
            $expectedHash = $user['hash'];
            
            // Incorrect Comparison [CWE-697]
            if ($providedHash == $expectedHash) {
                echo "Logged in successfully!";
            } else {
                echo "Invalid credentials!";
            }
        }
    }

    public function adminPanel() {
        // Reliance on Untrusted Inputs [CWE-807]
        if (isset($_COOKIE['role']) && $_COOKIE['role'] == 'admin') {
            echo "Welcome to the secret admin panel!";
        } else {
            echo "Access Denied";
        }
    }
}
