<?php

// Vulnerability 1: Remote Code Execution (RCE) via eval
if (isset($_GET['calc'])) {
    $expression = $_GET['calc'];
    
    // SINK
    eval("return " . $expression . ";");
}

// Vulnerability 2: Local File Inclusion (LFI)
if (isset($_GET['page'])) {
    $page = $_GET['page'];
    
    // SINK
    include($page . ".php");
}

// Vulnerability 3: Insecure Deserialization
class UserProfile {
    public $name;
    public $role;
    
    public function __wakeup() {
        if ($this->role === 'admin') {
            // Give admin privileges
        }
    }
}

if (isset($_COOKIE['session'])) {
    $data = $_COOKIE['session'];
    // SINK
    $user = unserialize(base64_decode($data));
}

?>
