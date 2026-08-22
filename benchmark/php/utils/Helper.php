<?php
class Helper {
    public function readFile($filename) {
        // Local File Inclusion [CWE-98]
        include($filename);
    }

    public function ping($ip) {
        // Command Injection [CWE-78]
        $cmd = "ping -c 4 " . $ip;
        system($cmd);
    }
}
