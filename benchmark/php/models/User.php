<?php
class User {
    private $db;

    public function __construct() {
        $this->db = new PDO('mysql:host=localhost;dbname=test', 'root', '');
    }

    public function findByUsername($username) {
        // SQL Injection [CWE-89]
        $sql = "SELECT * FROM users WHERE username = '" . $username . "'";
        return $this->db->query($sql)->fetch();
    }
}
