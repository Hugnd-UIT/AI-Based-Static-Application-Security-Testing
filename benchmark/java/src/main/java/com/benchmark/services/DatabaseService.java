package com.benchmark.services;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.Statement;

public class DatabaseService {
    public void getUserById(String id) {
        try {
            Connection conn = DriverManager.getConnection("jdbc:mysql://localhost/test", "root", "password");
            Statement stmt = conn.createStatement();
            // SQL Injection [CWE-89]
            String query = "SELECT * FROM users WHERE id = '" + id + "'";
            stmt.executeQuery(query);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
