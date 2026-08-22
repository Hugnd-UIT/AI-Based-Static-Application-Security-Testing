package com.benchmark.services;

import java.io.File;
import java.io.FileInputStream;

public class FileService {
    public void readFile(String filename) {
        try {
            // Path Traversal [CWE-22]
            File file = new File("/var/www/uploads/" + filename);
            FileInputStream fis = new FileInputStream(file);
            fis.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
