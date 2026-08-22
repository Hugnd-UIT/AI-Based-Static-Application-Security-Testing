package com.benchmark.services;

public class SystemService {
    public void pingHost(String ipAddress) {
        try {
            // Command Injection [CWE-78]
            String cmd = "ping -c 4 " + ipAddress;
            Runtime.getRuntime().exec(cmd);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
