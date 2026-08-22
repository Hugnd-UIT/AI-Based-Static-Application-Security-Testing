package com.benchmark.services;

import java.net.URL;
import java.net.URLConnection;
import java.io.InputStream;

public class HttpService {
    public void fetchUrl(String targetUrl) {
        try {
            // Server-Side Request Forgery (SSRF) [CWE-918]
            URL url = new URL(targetUrl);
            URLConnection connection = url.openConnection();
            InputStream in = connection.getInputStream();
            in.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
