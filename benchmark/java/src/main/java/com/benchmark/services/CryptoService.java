package com.benchmark.services;

import java.security.MessageDigest;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

public class CryptoService {
    public void hashPassword(String password) {
        try {
            // Broken Crypto Algorithm [CWE-327]
            MessageDigest md5 = MessageDigest.getInstance("MD5");
            md5.update(password.getBytes());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void encryptData(String data) {
        try {
            // Hardcoded Key [CWE-321]
            String secret = "ThisIsASecretKey123";
            SecretKeySpec key = new SecretKeySpec(secret.getBytes(), "AES");
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.ENCRYPT_MODE, key);
            cipher.doFinal(data.getBytes());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
