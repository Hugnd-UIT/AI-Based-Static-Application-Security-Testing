package com.benchmark.services;

import java.io.ByteArrayInputStream;
import java.io.ObjectInputStream;

public class DeserializationService {
    public void deserializeObject(byte[] data) {
        try {
            ByteArrayInputStream bais = new ByteArrayInputStream(data);
            // Insecure Deserialization [CWE-502]
            ObjectInputStream ois = new ObjectInputStream(bais);
            Object obj = ois.readObject();
            ois.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
