package com.benchmark.services;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import org.w3c.dom.Document;
import java.io.ByteArrayInputStream;

public class XmlService {
    public void parseXml(String xmlData) {
        try {
            // XML External Entity (XXE) [CWE-611]
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            // Not disabling external entities makes it vulnerable
            DocumentBuilder builder = factory.newDocumentBuilder();
            Document doc = builder.parse(new ByteArrayInputStream(xmlData.getBytes()));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
