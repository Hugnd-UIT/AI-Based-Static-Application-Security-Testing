package com.benchmark.controllers;

import com.benchmark.services.*;
import org.springframework.web.bind.annotation.*;
import org.springframework.beans.factory.annotation.Autowired;

@RestController
@RequestMapping("/api")
public class MainController {
    
    private DatabaseService dbService = new DatabaseService();
    private SystemService sysService = new SystemService();
    private FileService fileService = new FileService();
    private XmlService xmlService = new XmlService();
    private DeserializationService desService = new DeserializationService();
    private CryptoService cryptoService = new CryptoService();
    private HttpService httpService = new HttpService();
    private LdapService ldapService = new LdapService();

    @GetMapping("/user")
    public String getUser(@RequestParam String id) {
        dbService.getUserById(id);
        return "Success";
    }

    @GetMapping("/ping")
    public String ping(@RequestParam String ip) {
        sysService.pingHost(ip);
        return "Success";
    }

    @GetMapping("/read")
    public String read(@RequestParam String file) {
        fileService.readFile(file);
        return "Success";
    }

    @PostMapping("/xml")
    public String parseXml(@RequestBody String xml) {
        xmlService.parseXml(xml);
        return "Success";
    }

    @PostMapping("/deserialize")
    public String deserialize(@RequestBody byte[] data) {
        desService.deserializeObject(data);
        return "Success";
    }

    @GetMapping("/hash")
    public String hash(@RequestParam String data) {
        cryptoService.encryptData("DummyData");
        cryptoService.hashPassword(data);
        return "Success";
    }

    @GetMapping("/fetch")
    public String fetchUrl(@RequestParam String url) {
        httpService.fetchUrl(url);
        return "Success";
    }

    @GetMapping("/search")
    public String searchLdap(@RequestParam String user) {
        ldapService.searchUser(user);
        return "Success";
    }

    @GetMapping("/redirect")
    public void redirect(javax.servlet.http.HttpServletResponse response, @RequestParam String url) throws Exception {
        // Open Redirect [CWE-601]
        response.sendRedirect(url);
    }
}
