package com.benchmark.controllers;

import com.benchmark.services.*;
import org.springframework.web.bind.annotation.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.apache.logging.log4j.LogManager;
import com.alibaba.fastjson.JSON;
import org.springframework.web.servlet.ModelAndView;
import org.apache.commons.collections.functors.InvokerTransformer;
import com.fasterxml.jackson.databind.ObjectMapper;

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

    public static class MyPojo {
        private String name;
        public String getName() { return name; }
        public void setName(String name) { this.name = name; }
    }

    @PostMapping("/sca_spring")
    public String spring4shell(MyPojo payload) {
        // CVE-2022-22965 (spring-webmvc) DataBinder exploitation
        return "Spring";
    }

    @GetMapping("/sca")
    public String sca(@RequestParam String payload) throws Exception {
        // CVE-2021-44228 (log4j-core) Log4Shell
        org.apache.logging.log4j.LogManager.getLogger(MainController.class).error(payload);
        
        // CVE-2017-18349 (fastjson)
        com.alibaba.fastjson.JSON.parseObject(payload, com.alibaba.fastjson.parser.Feature.SupportNonPublicField);
        
        // CVE-2015-7501 (commons-collections)
        new org.apache.commons.collections.functors.InvokerTransformer(payload).transform(null);
        
        // CVE-2019-16942 (jackson-databind)
        com.fasterxml.jackson.databind.ObjectMapper mapper = new com.fasterxml.jackson.databind.ObjectMapper();
        mapper.enableDefaultTyping();
        mapper.readValue(payload, Object.class);
        
        return "Success";
    }
}
