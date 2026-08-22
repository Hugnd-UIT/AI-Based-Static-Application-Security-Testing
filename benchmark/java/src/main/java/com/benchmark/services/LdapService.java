package com.benchmark.services;

import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import javax.naming.directory.SearchControls;
import javax.naming.directory.NamingEnumeration;

public class LdapService {
    public void searchUser(String username) {
        try {
            DirContext ctx = new InitialDirContext();
            SearchControls controls = new SearchControls();
            
            // LDAP Injection [CWE-90]
            String filter = "(uid=" + username + ")";
            NamingEnumeration results = ctx.search("ou=users,dc=example,dc=com", filter, controls);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
