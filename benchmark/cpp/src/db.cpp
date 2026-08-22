#include "../include/db.h"
#include <iostream>
#include <string>

void executeQuery(const std::string& query) {
    // Dummy execute
    std::cout << "Executing: " << query << std::endl;
}

void fetchUser(const std::string& userId) {
    // SQL Injection [CWE-89]
    std::string query = "SELECT * FROM users WHERE id = '" + userId + "'";
    executeQuery(query);
}
