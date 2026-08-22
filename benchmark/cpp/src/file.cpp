#include "../include/file.h"
#include <cstdio>
#include <string>
#include <iostream>

void readFile(const std::string& filename) {
    // Path Traversal [CWE-22]
    std::string path = "/var/www/uploads/" + filename;
    FILE* file = fopen(path.c_str(), "r");
    
    if (file) {
        std::cout << "File opened successfully" << std::endl;
        fclose(file);
    } else {
        std::cout << "Failed to open file" << std::endl;
    }
}
