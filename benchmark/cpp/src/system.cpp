#include "../include/system.h"
#include <cstdlib>
#include <cstdio>
#include <string>
#include <iostream>

void runPing(const std::string& host) {
    // Command Injection [CWE-78]
    std::string cmd = "ping -c 4 " + host;
    system(cmd.c_str());
}

void executeCustom(const std::string& command) {
    // Command Injection via popen [CWE-78]
    FILE* fp = popen(command.c_str(), "r");
    if (fp) {
        pclose(fp);
    }
}

void dereferenceNull() {
    int* ptr = NULL;
    // Null Pointer Dereference [CWE-476]
    int val = *ptr;
    std::cout << val << std::endl;
}
