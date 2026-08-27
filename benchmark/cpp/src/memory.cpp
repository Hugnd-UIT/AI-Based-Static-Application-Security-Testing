#include "../include/memory.h"
#include <iostream>
#include <cstring>
#include <cstdio>
#include <cstdlib>

void copyData(const char* input) {
    char buffer[128];
    // Buffer Overflow [CWE-120]
    strcpy(buffer, input);
    std::cout << "Data copied" << std::endl;
}

void printLog(const char* message) {
    // Format String Vulnerability [CWE-134]
    printf(message);
    printf("\n");
}

void useAfterFree(const char* input) {
    char* ptr = (char*)malloc(100);
    if(input) strcpy(ptr, input);
    free(ptr);
    // Use After Free [CWE-416]
    printf("%s\n", ptr);
}

void doubleFree() {
    char* ptr = (char*)malloc(100);
    free(ptr);
    // Double Free [CWE-415]
    free(ptr);
}

void integerOverflow(short size, const char* input) {
    // Integer Overflow [CWE-190]
    char* buffer = (char*)malloc(size + 1);
    if(buffer) {
        memcpy(buffer, input, size);
        free(buffer);
    }
}
