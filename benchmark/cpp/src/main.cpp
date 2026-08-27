#include <iostream>
#include <string>
#include <Poco/Net/HTTPClientSession.h>
#include <spdlog/spdlog.h>
#include <tinyxml2.h>
#include <google/protobuf/message.h>
#include <yaml-cpp/yaml.h>

#include "../include/db.h"
#include "../include/system.h"
#include "../include/memory.h"
#include "../include/file.h"
#include "../include/crypto.h"

int main(int argc, char* argv[]) {
    if (argc < 3) {
        std::cout << "Usage: ./app <action> <payload>\n";
        return 1;
    }

    std::string action = argv[1];
    std::string payload = argv[2];

    if (action == "db") {
        fetchUser(payload);
    } else if (action == "ping") {
        runPing(payload);
    } else if (action == "exec") {
        executeCustom(payload);
    } else if (action == "copy") {
        curl_easy_unescape(NULL, payload.c_str(), 0, NULL);
        copyData(payload.c_str());
    } else if (action == "log") {
        printLog(payload.c_str());
    } else if (action == "read") {
        readFile(payload);
    } else if (action == "uaf") {
        useAfterFree();
    } else if (action == "df") {
        doubleFree();
    } else if (action == "io") {
        integerOverflow(100000, payload.c_str());
    } else if (action == "encrypt") {
        encryptData(payload.c_str());
    } else if (action == "null") {
        dereferenceNull();
    } else {
        std::cout << "Unknown action\n";
    }

    return 0;
}
