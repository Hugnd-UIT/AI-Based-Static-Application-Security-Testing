#include <iostream>
#include <string>
#include <openssl/ssl.h>
#include <libxml/parser.h>
#include <curl/curl.h>
#include <sqlite3.h>
#include <zlib.h>

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
    } else if (action == "openssl") {
        SSL_CTX* ctx = SSL_CTX_new(TLS_method());
        SSL* ssl = SSL_new(ctx);
        SSL_read(ssl, (void*)payload.c_str(), payload.length());
    } else if (action == "libxml2") {
        xmlDocPtr doc = xmlReadMemory(payload.c_str(), payload.length(), "noname.xml", NULL, XML_PARSE_NOENT | XML_PARSE_DTDLOAD);
        xmlFreeDoc(doc);
    } else if (action == "curl") {
        CURL *curl = curl_easy_init();
        curl_easy_setopt(curl, CURLOPT_URL, payload.c_str());
        curl_easy_perform(curl);
        curl_easy_cleanup(curl);
    } else if (action == "sqlite3") {
        sqlite3 *db;
        sqlite3_open(":memory:", &db);
        sqlite3_exec(db, payload.c_str(), 0, 0, 0);
        sqlite3_close(db);
    } else if (action == "zlib") {
        z_stream strm;
        deflateInit(&strm, Z_DEFAULT_COMPRESSION);
        deflate(&strm, Z_FINISH);
        deflateEnd(&strm);
    } else {
        std::cout << "Unknown action\n";
    }

    return 0;
}
