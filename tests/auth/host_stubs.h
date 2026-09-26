// Host adapters for exercising the real AuthManager implementation on Windows.
// Crypto uses Windows CNG; no production firmware code is replaced.
#include <windows.h>
#include <bcrypt.h>
#include <algorithm>
#include <cassert>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <map>
#include <string>
#include <vector>
#pragma comment(lib, "bcrypt.lib")
class String : public std::string {
public:
    using std::string::string;
    String(const std::string& value) : std::string(value) {}
    String(unsigned value) : std::string(std::to_string(value)) {}
    String(int value) : std::string(std::to_string(value)) {}
    bool isEmpty() const { return empty(); }
    bool startsWith(const String& prefix) const { return rfind(prefix, 0) == 0; }
    int indexOf(char value) const { auto pos = find(value); return pos == npos ? -1 : static_cast<int>(pos); }
    String substring(size_t start) const { return substr(start); }
    String substring(size_t start, size_t end) const { return substr(start, end - start); }
    void trim() { auto start = find_first_not_of(" \t"); *this = start == npos ? "" : substr(start, find_last_not_of(" \t") - start + 1); }
};
size_t strlcpy(char *target, const char *source, size_t length) { auto n = strlen(source); memcpy(target, source, std::min(n, length-1)); target[std::min(n, length-1)] = 0; return n; }
uint32_t ticks = 10000;
uint64_t epoch = 1800000000;
uint32_t millis() { return ticks; }
int64_t authTestTime(void *) { return static_cast<int64_t>(epoch); }
#define time authTestTime
void esp_fill_random(void *out, size_t size) { assert(BCryptGenRandom(nullptr, static_cast<PUCHAR>(out), static_cast<ULONG>(size), BCRYPT_USE_SYSTEM_PREFERRED_RNG) == 0); }
struct mbedtls_md_context_t {};
#define MBEDTLS_MD_SHA256 1
void mbedtls_md_init(mbedtls_md_context_t *) {}
void mbedtls_md_free(mbedtls_md_context_t *) {}
int mbedtls_md_info_from_type(int) { return 1; }
int mbedtls_md_setup(mbedtls_md_context_t *, int, int) { return 0; }
int mbedtls_pkcs5_pbkdf2_hmac(mbedtls_md_context_t *, const uint8_t *password, size_t length, const uint8_t *salt, size_t saltSize, unsigned iterations, unsigned outSize, uint8_t *out) {
    BCRYPT_ALG_HANDLE algorithm;
    if (BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, BCRYPT_ALG_HANDLE_HMAC_FLAG)) return -1;
    auto status = BCryptDeriveKeyPBKDF2(algorithm, const_cast<PUCHAR>(password), static_cast<ULONG>(length), const_cast<PUCHAR>(salt), static_cast<ULONG>(saltSize), iterations, out, outSize, 0);
    BCryptCloseAlgorithmProvider(algorithm, 0);
    return status == 0 ? 0 : -1;
}
int mbedtls_sha256_ret(const uint8_t *input, size_t size, uint8_t *out, int) {
    BCRYPT_ALG_HANDLE algorithm;
    if (BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0)) return -1;
    auto status = BCryptHash(algorithm, nullptr, 0, const_cast<PUCHAR>(input), static_cast<ULONG>(size), out, 32);
    BCryptCloseAlgorithmProvider(algorithm, 0);
    return status == 0 ? 0 : -1;
}
struct Preferences {
    std::vector<uint8_t> bytes, keyBytes;
    bool fail = false;
    const std::vector<uint8_t>& record(const char *name) const { return std::string(name) == "haKey" ? keyBytes : bytes; }
    bool isKey(const char *name) const { return !record(name).empty(); }
    size_t getBytesLength(const char *name) const { return record(name).size(); }
    size_t getBytes(const char *name, void *out, size_t size) const { memcpy(out, record(name).data(), size); return size; }
    size_t putBytes(const char *name, const void *data, size_t size) {
        if (fail) return 0;
        auto& target = std::string(name) == "haKey" ? keyBytes : bytes;
        target.assign(static_cast<const uint8_t *>(data), static_cast<const uint8_t *>(data)+size); return size;
    }
    bool remove(const char *name) {
        if (fail) return false;
        (std::string(name) == "haKey" ? keyBytes : bytes).clear(); return true;
    }
};
enum FieldType { FIELD_INT, FIELD_FLOAT, FIELD_BOOL, FIELD_STRING };
struct Field { String key; String value; FieldType type; };
String fieldsToJson(const std::vector<Field>& fields) {
    String out = "{";
    for (const auto& field : fields) {
        if (out.size() > 1) out += ",";
        out += "\"" + field.key + "\":";
        out += field.type == FIELD_STRING ? "\"" + field.value + "\"" : field.value;
    }
    return out + "}";
}
struct DataLogger {
    void logAuth(const String&, const std::vector<Field>& = {}) {}
    void logRequest(int, const char *, int, unsigned) {}
};
constexpr int HTTP_GET = 1, HTTP_POST = 2, HTTP_PUT = 4, HTTP_DELETE = 8, WIFI_AP = 2;
struct WiFiStub { int mode = 1; int getMode() const { return mode; } int softAPIP() const { return 2; } } WiFi;
struct Header { String data; String value() const { return data; } };
struct Client { int ip = 1; int localIP() const { return ip; } };
struct AsyncWebServerResponse {
    int status; String body; std::map<String, String> headers;
    void addHeader(const String& name, const String& value) { headers[name] = value; }
};
struct AsyncWebServerRequest {
    String path;
    int verb = HTTP_GET;
    Client socket;
    std::map<String, Header> headers, params;
    AsyncWebServerResponse result{0, "", {}};
    bool hasHeader(const char *name) const { return headers.count(name) != 0; }
    Header *getHeader(const char *name) { return &headers.at(name); }
    bool hasParam(const char *name, bool) const { return params.count(name) != 0; }
    Header *getParam(const char *name, bool) { return &params.at(name); }
    Client *client() { return &socket; }
    String url() const { return path; }
    String host() const { return "neato.local"; }
    int method() const { return verb; }
    AsyncWebServerResponse *beginResponse(int status, const char *, const String& body) { return new AsyncWebServerResponse{status, body, {}}; }
    void send(AsyncWebServerResponse *response) { result = *response; delete response; }
};
