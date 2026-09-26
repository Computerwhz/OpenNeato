#ifndef AUTH_MANAGER_H
#define AUTH_MANAGER_H

#include <ESPAsyncWebServer.h>
#include <Preferences.h>
#include "data_logger.h"

// Bounded, versioned NVS blob: accounts and their revocations commit together.
class AuthManager {
public:
    AuthManager(Preferences& prefs, DataLogger& logger) : prefs(prefs), logger(logger) {}
    void begin();
    bool authorize(AsyncWebServerRequest *request);
    void handle(AsyncWebServerRequest *request);
    bool recovery(AsyncWebServerRequest *request) const;

private:
    static constexpr unsigned USER_COUNT = 8;
    static constexpr unsigned SESSION_COUNT = 16;
    static constexpr uint32_t LIFETIME = 30 * 24 * 60 * 60;
    struct User {
        char name[33] = {};
        uint8_t role = 0;
        bool enabled = false;
        uint8_t salt[16] = {};
        uint8_t verifier[32] = {};
    };
    struct Session {
        uint8_t hash[32] = {};
        uint64_t issued = 0;
        uint64_t expires = 0;
        uint8_t user = 0;
    };
    struct Store {
        uint32_t version = 2;
        User users[USER_COUNT];
        Session sessions[SESSION_COUNT];
        bool authEnabled = false;
    } state;
    Preferences& prefs;
    DataLogger& logger;
    uint8_t haKeyHash[32] = {};
    bool haKeyEnabled = false;
    bool validHaKey(AsyncWebServerRequest *request) const;
    void handleHaKey(AsyncWebServerRequest *request);
    bool healthy = true;
    uint32_t lastAttempt = 0;
    bool attempted = false;
    bool configured() const;
    int sessionIndex(AsyncWebServerRequest *request) const;
    bool commit(const Store& next);
    static void revoke(Store& next, unsigned user);
    static String publicUser(const User& user, unsigned id);
    static bool derive(const String& password, const uint8_t *salt, uint8_t *out);
    static String parameter(AsyncWebServerRequest *request, const char *name);
    void reply(AsyncWebServerRequest *request, int status, const String& body, const String& cookie = "");
};

#endif
