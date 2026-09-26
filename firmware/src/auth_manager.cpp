#include "auth_manager.h"
#include <WiFi.h>
#include <esp_system.h>
#include <mbedtls/md.h>
#include <mbedtls/pkcs5.h>
#include <mbedtls/sha256.h>
#include <ctime>
#include <algorithm>
#include <cstddef>

namespace {
    bool equalBytes(const uint8_t *a, const uint8_t *b, size_t size) {
        volatile uint8_t difference = 0;
        for (size_t i = 0; i < size; ++i)
            difference |= a[i] ^ b[i];
        return difference == 0;
    }

    bool clockReady() {
        return time(nullptr) >= 1704067200;
    }

    String tokenValue(AsyncWebServerRequest *request) {
        if (!request->hasHeader("Cookie"))
            return "";
        String cookies = request->getHeader("Cookie")->value();
        while (!cookies.isEmpty()) {
            int end = cookies.indexOf(';');
            String part = end < 0 ? cookies : cookies.substring(0, end);
            part.trim();
            if (part.startsWith("openneato_session="))
                return part.substring(18);
            if (end < 0)
                break;
            cookies = cookies.substring(end + 1);
        }
        return "";
    }

    String cookieValue(const String& token, uint32_t age) {
        return "openneato_session=" + token + "; HttpOnly; SameSite=Strict; Path=/; Max-Age=" + String(age);
    }
} // namespace

void AuthManager::begin() {
    size_t keySize = prefs.getBytesLength("haKey");
    haKeyEnabled = keySize == sizeof(haKeyHash);
    healthy = (!prefs.isKey("haKey") || haKeyEnabled) &&
              (!haKeyEnabled || prefs.getBytes("haKey", haKeyHash, keySize) == keySize);
    if (!healthy) {
        logger.logAuth("storage_invalid");
        return;
    }
    size_t size = prefs.getBytesLength("auth");
    if (!size) {
        healthy = !prefs.isKey("auth");
        return;
    }
    // Version 1 is the unchanged prefix of version 2. Preserve accounts/sessions;
    // installations without an explicit opt-in default to authentication off.
    const size_t legacySize = offsetof(Store, authEnabled);
    healthy = (size == sizeof(state) || size == legacySize) && prefs.getBytes("auth", &state, size) == size;
    if (healthy && size == legacySize && state.version == 1) {
        state.version = 2;
        state.authEnabled = false;
    } else {
        healthy = healthy && size == sizeof(state) && state.version == 2;
    }
    for (const auto& user: state.users)
        healthy = healthy && user.name[32] == '\0' && user.role <= 3;
    logger.logAuth(healthy ? "loaded" : "storage_invalid");
}

bool AuthManager::validHaKey(AsyncWebServerRequest *request) const {
    if (!haKeyEnabled || !request->hasHeader("Authorization"))
        return false;
    String value = request->getHeader("Authorization")->value();
    if (!value.startsWith("Bearer onha_") || value.length() != 76)
        return false;
    String token = value.substring(7);
    uint8_t hash[32];
    return !mbedtls_sha256_ret(reinterpret_cast<const uint8_t *>(token.c_str()), token.length(), hash, 0) &&
           equalBytes(hash, haKeyHash, sizeof(hash));
}

void AuthManager::handleHaKey(AsyncWebServerRequest *request) {
    if (request->method() == HTTP_GET) {
        reply(request, 200, String("{\"configured\":") + (haKeyEnabled ? "true}" : "false}"));
        return;
    }
    if (request->method() == HTTP_DELETE) {
        bool ok = !haKeyEnabled || prefs.remove("haKey");
        if (ok) {
            haKeyEnabled = false;
            memset(haKeyHash, 0, sizeof(haKeyHash));
        }
        reply(request, ok ? 200 : 500, ok ? "{}" : "{\"error\":\"Storage write failed\"}");
        return;
    }
    uint8_t random[32];
    esp_fill_random(random, sizeof(random));
    String token = "onha_";
    const char *hex = "0123456789abcdef";
    for (auto byte: random) {
        token += hex[byte >> 4];
        token += hex[byte & 15];
    }
    uint8_t hash[32];
    bool ok = !mbedtls_sha256_ret(reinterpret_cast<const uint8_t *>(token.c_str()), token.length(), hash, 0) &&
              prefs.putBytes("haKey", hash, sizeof(hash)) == sizeof(hash);
    if (ok) {
        memcpy(haKeyHash, hash, sizeof(hash));
        haKeyEnabled = true;
    }
    reply(request, ok ? 200 : 500,
          ok ? "{\"key\":\"" + token + "\"}" : "{\"error\":\"Key generation or storage failed\"}");
}

bool AuthManager::configured() const {
    return std::any_of(std::begin(state.users), std::end(state.users), [](const User& user) { return user.role != 0; });
}

bool AuthManager::commit(const Store& next) {
    if (prefs.putBytes("auth", &next, sizeof(next)) != sizeof(next))
        return false;
    state = next;
    return true;
}

bool AuthManager::recovery(AsyncWebServerRequest *request) const {
    return (WiFi.getMode() & WIFI_AP) && request->client()->localIP() == WiFi.softAPIP();
}

int AuthManager::sessionIndex(AsyncWebServerRequest *request) const {
    if (!healthy || !clockReady())
        return -1;
    String token = tokenValue(request);
    if (token.length() != 64)
        return -1;
    uint8_t hash[32];
    if (mbedtls_sha256_ret(reinterpret_cast<const uint8_t *>(token.c_str()), token.length(), hash, 0))
        return -1;
    uint64_t now = time(nullptr);
    for (unsigned i = 0; i < SESSION_COUNT; ++i) {
        const auto& session = state.sessions[i];
        if (session.user < USER_COUNT && session.issued <= now && session.expires > now &&
            state.users[session.user].enabled && state.users[session.user].role &&
            equalBytes(session.hash, hash, sizeof(hash)))
            return static_cast<int>(i);
    }
    return -1;
}

void AuthManager::reply(AsyncWebServerRequest *request, int status, const String& body, const String& cookie) {
    auto *response = request->beginResponse(status, "application/json", body);
    response->addHeader("Cache-Control", "no-store");
    if (!cookie.isEmpty())
        response->addHeader("Set-Cookie", cookie);
    request->send(response);
    logger.logRequest(request->method(), request->url().c_str(), status, 0);
    if (request->method() != HTTP_GET || status >= 400)
        logger.logAuth(status < 400 ? "success" : "failure",
                       {{"path", request->url(), FIELD_STRING}, {"status", String(status), FIELD_INT}});
}

bool AuthManager::authorize(AsyncWebServerRequest *request) {
    String path = request->url();
    if (!path.startsWith("/api/"))
        return true;
    bool write = request->method() != HTTP_GET;
    // A custom header prevents cross-origin forms and simple fetches, including on the open AP.
    if (write && (!request->hasHeader("X-OpenNeato") || request->getHeader("X-OpenNeato")->value() != "1")) {
        reply(request, 403, "{\"error\":\"Same-origin request required\"}");
        return false;
    }
    if (request->hasHeader("Origin") && request->getHeader("Origin")->value() != "http://" + request->host()) {
        reply(request, 403, "{\"error\":\"Origin rejected\"}");
        return false;
    }
    if (!healthy) {
        reply(request, 503, "{\"error\":\"Account storage invalid; use physical factory reset\"}");
        return false;
    }
    if (path == "/api/auth/me" || path == "/api/auth/login" || (path == "/api/auth/setup" && !configured()))
        return true;
    if (recovery(request)) {
        if ((path == "/api/auth/ha-key" && request->method() != HTTP_POST) || path == "/api/auth/settings" ||
            path == "/api/users" || path.startsWith("/api/users/") || path == "/api/wifi/status" ||
            path == "/api/wifi/scan" || path == "/api/wifi/connect" || path == "/api/wifi/disconnect")
            return true;
        reply(request, 403, "{\"error\":\"Recovery mode only permits accounts and Wi-Fi provisioning\"}");
        return false;
    }
    if (!state.authEnabled)
        return true;
    if (request->hasHeader("Authorization")) {
        if (!validHaKey(request)) {
            reply(request, 401, "{\"error\":\"Invalid Home Assistant key\"}");
            return false;
        }
        // Service credentials cannot administer browser accounts or mint replacement keys.
        if (path.startsWith("/api/auth/") || path == "/api/users" || path.startsWith("/api/users/")) {
            reply(request, 403, "{\"error\":\"Use an Admin login to manage accounts and keys\"}");
            return false;
        }
        return true;
    }
    if (!clockReady()) {
        reply(request, 503, "{\"error\":\"Waiting for device clock\"}");
        return false;
    }
    int index = sessionIndex(request);
    if (index < 0) {
        reply(request, 401, "{\"error\":\"Login required\"}");
        return false;
    }
    unsigned role = state.users[state.sessions[index].user].role;
    bool operatorAction = path == "/api/clean" || path == "/api/sound" || path == "/api/manual" ||
                          path == "/api/manual/move" || path == "/api/manual/motors" || path == "/api/schedule/next" ||
                          path == "/api/schedule";
    // Default to Admin for unknown paths, including prefix aliases of sensitive handlers.
    bool viewerRead = path == "/api/version" || path == "/api/charger" || path == "/api/analog" ||
                      path == "/api/warranty" || path == "/api/motors" || path == "/api/state" ||
                      path == "/api/error" || path == "/api/lidar" || path == "/api/user-settings" ||
                      path == "/api/schedule" || path == "/api/schedule/next" || path == "/api/manual/status" ||
                      path == "/api/system" || path == "/api/firmware/version" || path == "/api/logs" ||
                      path.startsWith("/api/logs/") || path == "/api/history" || path.startsWith("/api/history/");
    unsigned required = write ? (operatorAction ? 2 : 3) : (viewerRead ? 1 : 3);
    if (path == "/api/auth/logout")
        required = 1;
    if (role >= required)
        return true;
    reply(request, 403, "{\"error\":\"Permission denied\"}");
    return false;
}

bool AuthManager::derive(const String& password, const uint8_t *salt, uint8_t *out) {
    mbedtls_md_context_t context;
    mbedtls_md_init(&context);
    int result = mbedtls_md_setup(&context, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 1);
    if (!result)
        result = mbedtls_pkcs5_pbkdf2_hmac(&context, reinterpret_cast<const uint8_t *>(password.c_str()),
                                           password.length(), salt, 16, 100000, 32, out);
    mbedtls_md_free(&context);
    return result == 0;
}

String AuthManager::parameter(AsyncWebServerRequest *request, const char *name) {
    return request->hasParam(name, true) ? request->getParam(name, true)->value() : String("");
}

String AuthManager::publicUser(const User& user, unsigned id) {
    const char *roles[] = {"", "Viewer", "Operator", "Admin"};
    return fieldsToJson({{"id", String(id), FIELD_INT},
                         {"username", user.name, FIELD_STRING},
                         {"role", roles[user.role], FIELD_STRING},
                         {"enabled", user.enabled ? "true" : "false", FIELD_BOOL}});
}

void AuthManager::revoke(Store& next, unsigned user) {
    for (auto& session: next.sessions)
        if (session.user == user)
            session = Session{};
}

void AuthManager::handle(AsyncWebServerRequest *request) {
    const String path = request->url();
    const auto method = request->method();
    if (path == "/api/auth/ha-key") {
        handleHaKey(request);
        return;
    }
    int index = sessionIndex(request);
    if (path == "/api/auth/me" && method == HTTP_GET) {
        String user =
                index < 0 ? "null" : publicUser(state.users[state.sessions[index].user], state.sessions[index].user);
        reply(request, 200,
              "{\"user\":" + user + ",\"setupRequired\":" + (!configured() ? "true" : "false") +
                      ",\"authEnabled\":" + (state.authEnabled ? "true" : "false") +
                      ",\"recovery\":" + (recovery(request) ? "true" : "false") +
                      ",\"clockReady\":" + (clockReady() ? "true" : "false") + "}");
        return;
    }
    Store next = state;
    if (path == "/api/auth/settings" && method == HTTP_PUT) {
        String enabled = parameter(request, "enabled");
        if (enabled != "true" && enabled != "false") {
            reply(request, 400, "{\"error\":\"enabled must be true or false\"}");
            return;
        }
        bool enable = enabled == "true";
        bool adminExists = std::any_of(std::begin(state.users), std::end(state.users),
                                       [](const User& user) { return user.role == 3 && user.enabled; });
        if (enable && !adminExists) {
            reply(request, 409, "{\"error\":\"Create an enabled Admin before enabling authentication\"}");
            return;
        }
        if (enable == state.authEnabled) {
            reply(request, 200, "{}");
            return;
        }
        next.authEnabled = enable;
        for (auto& session: next.sessions)
            session = Session{};
        bool ok = commit(next);
        reply(request, ok ? 200 : 500, ok ? "{}" : "{\"error\":\"Storage write failed\"}",
              ok ? cookieValue("", 0) : "");
        return;
    }
    if (path == "/api/auth/logout" && method == HTTP_POST) {
        if (index >= 0)
            next.sessions[index] = Session{};
        bool ok = commit(next);
        reply(request, ok ? 200 : 500, ok ? "{}" : "{\"error\":\"Storage write failed\"}",
              ok ? cookieValue("", 0) : "");
        return;
    }
    String username = parameter(request, "username");
    String password = parameter(request, "password");
    if (path == "/api/auth/login" && method == HTTP_POST) {
        if (!clockReady()) {
            reply(request, 503, "{\"error\":\"Waiting for device clock\"}");
            return;
        }
        uint32_t nowMs = millis();
        if (attempted && nowMs - lastAttempt < 3000) {
            reply(request, 429, "{\"error\":\"Try again in a few seconds\"}");
            return;
        }
        attempted = true;
        lastAttempt = nowMs;
        int found = -1;
        for (unsigned i = 0; i < USER_COUNT; ++i)
            if (state.users[i].role && username == state.users[i].name)
                found = static_cast<int>(i);
        uint8_t verifier[32] = {};
        const User& user = state.users[found < 0 ? 0 : found];
        bool valid = password.length() <= 128 && derive(password, user.salt, verifier);
        valid = valid && equalBytes(verifier, user.verifier, 32) && found >= 0 && user.enabled;
        memset(verifier, 0, sizeof(verifier));
        if (!valid) {
            reply(request, 401, "{\"error\":\"Invalid username or password\"}");
            return;
        }
        unsigned slot = 0;
        for (unsigned i = 1; i < SESSION_COUNT; ++i)
            if (next.sessions[i].expires < next.sessions[slot].expires)
                slot = i;
        uint8_t random[32];
        esp_fill_random(random, sizeof(random));
        String token;
        const char *hex = "0123456789abcdef";
        for (auto byte: random) {
            token += hex[byte >> 4];
            token += hex[byte & 15];
        }
        auto& session = next.sessions[slot];
        if (mbedtls_sha256_ret(reinterpret_cast<const uint8_t *>(token.c_str()), token.length(), session.hash, 0)) {
            reply(request, 500, "{\"error\":\"Session generation failed\"}");
            return;
        }
        session.user = static_cast<uint8_t>(found);
        session.issued = time(nullptr);
        session.expires = session.issued + LIFETIME;
        bool ok = commit(next);
        reply(request, ok ? 200 : 500, ok ? "{}" : "{\"error\":\"Storage write failed\"}",
              ok ? cookieValue(token, LIFETIME) : "");
        return;
    }
    if (path == "/api/users" && method == HTTP_GET) {
        String users = "[";
        for (unsigned i = 0; i < USER_COUNT; ++i) { // NOLINT(modernize-loop-convert) public IDs are array indices
            if (!state.users[i].role)
                continue;
            if (users.length() > 1)
                users += ",";
            users += publicUser(state.users[i], i);
        }
        reply(request, 200, users + "]");
        return;
    }
    bool setup = path == "/api/auth/setup" && method == HTTP_POST && !configured();
    bool create = setup || (path == "/api/users" && method == HTTP_POST);
    int id = -1;
    if (create) {
        for (unsigned i = 0; i < USER_COUNT; ++i)
            if (!next.users[i].role) {
                id = static_cast<int>(i);
                break;
            }
    } else if (path.startsWith("/api/users/")) {
        String suffix = path.substring(11);
        if (suffix.length() == 1 && suffix[0] >= '0' && suffix[0] < '0' + USER_COUNT)
            id = suffix[0] - '0';
        if (id >= 0 && !next.users[id].role)
            id = -1;
    }
    if (id < 0 || (!create && method != HTTP_PUT && method != HTTP_DELETE)) {
        reply(request, 400, "{\"error\":\"Invalid account or account limit reached\"}");
        return;
    }
    auto& user = next.users[id];
    if (method == HTTP_DELETE) {
        user = User{};
    } else if (parameter(request, "revokeSessions") != "true") {
        String role = setup ? "Admin" : parameter(request, "role");
        if (username.isEmpty())
            username = user.name;
        bool valid = username.length() >= 1 && username.length() <= 32;
        for (unsigned i = 0; i < username.length(); ++i) {
            char c = username[i];
            valid = valid && ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' ||
                              c == '-' || c == '.');
        }
        for (unsigned i = 0; i < USER_COUNT; ++i)
            if (static_cast<int>(i) != id && next.users[i].role && username == next.users[i].name)
                valid = false;
        if (!role.isEmpty())
            user.role = role == "Admin" ? 3 : (role == "Operator" ? 2 : (role == "Viewer" ? 1 : 0));
        valid = valid && user.role &&
                ((!create && password.isEmpty()) || (password.length() >= 12 && password.length() <= 128));
        if (!valid) {
            reply(request, 400, "{\"error\":\"Use a unique username, valid role and a 12-128 character password\"}");
            return;
        }
        strlcpy(user.name, username.c_str(), sizeof(user.name));
        if (create || request->hasParam("enabled", true))
            user.enabled = create || parameter(request, "enabled") == "true";
        if (!password.isEmpty()) {
            esp_fill_random(user.salt, sizeof(user.salt));
            if (!derive(password, user.salt, user.verifier)) {
                reply(request, 500, "{\"error\":\"Password generation failed\"}");
                return;
            }
        }
    }
    unsigned admins = 0;
    for (const auto& candidate: next.users)
        if (candidate.role == 3 && candidate.enabled)
            ++admins;
    if (!admins) {
        reply(request, 409, "{\"error\":\"Keep at least one enabled Admin\"}");
        return;
    }
    revoke(next, id);
    bool ok = commit(next);
    reply(request, ok ? 200 : 500, ok ? "{}" : "{\"error\":\"Storage write failed\"}");
}
