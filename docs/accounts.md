# Local accounts

OpenNeato stores up to eight local accounts and sixteen persistent sessions in the
existing `neato` NVS namespace. No cloud service or default credentials are used.
Authentication is **off by default**: the dashboard and all normal Wi-Fi APIs
are available without login. To enable it, open Settings > Accounts, create an
Admin account, and turn on **Require account login**. You will then be asked to log in.
The same switch turns authentication off. When enabled, only an Admin or a client
connected through the fallback AP can change it. When off, anyone on the local
network has full access, including the switch and account management.

The choice persists across reboot. Switching either way revokes existing sessions
but retains accounts. Authentication mode and session revocations commit in the
same NVS record. Factory reset restores the default off state. Version-1 account
records are migrated without losing accounts and default to off until opted in.

Usernames are case-sensitive,
1–32 ASCII letters, digits, dots, underscores or hyphens. New passwords must be
12–128 characters. Settings → Accounts lets an Admin add, rename, disable, delete,
change passwords, change roles, or revoke an account's sessions.

| Role | Access |
| --- | --- |
| Viewer | Status, dashboard, history, battery diagnostics, logs and schedule reads |
| Operator | Viewer access plus cleaning, manual controls, sounds and schedules |
| Admin | All APIs, including system/Wi-Fi settings, raw serial commands, destructive history/log actions, firmware updates and accounts |

Authorization is enforced in firmware. New or unrecognized API paths require
Admin access by default. Upload callbacks and JSON body callbacks check permissions
before side effects, because ESPAsyncWebServer invokes them before middleware.
The schedule-only `/api/schedule` endpoint avoids granting Operators access to
the settings API. At least one enabled Admin must remain.

## Sessions and storage

Passwords use PBKDF2-HMAC-SHA256 with 100,000 iterations and random 128-bit salts,
using the bundled mbedTLS implementation. This embedded-device work factor should
be benchmarked on hardware before changing it. Session tokens contain 256 random
bits, obtained with the Wi-Fi radio enabled; only their SHA-256 verifiers are stored.
Password verifiers and salts are never returned by the API or intentionally logged.

The browser receives an `openneato_session` cookie with `HttpOnly`,
`SameSite=Strict`, `Path=/` and `Max-Age=2592000` (30 days). `Secure` is omitted
because the device serves HTTP. HTTP does not encrypt passwords or cookies in
transit; use the device on a trusted local network.

Sessions keep their original expiry across reboot. Authentication waits until the
device has a plausible clock from NTP or the robot's clock; it does not restart
the expiry timer or accept sessions without time validation. Expired records are
ignored and their slots reused on login. When all sixteen slots are occupied,
login replaces the session with the earliest expiry. No background NVS writes
are performed for polling, last-seen timestamps, or expiry cleanup.

Logout revokes the current session. Every account update (including role changes),
disable, deletion, and “Log out everywhere” revokes that account's sessions.
Accounts and session revocations are saved together in one versioned NVS blob;
failed writes return an error and leave the live state unchanged. Factory reset
clears the shared namespace, including all accounts and sessions. Invalid stored
account data fails closed and requires the physical factory-reset button.

Login attempts are limited to one every three seconds across the device, in RAM.
Authentication events are recorded through DataLogger according to the configured
logging level. Account storage is not encrypted at rest; physical flash access is
outside this authentication boundary.

## Fallback AP recovery

The fallback AP remains open. Bypass is determined by the connection's **local
interface address**, not by the mere existence of an active AP. Requests arriving
through normal Wi-Fi still need a session even if both interfaces are active.

AP clients can use Wi-Fi provisioning and account management without logging in.
The recovery UI lets them reset an Admin password or enable an account and then
reconnect using normal Wi-Fi. Robot commands, raw serial access, firmware upload,
logs/history and system reset are unavailable over the recovery interface, even
with a valid session. Anyone within range of an active fallback AP can recover
accounts; this is the deliberately requested physical-proximity recovery model.

## API clients

See [OpenAPI](../frontend/api/openapi.yaml) for request and response schemas.
Account/login payloads use `application/x-www-form-urlencoded` in the request body.
All mutations, including login and AP provisioning, require `X-OpenNeato: 1`.
When an Origin header is present, it must match the device's HTTP origin. The
server does not enable cross-origin requests. When authentication is enabled, existing API/OTA clients must log in,
retain the session cookie, and add the header when writing.

For example, with credentials supplied from a local protected form file:

```sh
curl -c cookies.txt -H 'X-OpenNeato: 1' \
  --data-binary @login-form.txt http://neato.local/api/auth/login
curl -b cookies.txt http://neato.local/api/auth/me
curl -b cookies.txt -H 'X-OpenNeato: 1' -X POST \
  http://neato.local/api/clean?action=house
```

Protect and remove temporary credential and cookie files when finished. Direct
CLI OTA upload similarly requires the cookie and header; the old unauthenticated
PlatformIO OTA command will be rejected.

## Verification

`python tests/auth/run_host_tests.py` compiles the actual AuthManager sources with
Windows host adapters (Visual Studio C++ required). Windows CNG supplies PBKDF2,
SHA-256 and random bytes for these tests; hardware mbedTLS is validated by the
firmware build, not executed by the host suite. The tests exercise role boundaries,
prefix aliases, persistence across manager reconstruction, expiry, clock unavailability,
revocation, storage failures, CSRF header enforcement and simultaneous AP/STA isolation.

Run the frontend and firmware checks in AGENTS.md as well. Before hardware release,
verify real power-cycle persistence, NTP/robot-clock recovery, KDF latency/watchdog
behavior, multipart upload rejection, and NVS failure/power-loss behavior on a device.

The development mock uses ephemeral accounts and sessions and resets when its
server restarts. It is for UI development, not a security or persistence reference.

## Home Assistant

The bundled integration uses an optional **API key** field. Leave it blank when
OpenNeato login is off (the default). When login is on, generate a Home Assistant
key in **Settings > Accounts**. HA does not use account usernames or passwords.

For an existing entry, use Home Assistant's **Reconfigure** action to add, replace,
or remove the key. Re-enter the key to retain it; leaving it blank removes it.
A rejected key starts Home Assistant's reauthentication flow. Reconfiguration
verifies the robot serial number before updating the entry. Previously saved
HA usernames and passwords are removed on integration setup or reconfiguration.

Run `python -m unittest discover -s tests/ha` with `aiohttp` and `voluptuous`
installed to check the HTTP client and config flow. These tests use a local HTTP
server and stub Home Assistant framework surfaces; they do not replace live HA testing.

### Home Assistant API key

After flashing firmware with key support, open **Settings > Accounts > Home
Assistant API key** and select **Generate key**. Copy the displayed key into the
integration's optional **API key** field.
For an existing HA entry, use **Reconfigure**. Keys are shown once; leaving the
Accounts screen discards the displayed value. Replace a lost key and update HA.

There is one independent service key per device. It authorizes device controls,
telemetry and system settings, but cannot manage accounts or keys while login is
on. It is not tied to a user's password or browser sessions. Password changes and
logging out everywhere therefore do not revoke it: use **Revoke key** explicitly.
Replacing the key immediately invalidates the old one. Factory reset clears it.
The key persists across reboot without automatic expiry and works before clock
synchronization. Only its SHA-256 hash is stored in NVS. Generation and revocation
write flash once; API requests never write flash.

Clients send `Authorization: Bearer <key>` plus `X-OpenNeato: 1` for writes.
Transport remains local HTTP, as with passwords and session cookies. Login off
still permits unauthenticated access. Recovery AP access can revoke the key but
cannot generate one or use it for normal device controls.
