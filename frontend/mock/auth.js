// Development-only account/session simulator. Firmware remains the security boundary.
export function createMockAuth() {
    let authEnabled = false;
    let haKeyHash = "";
    const keyHash = async (key) =>
        hex(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(key))));
    const users = new Map();
    const sessions = new Map();
    const json = (data, status = 200, headers = {}) => ({
        status,
        headers: { "Content-Type": "application/json", "Cache-Control": "no-store", ...headers },
        body: JSON.stringify(data),
    });
    const fail = (error, status) => json({ error }, status);
    const visible = ({ salt: _salt, hash: _hash, ...user }) => user;
    const hex = (bytes) => Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
    const hash = async (password, salt) => {
        const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(password), "PBKDF2", false, [
            "deriveBits",
        ]);
        return hex(
            new Uint8Array(
                await crypto.subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt, iterations: 100000 }, key, 256),
            ),
        );
    };
    const cookie = (token, age) => ({
        "Set-Cookie": `openneato_session=${token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${age}`,
    });
    return async (request) => {
        const { path, method } = request;
        const token = request.cookie?.match(/(?:^|;\s*)openneato_session=([^;]*)/)?.[1];
        const session = sessions.get(token);
        const current = session && session.expires > Date.now() ? users.get(session.id) : undefined;
        if (path === "/api/auth/me")
            return json({
                user: current ? visible(current) : null,
                setupRequired: users.size === 0,
                authEnabled,
                recovery: false,
                clockReady: true,
            });
        if (path === "/api/auth/login") {
            const data = new URLSearchParams(await request.text());
            const user = [...users.values()].find((entry) => entry.username === data.get("username"));
            if (!user?.enabled || (await hash(data.get("password") ?? "", user.salt)) !== user.hash)
                return fail("Invalid username or password", 401);
            const fresh = hex(crypto.getRandomValues(new Uint8Array(32)));
            sessions.set(fresh, { id: user.id, expires: Date.now() + 2592000000 });
            return json({}, 200, cookie(fresh, 2592000));
        }
        if (authEnabled && request.authorization) {
            const supplied = request.authorization.startsWith("Bearer ") ? request.authorization.slice(7) : "";
            if (!haKeyHash || (await keyHash(supplied)) !== haKeyHash) return fail("Invalid Home Assistant key", 401);
            if (path.startsWith("/api/auth/") || path === "/api/users" || path.startsWith("/api/users/"))
                return fail("Use an Admin login to manage accounts and keys", 403);
            return null;
        }
        const setup = path === "/api/auth/setup" && users.size === 0;
        if (authEnabled && !setup && !current) return fail("Login required", 401);
        if (path === "/api/auth/ha-key") {
            if (authEnabled && current?.role !== "Admin") return fail("Permission denied", 403);
            if (method === "GET") return json({ configured: Boolean(haKeyHash) });
            if (method === "DELETE") {
                haKeyHash = "";
                return json({});
            }
            if (method !== "POST") return fail("Method not allowed", 405);
            const key = `onha_${hex(crypto.getRandomValues(new Uint8Array(32)))}`;
            haKeyHash = await keyHash(key);
            return json({ key });
        }
        if (path === "/api/auth/settings" && method === "PUT") {
            if (authEnabled && current?.role !== "Admin") return fail("Permission denied", 403);
            const enabled = new URLSearchParams(await request.text()).get("enabled");
            if (enabled !== "true" && enabled !== "false") return fail("enabled must be true or false", 400);
            if (enabled === "true" && ![...users.values()].some((user) => user.role === "Admin" && user.enabled))
                return fail("Create an enabled Admin first", 409);
            if (authEnabled !== (enabled === "true")) sessions.clear();
            authEnabled = enabled === "true";
            return json({}, 200, cookie("", 0));
        }
        if (path === "/api/auth/logout") {
            sessions.delete(token);
            return json({}, 200, cookie("", 0));
        }
        if (setup || path === "/api/users" || path.startsWith("/api/users/")) {
            if (authEnabled && !setup && current?.role !== "Admin") return fail("Permission denied", 403);
            if (method === "GET") return json([...users.values()].map(visible));
            const data = Object.fromEntries(new URLSearchParams(await request.text()));
            const create = setup || (path === "/api/users" && method === "POST");
            const id = create
                ? Array.from({ length: 8 }, (_, index) => index).find((index) => !users.has(index))
                : Number(path.split("/").at(-1));
            if (id === undefined || (!create && !users.has(id)))
                return fail("Invalid account or account limit reached", 400);
            const user = { ...users.get(id), id };
            if (data.revokeSessions !== "true" && method !== "DELETE") {
                user.username = data.username ?? user.username;
                user.role = setup ? "Admin" : (data.role ?? user.role);
                user.enabled = create ? true : data.enabled === undefined ? user.enabled : data.enabled === "true";
                if (
                    !/^[A-Za-z0-9_.-]{1,32}$/.test(user.username) ||
                    !["Admin", "Operator", "Viewer"].includes(user.role) ||
                    [...users.values()].some((entry) => entry.id !== id && entry.username === user.username)
                )
                    return fail("Invalid account", 400);
                if (create || data.password) {
                    if (!data.password || data.password.length < 12 || data.password.length > 128)
                        return fail("Use a 12-128 character password", 400);
                    user.salt = crypto.getRandomValues(new Uint8Array(16));
                    user.hash = await hash(data.password, user.salt);
                }
            }
            const next = new Map(users);
            if (method === "DELETE") next.delete(id);
            else next.set(id, user);
            if (![...next.values()].some((entry) => entry.role === "Admin" && entry.enabled))
                return fail("Keep at least one enabled Admin", 409);
            users.clear();
            for (const [key, value] of next) users.set(key, value);
            for (const [key, value] of sessions) if (value.id === id) sessions.delete(key);
            return json({});
        }
        if (!authEnabled) return null;
        const adminRead = path === "/api/settings" || path.startsWith("/api/wifi/");
        const operatorWrite = [
            "/api/clean",
            "/api/sound",
            "/api/manual",
            "/api/manual/move",
            "/api/manual/motors",
            "/api/schedule",
            "/api/schedule/next",
        ].includes(path);
        const required = adminRead ? 3 : method === "GET" ? 1 : operatorWrite ? 2 : 3;
        if ({ Viewer: 1, Operator: 2, Admin: 3 }[current.role] < required) return fail("Permission denied", 403);
        return null;
    };
}
