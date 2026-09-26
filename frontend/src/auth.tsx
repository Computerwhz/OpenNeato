import { networkRequest } from "./network-request";
import backSvg from "./assets/icons/back.svg?raw";
import { Icon } from "./components/icon";
import { createContext, type ComponentChildren } from "preact";
import { useCallback, useContext, useEffect, useState } from "preact/hooks";
import { I18nProvider, loadLanguagePreference, resolveLocale, T, useI18n } from "./i18n";
import type { Account, AuthState, HaKeyStatus, HaKeyCreated } from "./types.generated";

interface AuthContext {
    authEnabled: boolean;
    role: Account["role"] | null;
    user: Account | null;
    recovery: boolean;
    refresh: () => Promise<void>;
}
interface AuthGateProps {
    children: ComponentChildren;
}
interface CredentialsProps {
    setup: boolean;
    onDone: () => Promise<void>;
}
interface AccountEditorProps {
    account?: Account;
    onSaved: () => Promise<void>;
}

const Context = createContext<AuthContext>({
    authEnabled: true,
    role: null,
    user: null,
    recovery: false,
    refresh: async () => {},
});
export const useAuth = () => useContext(Context);

export async function authFetch(url: string, init?: RequestInit): Promise<Response> {
    const headers = new Headers(init?.headers);
    headers.set("X-OpenNeato", "1");
    const response = await networkRequest(url, { ...init, headers, credentials: "same-origin", cache: "no-store" });
    if (response.status === 401 && url !== "/api/auth/login") window.dispatchEvent(new Event("session-expired"));
    return response;
}

async function request<T>(url: string, method = "GET", values?: Record<string, string>): Promise<T> {
    const response = await authFetch(url, { method, body: values ? new URLSearchParams(values) : undefined });
    const body = await response.json();
    if (!response.ok) throw new Error(body.error || `${response.status}`);
    return body as T;
}

function Credentials({ setup, onDone }: CredentialsProps) {
    const { t } = useI18n();
    const [username, setUsername] = useState("");
    const [password, setPassword] = useState("");
    const [error, setError] = useState("");
    const [busy, setBusy] = useState(false);
    return (
        <form
            class="account-card"
            onSubmit={async (event) => {
                event.preventDefault();
                setBusy(true);
                setError("");
                try {
                    await request(setup ? "/api/auth/setup" : "/api/auth/login", "POST", { username, password });
                    setPassword("");
                    await onDone();
                } catch (cause) {
                    setError(String(cause));
                } finally {
                    setBusy(false);
                }
            }}
        >
            <h1>{t(setup ? "Create first Admin account" : "Log in to OpenNeato")}</h1>
            <label>
                <T>Username</T>
                <input
                    required
                    maxLength={32}
                    autoComplete="username"
                    value={username}
                    onInput={(e) => setUsername(e.currentTarget.value)}
                />
            </label>
            <label>
                <T>Password</T>
                <input
                    required
                    type="password"
                    minLength={setup ? 12 : 1}
                    maxLength={128}
                    autoComplete={setup ? "new-password" : "current-password"}
                    value={password}
                    onInput={(e) => setPassword(e.currentTarget.value)}
                />
            </label>
            {setup && (
                <p>
                    <T>Use at least 12 characters. No default account is provided.</T>
                </p>
            )}
            {error && <p role="alert">{error}</p>}
            <button class="settings-device-btn" disabled={busy}>
                {t(setup ? "Create account" : "Log in")}
            </button>
        </form>
    );
}

function AccountEditor({ account, onSaved }: AccountEditorProps) {
    const { t } = useI18n();
    const [username, setUsername] = useState(account?.username ?? "");
    const [role, setRole] = useState(account?.role ?? "Viewer");
    const [enabled, setEnabled] = useState(account?.enabled ?? true);
    const [password, setPassword] = useState("");
    const [error, setError] = useState("");
    const [busy, setBusy] = useState(false);
    const save = async (action: "save" | "delete" | "revoke") => {
        if (action === "delete" && !window.confirm(t("Delete this account?"))) return;
        setBusy(true);
        setError("");
        try {
            await request(
                account ? `/api/users/${account.id}` : "/api/users",
                action === "delete" ? "DELETE" : account ? "PUT" : "POST",
                action === "revoke"
                    ? { revokeSessions: "true" }
                    : { username, role, enabled: String(enabled), password },
            );
            setPassword("");
            if (!account) setUsername("");
            await onSaved();
        } catch (cause) {
            setError(String(cause));
        } finally {
            setBusy(false);
        }
    };
    return (
        <form
            class="account-card"
            onSubmit={(event) => {
                event.preventDefault();
                void save("save");
            }}
        >
            <h2>{account ? account.username : t("Add account")}</h2>
            <label>
                <T>Username</T>
                <input required maxLength={32} value={username} onInput={(e) => setUsername(e.currentTarget.value)} />
            </label>
            <label>
                <T>Role</T>
                <select value={role} onChange={(e) => setRole(e.currentTarget.value as Account["role"])}>
                    <option value="Viewer">
                        <T>Viewer</T>
                    </option>
                    <option value="Operator">
                        <T>Operator</T>
                    </option>
                    <option value="Admin">
                        <T>Admin</T>
                    </option>
                </select>
            </label>
            <label>
                <T>Change password</T>
                <input
                    type="password"
                    autoComplete="new-password"
                    required={!account}
                    minLength={12}
                    maxLength={128}
                    value={password}
                    onInput={(e) => setPassword(e.currentTarget.value)}
                />
            </label>
            {account && (
                <div class="settings-toggle-row">
                    <span class="settings-toggle-title">
                        <T>Enabled</T>
                    </span>
                    <button
                        type="button"
                        role="switch"
                        aria-checked={enabled}
                        aria-label={t("Account enabled")}
                        class={`settings-toggle${enabled ? " on" : ""}`}
                        onClick={() => setEnabled(!enabled)}
                    />
                </div>
            )}
            {error && <p role="alert">{error}</p>}
            <div class="account-actions">
                <button class="settings-device-btn" disabled={busy}>
                    <T>Save</T>
                </button>
                {account && (
                    <>
                        <button
                            class="settings-device-btn"
                            type="button"
                            disabled={busy}
                            onClick={() => void save("revoke")}
                        >
                            <T>Log out everywhere</T>
                        </button>
                        <button
                            class="settings-device-btn"
                            type="button"
                            disabled={busy}
                            onClick={() => void save("delete")}
                        >
                            <T>Delete account</T>
                        </button>
                    </>
                )}
            </div>
        </form>
    );
}

function HomeAssistantKey() {
    const { t } = useI18n();
    const { recovery } = useAuth();
    const [configured, setConfigured] = useState<boolean | null>(null);
    const [key, setKey] = useState("");
    const [busy, setBusy] = useState(false);
    const [error, setError] = useState("");
    useEffect(() => {
        void request<HaKeyStatus>("/api/auth/ha-key")
            .then((status) => setConfigured(status.configured))
            .catch((cause) => setError(String(cause)));
    }, []);
    const change = async (remove: boolean) => {
        if (configured && !window.confirm(t("The current Home Assistant key will stop working. Continue?"))) return;
        setBusy(true);
        setError("");
        try {
            const result = await request<Partial<HaKeyCreated>>("/api/auth/ha-key", remove ? "DELETE" : "POST");
            setKey(result.key ?? "");
            setConfigured(!remove);
        } catch (cause) {
            setError(String(cause));
        } finally {
            setBusy(false);
        }
    };
    return (
        <div class="account-card">
            <h2>
                <T>Home Assistant API key</T>
            </h2>
            <p class="account-note">
                <T>
                    Allows device controls and settings without your password. Remains valid until replaced or revoked.
                </T>
            </p>
            <p>{configured === null ? t("Loading...") : configured ? t("Key configured") : t("No key configured")}</p>
            {key && (
                <label>
                    <T>Copy this key into Home Assistant now. It is shown only once.</T>
                    <input
                        readOnly
                        value={key}
                        autoComplete="off"
                        spellcheck={false}
                        onFocus={(event) => event.currentTarget.select()}
                    />
                </label>
            )}
            {error && <p role="alert">{error}</p>}
            <div class="account-actions">
                {!recovery && (
                    <button
                        class="settings-device-btn"
                        disabled={busy || configured === null}
                        onClick={() => void change(false)}
                    >
                        {configured ? t("Replace key") : t("Generate key")}
                    </button>
                )}
                {configured && (
                    <button class="settings-device-btn" disabled={busy} onClick={() => void change(true)}>
                        <T>Revoke key</T>
                    </button>
                )}
            </div>
        </div>
    );
}

export function AccountsView() {
    const { t } = useI18n();
    const { refresh, recovery, authEnabled } = useAuth();
    const [changingAuth, setChangingAuth] = useState(false);
    const [users, setUsers] = useState<Account[]>([]);
    const [error, setError] = useState("");
    const load = useCallback(async () => {
        try {
            setUsers(await request<Account[]>("/api/users"));
            setError("");
        } catch (cause) {
            setError(String(cause));
        }
    }, []);
    useEffect(() => {
        void load();
    }, [load]);
    const saved = async () => {
        await refresh();
        await load();
    };
    return (
        <>
            {!recovery && (
                <div class="header">
                    <a href="#/settings" class="header-back-btn" aria-label={t("Back")}>
                        <Icon svg={backSvg} />
                    </a>
                    <h1>
                        <T>Accounts</T>
                    </h1>
                    <div class="header-right-spacer" />
                </div>
            )}
            <section class="accounts-page">
                {recovery && (
                    <h2>
                        <T>Accounts</T>
                    </h2>
                )}
                {authEnabled && !recovery && (
                    <button
                        class="settings-device-btn"
                        onClick={async () => {
                            try {
                                await request("/api/auth/logout", "POST");
                                await refresh();
                            } catch (cause) {
                                setError(String(cause));
                            }
                        }}
                    >
                        <T>Log out</T>
                    </button>
                )}
                <div class="settings-toggle-row">
                    <div class="settings-toggle-label">
                        <span class="settings-toggle-title">
                            <T>Require account login</T>
                        </span>
                        <span class="settings-toggle-desc">
                            <T>Off by default. When off, anyone on your local network has full access.</T>
                        </span>
                    </div>
                    <button
                        type="button"
                        role="switch"
                        aria-checked={authEnabled}
                        aria-label={t("Require account login")}
                        class={`settings-toggle${authEnabled ? " on" : ""}`}
                        disabled={
                            changingAuth ||
                            (!authEnabled && !users.some((account) => account.role === "Admin" && account.enabled))
                        }
                        onClick={async () => {
                            setChangingAuth(true);
                            setError("");
                            try {
                                await request("/api/auth/settings", "PUT", { enabled: String(!authEnabled) });
                                await refresh();
                            } catch (cause) {
                                setError(String(cause));
                            } finally {
                                setChangingAuth(false);
                            }
                        }}
                    />
                </div>
                <p class="account-note">
                    <T>
                        Create an Admin account before enabling login. Account changes sign that user out on all
                        devices.
                    </T>
                </p>
                {error && <p role="alert">{error}</p>}
                <HomeAssistantKey />
                {users.map((account) => (
                    <AccountEditor key={JSON.stringify(account)} account={account} onSaved={saved} />
                ))}
                {users.length === 0 ? (
                    <Credentials setup onDone={saved} />
                ) : (
                    users.length < 8 && <AccountEditor onSaved={saved} />
                )}
            </section>
        </>
    );
}

function RecoveryView() {
    const [ssid, setSsid] = useState("");
    const [password, setPassword] = useState("");
    const [message, setMessage] = useState("");
    const [busy, setBusy] = useState(false);
    const { t } = useI18n();
    return (
        <main class="accounts-page">
            <h1>
                <T>Recovery mode</T>
            </h1>
            <p>
                <T>
                    This open access point permits account recovery and Wi-Fi provisioning. Robot controls are
                    unavailable.
                </T>
            </p>
            <form
                class="account-card"
                onSubmit={async (event) => {
                    event.preventDefault();
                    setBusy(true);
                    setMessage("");
                    try {
                        await request(`/api/wifi/connect?${new URLSearchParams({ ssid, password })}`, "POST");
                        setPassword("");
                        setMessage(t("Wi-Fi saved. Reconnect to your normal network."));
                    } catch (cause) {
                        setMessage(String(cause));
                    } finally {
                        setBusy(false);
                    }
                }}
            >
                <label>
                    <T>Wi-Fi network</T>
                    <input required value={ssid} onInput={(e) => setSsid(e.currentTarget.value)} />
                </label>
                <label>
                    <T>Wi-Fi password</T>
                    <input type="password" value={password} onInput={(e) => setPassword(e.currentTarget.value)} />
                </label>
                <button class="settings-device-btn" disabled={busy}>
                    <T>Connect</T>
                </button>
                {message && <p role="status">{message}</p>}
            </form>
            <AccountsView />
        </main>
    );
}

export function AuthGate({ children }: AuthGateProps) {
    const [state, setState] = useState<AuthState | null>(null);
    const [error, setError] = useState("");
    const [language, setLanguage] = useState(loadLanguagePreference);
    const refresh = useCallback(async () => {
        try {
            setState(await request<AuthState>("/api/auth/me"));
            setError("");
        } catch (cause) {
            setState(null);
            setError(String(cause));
        }
    }, []);
    useEffect(() => {
        void refresh();
        const expired = () => {
            setState(null);
            void refresh();
        };
        window.addEventListener("session-expired", expired);
        const timer = window.setInterval(() => void refresh(), 15000);
        return () => {
            window.removeEventListener("session-expired", expired);
            window.clearInterval(timer);
        };
    }, [refresh]);
    return (
        <I18nProvider preference={language} locale={resolveLocale(language)} setPreference={setLanguage}>
            <Context.Provider
                value={{
                    user: state?.user ?? null,
                    recovery: state?.recovery ?? false,
                    authEnabled: state?.authEnabled ?? true,
                    role: state && !state.authEnabled ? "Admin" : (state?.user?.role ?? null),
                    refresh,
                }}
            >
                {!state ? (
                    <main class="accounts-page">
                        <p role="status">{error || <T>Loading session...</T>}</p>
                        <button class="settings-device-btn" onClick={() => void refresh()}>
                            <T>Retry</T>
                        </button>
                    </main>
                ) : state.recovery ? (
                    <RecoveryView />
                ) : !state.authEnabled ? (
                    children
                ) : state.setupRequired ? (
                    <main class="accounts-page">
                        <Credentials setup onDone={refresh} />
                    </main>
                ) : !state.clockReady ? (
                    <main class="accounts-page">
                        <p role="status">
                            <T>Waiting for the device clock. Your saved session will resume automatically.</T>
                        </p>
                    </main>
                ) : !state.user ? (
                    <main class="accounts-page">
                        <Credentials setup={false} onDone={refresh} />
                    </main>
                ) : (
                    children
                )}
            </Context.Provider>
        </I18nProvider>
    );
}
