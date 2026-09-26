import assert from "node:assert/strict";
import test from "node:test";
import { networkRequest } from "../../frontend/src/network-request.ts";

test("a transient read failure recovers before reaching UI error state", async (t) => {
    let calls = 0;
    t.mock.method(globalThis, "fetch", async () => {
        if (++calls === 1) throw new TypeError("Failed to fetch");
        return new Response("{}");
    });
    assert.equal((await networkRequest("/api/auth/me")).status, 200);
    assert.equal(calls, 2);
});

test("persistent read failures remain visible after one retry", async (t) => {
    let calls = 0;
    t.mock.method(globalThis, "fetch", async () => {
        calls++;
        throw new TypeError("Failed to fetch");
    });
    await assert.rejects(networkRequest("/api/state"), /Unable to connect to OpenNeato/);
    assert.equal(calls, 2);
});

test("writes are never replayed", async (t) => {
    let calls = 0;
    t.mock.method(globalThis, "fetch", async () => {
        calls++;
        throw new TypeError("Failed to fetch");
    });
    for (const method of ["POST", "PUT", "DELETE"]) {
        await assert.rejects(networkRequest("/api/clean", { method }), /Unable to connect/);
    }
    assert.equal(calls, 3);
});

test("HTTP errors are returned immediately", async (t) => {
    let calls = 0;
    t.mock.method(globalThis, "fetch", async () => { calls++; return new Response("", { status: 401 }); });
    assert.equal((await networkRequest("/api/state")).status, 401);
    assert.equal(calls, 1);
});

test("aborts and non-network errors are not hidden", async (t) => {
    const failure = new Error("unexpected failure");
    t.mock.method(globalThis, "fetch", async () => { throw failure; });
    await assert.rejects(networkRequest("/api/state"), (error) => error === failure);
});
