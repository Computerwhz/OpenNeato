import assert from 'node:assert/strict';
import test from 'node:test';
import { createMockAuth } from '../../frontend/mock/auth.js';

test('development auth supports setup, login, permissions and account revocation', async () => {
    const auth = createMockAuth();
    const request = async (path, method = 'GET', values = {}, cookie = '') => auth({
        path, method, cookie, text: async () => new URLSearchParams(values).toString(),
    });
    assert.equal(JSON.parse((await request('/api/auth/me')).body).setupRequired, true);
    assert.equal(JSON.parse((await request('/api/auth/me')).body).authEnabled, false);
    assert.equal(await request('/api/state'), null);
    assert.equal((await request('/api/auth/settings', 'PUT', { enabled: 'true' })).status, 409);
    assert.equal((await request('/api/auth/setup', 'POST', { username: 'test-admin', password: 'test-only-passphrase' })).status, 200);
    assert.equal((await request('/api/auth/settings', 'PUT', { enabled: 'true' })).status, 200);
    const login = await request('/api/auth/login', 'POST', { username: 'test-admin', password: 'test-only-passphrase' });
    assert.equal(login.status, 200);
    const cookie = login.headers['Set-Cookie'];
    assert.match(cookie, /HttpOnly; SameSite=Strict/);
    assert.equal(JSON.parse((await request('/api/auth/me', 'GET', {}, cookie)).body).user.role, 'Admin');
    assert.equal((await request('/api/users', 'POST', { username: 'test-viewer', password: 'test-only-passphrase', role: 'Viewer' }, cookie)).status, 200);
    const viewer = (await request('/api/auth/login', 'POST', { username: 'test-viewer', password: 'test-only-passphrase' })).headers['Set-Cookie'];
    assert.equal(await request('/api/state', 'GET', {}, viewer), null);
    assert.equal((await request('/api/clean', 'POST', {}, viewer)).status, 403);
    assert.equal((await request('/api/users', 'GET', {}, viewer)).status, 403);
    assert.equal((await request('/api/auth/settings', 'PUT', { enabled: 'false' }, viewer)).status, 403);
    const listed = (await request('/api/users', 'GET', {}, cookie)).body;
    assert.doesNotMatch(listed, /salt|hash|test-only-passphrase/);
    assert.equal((await request('/api/users/0', 'DELETE', {}, cookie)).status, 409);
    assert.equal((await request('/api/users/1', 'PUT', { revokeSessions: 'true' }, cookie)).status, 200);
    assert.equal((await request('/api/state', 'GET', {}, viewer)).status, 401);
    assert.equal((await request('/api/auth/logout', 'POST', {}, cookie)).status, 200);
    assert.equal((await request('/api/state', 'GET', {}, cookie)).status, 401);
});

test('Home Assistant keys rotate, revoke and cannot manage accounts', async () => {
    const auth = createMockAuth();
    const request = (path, method = 'GET', authorization = '') => auth({ path, method, authorization, text: async () => '' });
    const first = JSON.parse((await request('/api/auth/ha-key', 'POST')).body).key;
    assert.match(first, /^onha_[0-9a-f]{64}$/);
    assert.deepEqual(JSON.parse((await request('/api/auth/ha-key')).body), { configured: true });
    await auth({ path: '/api/auth/setup', method: 'POST', text: async () => 'username=root&password=test-only-passphrase' });
    await auth({ path: '/api/auth/settings', method: 'PUT', text: async () => 'enabled=true' });
    assert.equal(await request('/api/settings', 'GET', `Bearer ${first}`), null);
    assert.equal((await request('/api/users', 'GET', `Bearer ${first}`)).status, 403);
    assert.equal((await request('/api/auth/ha-key', 'POST', `Bearer ${first}`)).status, 403);
    assert.equal((await request('/api/state', 'GET', 'Bearer invalid')).status, 401);
    const login = await auth({ path: '/api/auth/login', method: 'POST', text: async () => 'username=root&password=test-only-passphrase' });
    const admin = (method) => auth({ path: '/api/auth/ha-key', method, cookie: login.headers['Set-Cookie'], text: async () => '' });
    const second = JSON.parse((await admin('POST')).body).key;
    assert.notEqual(first, second);
    assert.equal((await request('/api/state', 'GET', `Bearer ${first}`)).status, 401);
    assert.equal(await request('/api/state', 'GET', `Bearer ${second}`), null);
    assert.equal((await admin('DELETE')).status, 200);
    assert.equal((await request('/api/state', 'GET', `Bearer ${second}`)).status, 401);
});
