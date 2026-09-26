"""Run with python -m unittest discover -s tests/ha (aiohttp, voluptuous required).

HA framework surfaces are stubbed; HTTP requests use a real local aiohttp server.
"""
import asyncio
import importlib
from pathlib import Path
import sys
import types
import unittest
from unittest.mock import AsyncMock, patch

import aiohttp
from aiohttp import web

ROOT = Path(__file__).resolve().parents[2]


def module(name, **attrs):
    value = types.ModuleType(name)
    value.__dict__.update(attrs)
    sys.modules[name] = value
    return value


class HAError(Exception):
    pass


class Flow:
    def __init_subclass__(cls, **kwargs):
        pass

    def async_show_form(self, **kwargs):
        return kwargs

    def async_create_entry(self, **kwargs):
        return kwargs

    async def async_set_unique_id(self, value):
        self.unique_id = value

    def _abort_if_unique_id_configured(self):
        pass

    def _get_reconfigure_entry(self):
        return self.entry

    _get_reauth_entry = _get_reconfigure_entry

    def async_update_reload_and_abort(self, entry, **kwargs):
        return kwargs


module('homeassistant')
module('homeassistant.components')
module('homeassistant.components.vacuum', VacuumActivity=types.SimpleNamespace(
    CLEANING='cleaning', PAUSED='paused', RETURNING='returning'))
module('homeassistant.exceptions', HomeAssistantError=HAError, ConfigEntryAuthFailed=HAError)
module('homeassistant.config_entries', ConfigFlow=Flow, ConfigFlowResult=dict)
module('homeassistant.const', CONF_USERNAME='username', CONF_PASSWORD='password')
module('homeassistant.helpers')
module('homeassistant.helpers.aiohttp_client', async_get_clientsession=lambda hass: hass)
module('homeassistant.helpers.selector', TextSelector=lambda config: str,
       TextSelectorConfig=dict, TextSelectorType=types.SimpleNamespace(PASSWORD='password'))
class Coordinator:
    @classmethod
    def __class_getitem__(cls, item):
        return cls

    def __init__(self, *args, **kwargs):
        self.data = {}


module('homeassistant.core', HomeAssistant=object)
module('homeassistant.helpers.update_coordinator', DataUpdateCoordinator=Coordinator, UpdateFailed=HAError)
package = module('test_openneato')
package.__path__ = [str(ROOT / 'custom_components/openneato')]
api = importlib.import_module('test_openneato.api')
flow = importlib.import_module('test_openneato.config_flow')
coordinator = importlib.import_module('test_openneato.coordinator')


class ClientTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.enabled = True
        self.token = 'a' * 64
        self.logins = 0
        self.requests = []
        self.login_status = 200
        self.api_key = "onha_" + "c" * 64
        self.forbidden = False
        self.reject_token = False
        self.redirect = False
        app = web.Application()
        app.router.add_route('*', '/{path:.*}', self.handle)
        self.runner = web.AppRunner(app)
        await self.runner.setup()
        site = web.TCPSite(self.runner, '127.0.0.1', 0)
        await site.start()
        port = site._server.sockets[0].getsockname()[1]
        self.session = aiohttp.ClientSession(cookie_jar=aiohttp.DummyCookieJar())
        self.client = api.OpenNeatoApiClient(f'127.0.0.1:{port}', self.session, self.api_key)

    async def asyncTearDown(self):
        await self.session.close()
        await self.runner.cleanup()

    async def handle(self, request):
        self.requests.append((request.method, request.path, request.headers.get('Cookie')))
        if request.method != 'GET' and request.headers.get('X-OpenNeato') != '1':
            return web.Response(status=403)
        if request.path == '/api/auth/login':
            self.logins += 1
            self.assertEqual(dict(await request.post()), {'username': 'admin', 'password': 'secret'})
            self.assertFalse(request.query)
            response = web.json_response({}, status=self.login_status)
            if self.login_status == 200:
                response.set_cookie('openneato_session', self.token, httponly=True)
            return response
        if self.redirect:
            return web.Response(status=302, headers={'Location': '/redirect-target'})
        bearer = request.headers.get('Authorization')
        if bearer and bearer != f'Bearer {self.api_key}':
            return web.Response(status=401)
        if self.reject_token or (self.enabled and not bearer and request.cookies.get('openneato_session') != self.token):
            return web.Response(status=401)
        if self.forbidden:
            return web.Response(status=403)
        if request.path == '/api/history/123.jsonl' and request.method == 'GET':
            return web.Response(text='{"time":1}\n')
        return web.json_response({'ok': True})

    async def test_api_key_auth_and_rejection_never_use_password_login(self):
        self.client._api_key = self.api_key
        await self.client.get_state()
        await self.client.clean('house')
        await self.client.get_history_session('123.jsonl')
        self.assertEqual(self.logins, 0)
        self.client._api_key = 'revoked'
        with self.assertRaises(api.OpenNeatoAuthError):
            await self.client.get_state()
        self.assertEqual(self.logins, 0)

    async def test_auth_off_and_write_header(self):
        self.enabled = False
        self.client._api_key = ''
        await self.client.clean('house')
        self.assertEqual(self.logins, 0)

    async def test_missing_credentials(self):
        self.client._api_key = ''
        with self.assertRaises(api.OpenNeatoAuthError):
            await self.client.get_state()
        self.assertEqual(self.logins, 0)

    async def test_forbidden_does_not_relogin(self):
        await self.client.get_state()
        self.forbidden = True
        with self.assertRaises(api.OpenNeatoPermissionError):
            await self.client.get_settings()
        self.assertEqual(self.logins, 0)

    async def test_separate_clients_do_not_share_token(self):
        await self.client.get_state()
        other = api.OpenNeatoApiClient(self.client._host, self.session)
        with self.assertRaises(api.OpenNeatoAuthError):
            await other.get_state()

    async def test_redirect_is_not_followed(self):
        self.redirect = True
        with self.assertRaises(api.OpenNeatoApiError):
            await self.client.get_state()
        self.assertEqual(len(self.requests), 1)

    async def test_coordinator_raises_reauth_instead_of_using_stale_data(self):
        self.client._api_key = 'revoked'
        instance = coordinator.OpenNeatoCoordinator(None, self.client)
        instance.data = {'state': {'stale': True}}
        with self.assertRaises(HAError):
            await instance._async_update_data()
        self.assertEqual(self.logins, 0)


class FlowTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.flow = flow.OpenNeatoConfigFlow()
        self.flow.hass = object()
        self.client = types.SimpleNamespace(
            get_firmware_version=AsyncMock(return_value={'version': '1'}),
            get_robot_version=AsyncMock(return_value={'serialNumber': '123', 'modelName': 'D7'}),
            get_settings=AsyncMock(return_value={}),
        )
        self.mock = patch.object(flow, 'OpenNeatoApiClient', return_value=self.client)
        self.factory = self.mock.start()
        self.addCleanup(self.mock.stop)

    async def test_optional_schema_and_legacy_setup(self):
        fields = flow._schema({})({'host': 'robot'})
        self.assertEqual(fields, {'host': 'robot', 'api_key': ''})
        result = await self.flow.async_step_user({'host': 'robot'})
        self.assertEqual(result['data']['api_key'], '')
        self.assertNotIn('username', result['data'])
        self.assertNotIn('password', result['data'])

    async def test_api_key_configuration(self):
        result = await self.flow.async_step_user({'host': 'robot', 'api_key': 'onha_test'})
        self.assertEqual(result['data']['api_key'], 'onha_test')
        self.client.get_settings.assert_awaited_once()

    async def test_auth_and_permission_errors(self):
        for error, key in [(api.OpenNeatoAuthError(), 'invalid_auth'),
                           (api.OpenNeatoPermissionError(), 'insufficient_permissions')]:
            self.client.get_settings.side_effect = error
            result = await self.flow.async_step_user({'host': 'robot'})
            self.assertEqual(result['errors']['base'], key)

    async def test_reauth_and_reconfigure_preserve_device_identity(self):
        self.flow.entry = types.SimpleNamespace(unique_id='123', data={'host': 'robot', 'username': 'old', 'password': 'old-secret'})
        for step in (self.flow.async_step_reauth_confirm, self.flow.async_step_reconfigure):
            result = await step({'host': 'robot', 'api_key': 'new'})
            self.assertEqual(result['data']['api_key'], 'new')
            self.assertNotIn('username', result['data'])
            self.assertNotIn('password', result['data'])
            self.flow.entry.unique_id = 'different'
            result = await step({'host': 'robot'})
            self.assertEqual(result['errors']['base'], 'wrong_device')
            self.flow.entry.unique_id = '123'


if __name__ == '__main__':
    unittest.main()
