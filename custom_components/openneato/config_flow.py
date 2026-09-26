"""Config flow for OpenNeato integration."""

from __future__ import annotations

import logging
from typing import Any

import voluptuous as vol

from homeassistant.config_entries import ConfigFlow, ConfigFlowResult
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.helpers.selector import TextSelector, TextSelectorConfig, TextSelectorType

from .api import (
    OpenNeatoApiClient, OpenNeatoAuthError, OpenNeatoPermissionError,
    OpenNeatoConnectionError, OpenNeatoApiError,
)
from .const import DOMAIN, CONF_HOST, CONF_API_KEY

_LOGGER = logging.getLogger(__name__)


def _schema(data: dict[str, Any]) -> vol.Schema:
    """Credentials are optional; blank fields explicitly remove saved credentials."""
    return vol.Schema({
        vol.Required(CONF_HOST, default=data.get(CONF_HOST, "")): str,
        vol.Optional(CONF_API_KEY, default=""): TextSelector(
            TextSelectorConfig(type=TextSelectorType.PASSWORD)
        ),
    })


class OpenNeatoConfigFlow(ConfigFlow, domain=DOMAIN):
    """Handle setup, credential recovery and user-requested reconfiguration."""

    VERSION = 1

    async def async_step_user(self, user_input: dict[str, Any] | None = None) -> ConfigFlowResult:
        return await self._async_connection_step("user", user_input)

    async def async_step_reconfigure(self, user_input: dict[str, Any] | None = None) -> ConfigFlowResult:
        return await self._async_connection_step("reconfigure", user_input)

    async def async_step_reauth(self, entry_data: dict[str, Any]) -> ConfigFlowResult:
        return await self.async_step_reauth_confirm()

    async def async_step_reauth_confirm(self, user_input: dict[str, Any] | None = None) -> ConfigFlowResult:
        return await self._async_connection_step("reauth_confirm", user_input)

    async def _async_connection_step(
        self, step_id: str, user_input: dict[str, Any] | None,
    ) -> ConfigFlowResult:
        errors: dict[str, str] = {}
        entry = None
        if step_id == "reconfigure":
            entry = self._get_reconfigure_entry()
        elif step_id == "reauth_confirm":
            entry = self._get_reauth_entry()
        defaults = dict(entry.data) if entry else {}
        if user_input is not None:
            defaults = user_input
            host = user_input[CONF_HOST].strip()
            api_key = user_input.get(CONF_API_KEY, "").strip()
            api = OpenNeatoApiClient(host, async_get_clientsession(self.hass), api_key)
            try:
                firmware = await api.get_firmware_version()
                robot = await api.get_robot_version()
                # The integration exposes device settings and requires Admin access.
                await api.get_settings()
            except OpenNeatoAuthError:
                errors["base"] = "invalid_auth"
            except OpenNeatoPermissionError:
                errors["base"] = "insufficient_permissions"
            except (OpenNeatoConnectionError, OpenNeatoApiError):
                errors["base"] = "cannot_connect"
            except Exception:  # noqa: BLE001
                _LOGGER.exception("Unexpected exception during config flow")
                errors["base"] = "unknown"
            else:
                serial = robot.get("serialNumber", "")
                if not serial:
                    errors["base"] = "unknown"
                elif entry and serial != entry.unique_id:
                    errors["base"] = "wrong_device"
                else:
                    data = {
                        CONF_HOST: host, CONF_API_KEY: api_key,
                        "serial": serial, "model": robot.get("modelName"),
                        "firmware_version": firmware.get("version"),
                        "software_version": robot.get("softwareVersion"),
                    }
                    if entry:
                        cleaned = {key: value for key, value in entry.data.items() if key not in ("username", "password")}
                        return self.async_update_reload_and_abort(entry, data={**cleaned, **data})
                    await self.async_set_unique_id(serial)
                    self._abort_if_unique_id_configured()
                    return self.async_create_entry(
                        title=robot.get("modelName") or f"OpenNeato ({host})", data=data,
                    )
        return self.async_show_form(step_id=step_id, data_schema=_schema(defaults), errors=errors)
