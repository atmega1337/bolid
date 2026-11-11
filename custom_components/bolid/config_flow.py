import voluptuous as vol
from homeassistant import config_entries
from homeassistant.core import callback

from .const import (DOMAIN, CONF_IP, CONF_PORT, CONF_LOOPS, CONF_SLAVE, CONF_ZONES, CONF_POLL,
                    CONF_STALE, CONF_GROUP, CONF_EVENTS, CONF_CONTROL, DEFAULT_PORT, DEFAULT_POLL,
                    DEFAULT_STALE, DEFAULT_GROUP, MIN_POLL)


def _options_schema(d):
    return vol.Schema({
        vol.Required(CONF_ZONES, default=d.get(CONF_ZONES, "1-16")): str,
        vol.Required(CONF_POLL, default=d.get(CONF_POLL, DEFAULT_POLL)):
            vol.All(vol.Coerce(int), vol.Range(min=MIN_POLL, max=3600)),
        vol.Required(CONF_STALE, default=d.get(CONF_STALE, DEFAULT_STALE)):
            vol.All(vol.Coerce(int), vol.Range(min=2, max=7200)),
        vol.Required(CONF_GROUP, default=d.get(CONF_GROUP, DEFAULT_GROUP)):
            vol.All(vol.Coerce(int), vol.Range(min=1, max=100)),
        vol.Required(CONF_EVENTS, default=d.get(CONF_EVENTS, False)): bool,
        vol.Required(CONF_CONTROL, default=d.get(CONF_CONTROL, True)): bool,
    })


def _validate(user_input) -> dict:
    """Ошибки проверки: список зон и «таймаут устаревания > период опроса»."""
    from .c2000pp import parse_zone_spec
    errors = {}
    try:
        if not parse_zone_spec(user_input[CONF_ZONES]):
            raise ValueError
    except ValueError:
        errors[CONF_ZONES] = "invalid_zones"
    if user_input[CONF_STALE] <= user_input[CONF_POLL]:
        errors[CONF_STALE] = "stale_le_poll"
    return errors


def _defaults_from_entry(entry):
    """Старые записи хранили только loops_count – превращаем в список зон."""
    d = {}
    if CONF_LOOPS in entry.data:
        d[CONF_ZONES] = f"1-{entry.data[CONF_LOOPS]}"
    return d


class BolidConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    VERSION = 1

    @staticmethod
    @callback
    def async_get_options_flow(config_entry):
        return BolidOptionsFlow(config_entry)

    async def async_step_user(self, user_input=None):
        errors = {}
        if user_input is not None:
            errors = _validate(user_input)
            if not errors:
                await self.async_set_unique_id(user_input[CONF_IP])
                self._abort_if_unique_id_configured()
                data = {k: user_input[k] for k in (CONF_IP, CONF_PORT, CONF_SLAVE)}
                opts = {k: user_input[k] for k in (CONF_ZONES, CONF_POLL, CONF_STALE, CONF_GROUP,
                                                   CONF_EVENTS, CONF_CONTROL)}
                return self.async_create_entry(title=f"S2000PP ({user_input[CONF_IP]})",
                                               data=data, options=opts)
        schema = vol.Schema({
            vol.Required(CONF_IP): str,
            vol.Required(CONF_PORT, default=DEFAULT_PORT): int,
            vol.Required(CONF_SLAVE, default=1): vol.All(int, vol.Range(min=1, max=247)),
            **_options_schema(user_input or {}).schema,
        })
        return self.async_show_form(step_id="user", data_schema=schema, errors=errors)


class BolidOptionsFlow(config_entries.OptionsFlow):
    def __init__(self, entry):
        self._entry = entry

    async def async_step_init(self, user_input=None):
        errors = {}
        if user_input is not None:
            errors = _validate(user_input)
            if not errors:
                return self.async_create_entry(title="", data=user_input)
        cur = {**_defaults_from_entry(self._entry), **self._entry.options, **(user_input or {})}
        return self.async_show_form(step_id="init", data_schema=_options_schema(cur), errors=errors)
