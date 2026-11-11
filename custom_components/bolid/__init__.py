"""Интеграция С2000-ПП (Болид) через С2000-Ethernet.

Вся работа с сетью – в c2000pp.C2000PP (asyncio, один сокет, одна очередь запросов).
Здесь только связка с Home Assistant: данные приходят «пушем» через слушателя клиента.
"""
import logging

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import Platform
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryNotReady
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator

from .const import (DOMAIN, CONF_IP, CONF_PORT, CONF_LOOPS, CONF_SLAVE, CONF_ZONES, CONF_POLL,
                    CONF_STALE, CONF_GROUP, CONF_EVENTS, DEFAULT_PORT, DEFAULT_POLL,
                    DEFAULT_STALE, DEFAULT_GROUP)

_LOGGER = logging.getLogger(__name__)
PLATFORMS = [Platform.SENSOR, Platform.BINARY_SENSOR, Platform.SWITCH]


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    from .c2000pp import C2000PP, C2000Error, parse_zone_spec

    opts = {**entry.options}
    zones_spec = opts.get(CONF_ZONES) or f"1-{entry.data.get(CONF_LOOPS, 16)}"
    zones = parse_zone_spec(zones_spec)

    client = C2000PP(
        entry.data[CONF_IP], entry.data.get(CONF_PORT, DEFAULT_PORT),
        slave_id=entry.data.get(CONF_SLAVE, 1), zones=zones,
        poll_interval=opts.get(CONF_POLL, DEFAULT_POLL),
        stale_timeout=opts.get(CONF_STALE, DEFAULT_STALE),
        group_size=opts.get(CONF_GROUP, DEFAULT_GROUP),
        use_events=opts.get(CONF_EVENTS, False),
    )
    try:
        await client.start()
    except C2000Error as err:
        raise ConfigEntryNotReady(str(err)) from err

    coordinator = DataUpdateCoordinator(hass, _LOGGER, name=f"Bolid {entry.data[CONF_IP]}",
                                        update_interval=None)   # только push от клиента
    coordinator.async_set_updated_data(client.snapshot())

    def on_client_event(name, payload):
        if name in ("zones", "availability"):
            coordinator.async_set_updated_data(client.snapshot())
        elif name == "event":
            hass.bus.async_fire(f"{DOMAIN}_event", {
                "host": entry.data[CONF_IP], "number": payload.number, "code": payload.code,
                "name": payload.name, "zone": payload.zone, "section": payload.section,
                "user": payload.user, "time": payload.time})

    entry.async_on_unload(client.add_listener(on_client_event))
    entry.async_on_unload(entry.add_update_listener(_reload_on_options))

    hass.data.setdefault(DOMAIN, {})[entry.entry_id] = {"client": client, "coordinator": coordinator}

    try:                                   # первый опрос не блокирует запуск при недоступности
        await client.poll_all()
        await client.read_device_info()
    except C2000Error as err:
        _LOGGER.warning("Первичный опрос С2000-ПП не удался: %s", err)
    coordinator.async_set_updated_data(client.snapshot())

    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    return True


async def _reload_on_options(hass: HomeAssistant, entry: ConfigEntry):
    await hass.config_entries.async_reload(entry.entry_id)


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    ok = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    if ok:
        data = hass.data[DOMAIN].pop(entry.entry_id)
        await data["client"].stop()        # освобождает UDP-порт до повторного setup
    return ok
