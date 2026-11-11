from homeassistant.components.binary_sensor import BinarySensorDeviceClass, BinarySensorEntity
from homeassistant.const import MATCH_ALL
from homeassistant.helpers.entity import EntityCategory

from .const import DOMAIN, CONF_IP
from .entity import BolidEntity


async def async_setup_entry(hass, entry, async_add_entities):
    d = hass.data[DOMAIN][entry.entry_id]
    async_add_entities([BolidLink(d["coordinator"], d["client"], entry)])


class BolidLink(BolidEntity, BinarySensorEntity):
    """Связь с С2000-ПП (есть валидные ответы). В атрибутах – диагностика обмена."""
    _attr_device_class = BinarySensorDeviceClass.CONNECTIVITY
    _attr_entity_category = EntityCategory.DIAGNOSTIC
    _unrecorded_attributes = frozenset({MATCH_ALL})     # статистика не пишется в recorder

    def __init__(self, coordinator, client, entry):
        super().__init__(coordinator, client, entry)
        self._attr_name = f"С2000-ПП связь ({entry.data[CONF_IP]})"
        self._attr_unique_id = f"{entry.entry_id}_link"

    async def async_added_to_hass(self):
        await super().async_added_to_hass()
        # обновляем атрибуты после каждого цикла опроса (только эта сущность, не все зоны)
        def on_event(name, payload):
            if name == "poll":
                self.async_write_ha_state()
        self.async_on_remove(self._client.add_listener(on_event))

    @property
    def available(self):
        return True

    @property
    def is_on(self):
        return self._client.available

    @property
    def extra_state_attributes(self):
        c = self._client
        attrs = {**c.t.stats, **c.info,
                 "last_poll_duration_s": round(c.last_poll_duration, 3),
                 "poll_interval_s": c.poll_interval, "stale_timeout_s": c.stale_timeout,
                 "group_size": c.group_size}
        rtt = c.t.rtt_stats()
        if rtt:
            attrs.update({f"rtt_{k}_ms": round(v, 1) for k, v in rtt.items() if k != "n"})
        return attrs
