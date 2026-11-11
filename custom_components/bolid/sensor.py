from homeassistant.components.sensor import SensorEntity

from .const import DOMAIN, CONF_IP
from .entity import BolidEntity


async def async_setup_entry(hass, entry, async_add_entities):
    d = hass.data[DOMAIN][entry.entry_id]
    client, coord = d["client"], d["coordinator"]
    async_add_entities([BolidZoneSensor(coord, client, entry, z) for z in sorted(client.zones)])


class BolidZoneSensor(BolidEntity, SensorEntity):
    """Состояние шлейфа/зоны (реальное, как его сообщает ПП)."""

    def __init__(self, coordinator, client, entry, zone):
        super().__init__(coordinator, client, entry)
        self._zone = zone
        self._attr_name = f"Шлейф {zone} ({entry.data[CONF_IP]})"
        self._attr_unique_id = f"{entry.entry_id}_zone_{zone}"   # как в старой версии

    @property
    def _z(self):
        return (self.coordinator.data or {}).get(self._zone)

    @property
    def available(self):
        # timeout -> «недоступен»: данные давно не обновлялись (ошибка таймаута)
        z = self._z
        return bool(z) and z["status"] != "timeout"

    @property
    def native_value(self):
        z = self._z
        if not z:
            return None
        if z["status"] == "pending":
            return "Ожидание данных"
        if z["status"] == "no_data":
            return "Нет данных"
        return z["name"]

    @property
    def extra_state_attributes(self):
        z = self._z or {}
        return {"code": z.get("code"), "status": z.get("status"),
                "armed": z.get("armed_actual"), "error": z.get("error") or None}
