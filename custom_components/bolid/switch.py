from homeassistant.components.switch import SwitchEntity
from homeassistant.exceptions import HomeAssistantError

from .const import DOMAIN, CONF_IP, CONF_CONTROL
from .entity import BolidEntity


async def async_setup_entry(hass, entry, async_add_entities):
    if not entry.options.get(CONF_CONTROL, True):
        return
    d = hass.data[DOMAIN][entry.entry_id]
    client = d["client"]
    async_add_entities([BolidArmSwitch(d["coordinator"], client, entry, z)
                        for z in sorted(client.zones)])


class BolidArmSwitch(BolidEntity, SwitchEntity):
    """Взять / снять шлейф.

    Пока ПП не подтвердил команду (1–3 с, у шлейфов с задержкой взятия дольше), переключатель
    показывает ЦЕЛЕВОЕ состояние – без «моргания». Если за 15 с подтверждения нет, показывается
    реальное. Требует разрешения управления зонами в конфигурации С2000-ПП."""

    def __init__(self, coordinator, client, entry, zone):
        super().__init__(coordinator, client, entry)
        self._zone = zone
        self._attr_name = f"Охрана шлейфа {zone} ({entry.data[CONF_IP]})"
        self._attr_unique_id = f"{entry.entry_id}_arm_{zone}"
        self._attr_entity_registry_enabled_default = False   # включаете вручную нужные

    @property
    def _z(self):
        return (self.coordinator.data or {}).get(self._zone)

    @property
    def available(self):
        z = self._z
        return bool(z) and z["status"] == "ok"

    @property
    def is_on(self):
        z = self._z
        return bool(z and z["armed"])        # «armed» уже учитывает ожидающую команду

    @property
    def extra_state_attributes(self):
        z = self._z or {}
        return {"actual_armed": z.get("armed_actual"), "pending": z.get("pending"),
                "state": z.get("name")}

    async def _do(self, fn):
        try:
            await fn(self._zone)
        except Exception as err:             # ModbusException / C2000Timeout
            raise HomeAssistantError(f"С2000-ПП: команда для шлейфа {self._zone} не выполнена: {err}") from err

    async def async_turn_on(self, **kwargs):
        await self._do(self._client.arm_zone)

    async def async_turn_off(self, **kwargs):
        await self._do(self._client.disarm_zone)
