from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DOMAIN, CONF_IP


def device_info(entry, client) -> DeviceInfo:
    return DeviceInfo(identifiers={(DOMAIN, entry.entry_id)}, manufacturer="Болид",
                      model="С2000-ПП", name=f"С2000-ПП ({entry.data[CONF_IP]})",
                      sw_version=client.info.get("version"))


class BolidEntity(CoordinatorEntity):
    _attr_has_entity_name = False

    def __init__(self, coordinator, client, entry):
        super().__init__(coordinator)
        self._client, self._entry = client, entry
        self._attr_device_info = device_info(entry, client)
