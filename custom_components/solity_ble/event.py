"""Event platform for Solity BLE: every door access as it is read from the lock.

Fires once per access-log entry (read from the lock's queue in each BLE
session) and per live door event the lock pushes while connected. Event types:
``open`` / ``close`` / ``other``; attributes say how (method), which slot,
who (from the slot names option) and when the lock logged it.
"""
from __future__ import annotations

from homeassistant.components.event import EventEntity
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from . import SolityBleConfigEntry
from .const import CONF_MAC, EVENT_TYPE_CLOSE, EVENT_TYPE_OPEN, EVENT_TYPE_OTHER
from .coordinator import SolityAccess
from .entity import device_info


async def async_setup_entry(
    hass: HomeAssistant,
    entry: SolityBleConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    async_add_entities([SolityBleAccessEvent(entry)])


class SolityBleAccessEvent(EventEntity):
    """Door access events (open / close / other) from the lock."""

    _attr_has_entity_name = True
    _attr_translation_key = "access"
    _attr_icon = "mdi:door"
    _attr_event_types = [EVENT_TYPE_OPEN, EVENT_TYPE_CLOSE, EVENT_TYPE_OTHER]
    _attr_should_poll = False

    def __init__(self, entry: SolityBleConfigEntry) -> None:
        self._coordinator = entry.runtime_data.coordinator
        self._attr_unique_id = f"{entry.data[CONF_MAC]}_access_event"
        self._attr_device_info = device_info(entry)

    async def async_added_to_hass(self) -> None:
        await super().async_added_to_hass()
        self.async_on_remove(self._coordinator.add_access_listener(self._on_access))

    @callback
    def _on_access(self, access: SolityAccess) -> None:
        attrs = access.as_attributes()
        attrs["summary"] = access.summary
        self._trigger_event(access.event_type, attrs)
        self.async_write_ha_state()
