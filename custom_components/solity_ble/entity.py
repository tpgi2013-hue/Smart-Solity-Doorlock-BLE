"""Shared bits for Solity BLE entities."""
from __future__ import annotations

from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .ble import SolityFunction
from .const import CONF_MAC, CONF_NAME, DOMAIN, MANUFACTURER, MODEL
from .coordinator import SolityBleCoordinator


def device_info(entry) -> DeviceInfo:
    mac = entry.data[CONF_MAC]
    return DeviceInfo(
        identifiers={(DOMAIN, mac)},
        connections={("bluetooth", mac)},
        name=entry.data.get(CONF_NAME) or "Solity Doorlock (BLE)",
        manufacturer=MANUFACTURER,
        model=MODEL,
    )


class SolityBleSettingEntity(CoordinatorEntity[SolityBleCoordinator]):
    """An entity backed by the lock's settings frame (0x5A -> 0xDA)."""

    _attr_has_entity_name = True

    def __init__(self, entry, key: str) -> None:
        super().__init__(entry.runtime_data.coordinator)
        self._attr_unique_id = f"{entry.data[CONF_MAC]}_{key}"
        self._attr_translation_key = key
        self._attr_device_info = device_info(entry)

    @property
    def function(self) -> SolityFunction | None:
        return self.coordinator.function

    @property
    def available(self) -> bool:
        # Settings are known once read; they stay valid between BLE sessions.
        return self.function is not None
