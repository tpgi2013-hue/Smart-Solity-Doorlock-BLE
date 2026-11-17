"""Sensor platform for Solity BLE — status frame, last access, settings extras."""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from homeassistant.components.bluetooth import async_last_service_info

from homeassistant.components.sensor import (
    RestoreSensor,
    SensorDeviceClass,
    SensorEntity,
    SensorEntityDescription,
    SensorStateClass,
)
from homeassistant.const import (
    PERCENTAGE,
    SIGNAL_STRENGTH_DECIBELS_MILLIWATT,
    EntityCategory,
)
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.util import dt as dt_util
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from . import SolityBleConfigEntry
from .ble import SolityFunction, SolityStatus
from .const import CONF_MAC, CONF_NAME, DOMAIN, MANUFACTURER, MODEL
from .const import EVENT_TYPE_OPEN
from .coordinator import SolityAccess, SolityBleCoordinator
from .entity import SolityBleSettingEntity


@dataclass(frozen=True, kw_only=True)
class SolityBleSensorDescription(SensorEntityDescription):
    """Describes a Solity BLE sensor."""

    value_fn: Callable[[SolityStatus], int | None]


SENSORS: tuple[SolityBleSensorDescription, ...] = (
    SolityBleSensorDescription(
        key="battery",
        device_class=SensorDeviceClass.BATTERY,
        native_unit_of_measurement=PERCENTAGE,
        state_class=SensorStateClass.MEASUREMENT,
        entity_category=EntityCategory.DIAGNOSTIC,
        value_fn=lambda s: s.battery,
    ),
    SolityBleSensorDescription(
        key="count_card",
        translation_key="count_card",
        icon="mdi:card-account-details",
        state_class=SensorStateClass.MEASUREMENT,
        entity_category=EntityCategory.DIAGNOSTIC,
        value_fn=lambda s: s.count_card,
    ),
    SolityBleSensorDescription(
        key="count_password",
        translation_key="count_password",
        icon="mdi:dialpad",
        state_class=SensorStateClass.MEASUREMENT,
        entity_category=EntityCategory.DIAGNOSTIC,
        value_fn=lambda s: s.pw_info,
    ),
    # No count_fingerprint / count_face / count_vein here: this lock's BLE
    # status frame reports password and card counts, but not fingerprint, face
    # or vein (the app reads those from a separate registration-list command).
    # Use the FM225 entity (sensor.front_door_face_face_count) for faces.
    SolityBleSensorDescription(
        key="count_remote",
        translation_key="count_remote",
        icon="mdi:remote",
        state_class=SensorStateClass.MEASUREMENT,
        entity_category=EntityCategory.DIAGNOSTIC,
        value_fn=lambda s: s.count_remote,
    ),
    SolityBleSensorDescription(
        key="count_mastercard",
        translation_key="count_mastercard",
        icon="mdi:card-account-details-star",
        state_class=SensorStateClass.MEASUREMENT,
        entity_category=EntityCategory.DIAGNOSTIC,
        value_fn=lambda s: s.count_mastercard,
    ),
    SolityBleSensorDescription(
        key="system_mode",
        translation_key="system_mode",
        icon="mdi:cog",
        entity_category=EntityCategory.DIAGNOSTIC,
        value_fn=lambda s: s.system_mode,
    ),
    SolityBleSensorDescription(
        key="sub_latch",
        translation_key="sub_latch",
        icon="mdi:gesture-tap-button",
        entity_category=EntityCategory.DIAGNOSTIC,
        value_fn=lambda s: s.sub_latch,
    ),
)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: SolityBleConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up the Solity BLE sensors."""
    coordinator = entry.runtime_data.coordinator
    entities: list[SensorEntity] = [
        SolityBleSensor(coordinator, entry, desc) for desc in SENSORS
    ]
    entities.append(SolityBleRssiSensor(hass, entry))
    entities.append(SolityBleLastAccessSensor(entry, timestamp=False))
    entities.append(SolityBleLastAccessSensor(entry, timestamp=True))
    for desc in SETTING_SENSORS:
        entities.append(SolityBleSettingSensor(entry, desc))
    async_add_entities(entities)


# Settings this lock model has, read-only (app 기능설정: 외부/내부 강제잠금,
# 수동잠금). Volume is a number entity, mute a switch. Keys keep the 1.4.0 unique IDs.
@dataclass(frozen=True, kw_only=True)
class SolityBleSettingDescription(SensorEntityDescription):
    value_fn: Callable[[SolityFunction], int | str | None]


def _on_off(value: int | None) -> str | None:
    return None if value is None else ("on" if value == 1 else "off")


SETTING_SENSORS: tuple[SolityBleSettingDescription, ...] = (
    SolityBleSettingDescription(
        key="always_open",
        icon="mdi:lock-open-variant",
        device_class=SensorDeviceClass.ENUM,
        options=["off", "on"],
        value_fn=lambda f: _on_off(f.always_open),
    ),
    SolityBleSettingDescription(
        key="double_lock",
        icon="mdi:lock-plus",
        device_class=SensorDeviceClass.ENUM,
        options=["off", "inside", "outside"],
        value_fn=lambda f: {0: "off", 1: "inside", 2: "outside"}.get(f.double_lock)
        if f.double_lock is not None
        else None,
    ),
)


class SolityBleLastAccessSensor(RestoreSensor):
    """Last time the door was opened from outside/inside, and how.

    ``timestamp=False``: text like '지문 3번 (재현)'. ``timestamp=True``: when
    (lock clock). Both carry method / slot / person attributes. Survives HA
    restarts (the lock hands each log entry out only once).
    """

    _attr_has_entity_name = True
    _attr_should_poll = False

    def __init__(self, entry: SolityBleConfigEntry, timestamp: bool) -> None:
        self._coordinator = entry.runtime_data.coordinator
        self._timestamp = timestamp
        key = "last_access_time" if timestamp else "last_access"
        self._attr_translation_key = key
        self._attr_unique_id = f"{entry.data[CONF_MAC]}_{key}"
        self._attr_device_info = _device_info(entry)
        if timestamp:
            self._attr_device_class = SensorDeviceClass.TIMESTAMP
            self._attr_icon = "mdi:door-open"
        else:
            self._attr_icon = "mdi:account-key"
        self._attr_extra_state_attributes = {}

    async def async_added_to_hass(self) -> None:
        await super().async_added_to_hass()
        last = await self.async_get_last_state()
        last_data = await self.async_get_last_sensor_data()
        if last is not None:
            self._attr_extra_state_attributes = {
                k: v
                for k, v in last.attributes.items()
                if k in ("method", "method_code", "slot", "person", "at", "battery", "source")
            }
        if last_data is not None and last_data.native_value is not None:
            value = last_data.native_value
            if self._timestamp and isinstance(value, str):
                value = dt_util.parse_datetime(value)
            self._attr_native_value = value
        self.async_on_remove(self._coordinator.add_access_listener(self._on_access))

    @callback
    def _on_access(self, access: SolityAccess) -> None:
        if access.event_type != EVENT_TYPE_OPEN:
            return
        prev = self._attr_extra_state_attributes.get("at")
        if prev:
            prev_at = dt_util.parse_datetime(prev)
            if prev_at is not None and access.at < prev_at:
                return  # an older entry arriving late
        self._attr_native_value = access.at if self._timestamp else access.summary
        self._attr_extra_state_attributes = access.as_attributes()
        self.async_write_ha_state()


class SolityBleSettingSensor(SolityBleSettingEntity, SensorEntity):
    """A lock setting read from the settings frame."""

    _attr_entity_category = EntityCategory.DIAGNOSTIC
    entity_description: SolityBleSettingDescription

    def __init__(
        self, entry: SolityBleConfigEntry, description: SolityBleSettingDescription
    ) -> None:
        super().__init__(entry, description.key)
        self.entity_description = description

    @property
    def native_value(self) -> int | str | None:
        f = self.function
        return self.entity_description.value_fn(f) if f is not None else None


def _device_info(entry: SolityBleConfigEntry) -> DeviceInfo:
    mac = entry.data[CONF_MAC]
    return DeviceInfo(
        identifiers={(DOMAIN, mac)},
        connections={("bluetooth", mac)},
        name=entry.data.get(CONF_NAME) or "Solity Doorlock (BLE)",
        manufacturer=MANUFACTURER,
        model=MODEL,
    )


class SolityBleRssiSensor(SensorEntity):
    """Signal strength of the lock as seen by the HA Bluetooth proxy mesh."""

    _attr_has_entity_name = True
    _attr_translation_key = "rssi"
    _attr_device_class = SensorDeviceClass.SIGNAL_STRENGTH
    _attr_native_unit_of_measurement = SIGNAL_STRENGTH_DECIBELS_MILLIWATT
    _attr_state_class = SensorStateClass.MEASUREMENT
    _attr_entity_category = EntityCategory.DIAGNOSTIC

    def __init__(self, hass: HomeAssistant, entry: SolityBleConfigEntry) -> None:
        self._hass = hass
        self._mac = entry.data[CONF_MAC]
        self._attr_unique_id = f"{self._mac}_rssi"
        self._attr_device_info = _device_info(entry)

    @property
    def native_value(self) -> int | None:
        # connectable=False: the strongest advertisement across all proxies.
        info = async_last_service_info(self._hass, self._mac, connectable=False)
        return info.rssi if info is not None else None


class SolityBleSensor(CoordinatorEntity[SolityBleCoordinator], SensorEntity):
    """A status value read from the lock over BLE."""

    _attr_has_entity_name = True
    entity_description: SolityBleSensorDescription

    def __init__(
        self,
        coordinator: SolityBleCoordinator,
        entry: SolityBleConfigEntry,
        description: SolityBleSensorDescription,
    ) -> None:
        super().__init__(coordinator)
        self.entity_description = description
        mac = entry.data[CONF_MAC]
        self._attr_unique_id = f"{mac}_{description.key}"
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, mac)},
            connections={("bluetooth", mac)},
            name=entry.data.get(CONF_NAME) or "Solity Doorlock (BLE)",
            manufacturer=MANUFACTURER,
            model=MODEL,
        )

    @property
    def native_value(self) -> int | None:
        data = self.coordinator.data
        if data is None:
            return None
        return self.entity_description.value_fn(data)
