"""Number platform for Solity BLE: lock volume, as the app shows it (0-6)."""
from __future__ import annotations

from homeassistant.components.number import NumberEntity, NumberMode
from homeassistant.const import EntityCategory
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from . import SolityBleConfigEntry
from .ble import SolityBleError
from .entity import SolityBleSettingEntity

# App volume steps; the lock itself uses 1-7 (= step + 1).
VOLUME_STEP_MIN = 0
VOLUME_STEP_MAX = 6


async def async_setup_entry(
    hass: HomeAssistant,
    entry: SolityBleConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    async_add_entities([SolityBleVolume(entry)])


class SolityBleVolume(SolityBleSettingEntity, NumberEntity):
    """Lock volume; writing it keeps the mute (etiquette mode) setting."""

    _attr_icon = "mdi:volume-high"
    _attr_entity_category = EntityCategory.CONFIG
    _attr_native_min_value = VOLUME_STEP_MIN
    _attr_native_max_value = VOLUME_STEP_MAX
    _attr_native_step = 1
    _attr_mode = NumberMode.SLIDER

    def __init__(self, entry: SolityBleConfigEntry) -> None:
        super().__init__(entry, "volume")

    @property
    def native_value(self) -> float | None:
        f = self.function
        if f is None or f.volume is None:
            return None
        return max(f.volume - 1, VOLUME_STEP_MIN)

    async def async_set_native_value(self, value: float) -> None:
        step = int(round(value))
        if not VOLUME_STEP_MIN <= step <= VOLUME_STEP_MAX:
            raise HomeAssistantError(f"음량은 {VOLUME_STEP_MIN}~{VOLUME_STEP_MAX} 사이여야 합니다")
        try:
            await self.coordinator.async_set_volume_step(step)
        except SolityBleError as err:
            raise HomeAssistantError(f"도어락 음량 변경 실패: {err}") from err
