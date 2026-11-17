"""Status / access-log / settings coordinator for Solity BLE.

Periodically reads the lock's status over BLE (battery, deadbolt, credential
counts, system mode). Each open/close also yields a fresh status frame, which
the lock entity pushes in here so the sensors update immediately without an
extra connection.

Every BLE session also drains the lock's access-log queue (who opened, how,
which slot, when) and catches live door events pushed while connected; both
end up here as ``SolityAccess`` records for the event entity and the
last-access sensors. The settings frame (volume, auto-lock …) is read at
start and every few hours.
"""
from __future__ import annotations

import logging
import re
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta

from homeassistant.core import CALLBACK_TYPE, HomeAssistant, callback
from homeassistant.helpers.event import async_call_later
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed
from homeassistant.util import dt as dt_util

from .ble import (
    EVENT_CLOSE,
    EVENT_OPEN,
    SolityBleClient,
    SolityBleError,
    SolityEvent,
    SolityFunction,
    SolityStatus,
)
from .const import (
    EVENT_TYPE_CLOSE,
    EVENT_TYPE_OPEN,
    EVENT_TYPE_OTHER,
    FUNCTION_REFRESH_HOURS,
    LIVE_DEDUP_SECONDS,
    MEDIA_NAMES,
    SLOT_MEDIA,
    SLOT_NAME_ALIASES,
    UNLOCKED_RECHECK_MAX,
    UNLOCKED_RECHECK_SECONDS,
)

_LOGGER = logging.getLogger(__name__)

_SLOT_LINE = re.compile(r"^\s*(\D+?)\s*(\d+)\s*(?:번)?\s*[=:]\s*(.+?)\s*$")


def parse_slot_names(text: str | None) -> dict[tuple[int, int], str]:
    """Parse "지문 3 = 재현" lines into {(media, slot): name}."""
    names: dict[tuple[int, int], str] = {}
    for line in re.split(r"[\n,;]", text or ""):
        m = _SLOT_LINE.match(line)
        if not m:
            continue
        word = m.group(1).replace(" ", "")
        medias = SLOT_NAME_ALIASES.get(word)
        if medias is None:
            continue
        for media in medias:
            names[(media, int(m.group(2)))] = m.group(3)
    return names


@dataclass
class SolityAccess:
    """One access event as shown in Home Assistant."""

    event_type: str  # open / close / other
    method: str  # e.g. "지문", "실내"
    method_code: int | None
    slot: int | None
    person: str | None
    at: datetime  # when it happened (lock clock, or now for live events)
    battery: int | None
    source: str  # "live" | "log"

    @property
    def summary(self) -> str:
        """e.g. '지문 3번 (재현)', '실내', '비밀번호 1번'."""
        text = self.method
        if self.slot:
            text = f"{text} {self.slot}번"
        if self.person:
            text = f"{text} ({self.person})"
        return text

    def as_attributes(self) -> dict:
        return {
            "method": self.method,
            "method_code": self.method_code,
            "slot": self.slot,
            "person": self.person,
            "at": self.at.isoformat(),
            "battery": self.battery,
            "source": self.source,
        }


class SolityBleCoordinator(DataUpdateCoordinator[SolityStatus | None]):
    """Polls lock status over BLE and accepts status pushed from commands."""

    def __init__(
        self,
        hass: HomeAssistant,
        client: SolityBleClient,
        name: str,
        poll_minutes: int,
        slot_names: dict[tuple[int, int], str] | None = None,
    ) -> None:
        super().__init__(
            hass,
            _LOGGER,
            name=name,
            update_interval=timedelta(minutes=poll_minutes) if poll_minutes > 0 else None,
        )
        self.client = client
        self.slot_names = slot_names or {}
        self._recheck_cancel: CALLBACK_TYPE | None = None
        self._rechecks = 0
        self._function_read_at: float | None = None
        self._live_recent: list[tuple[int, int | None, int | None, float]] = []
        self._access_listeners: list[Callable[[SolityAccess], None]] = []
        client.set_event_listener(self._on_events)
        client.set_function_listener(self._on_function)

    # ---- status ------------------------------------------------------------

    async def _async_update_data(self) -> SolityStatus | None:
        read_function = (
            self._function_read_at is None
            or time.monotonic() - self._function_read_at > FUNCTION_REFRESH_HOURS * 3600
        )
        try:
            status = await self.client.async_read_status(read_function=read_function)
        except SolityBleError as err:
            raise UpdateFailed(str(err)) from err
        if status is None:
            # Connected/authed but no status frame arrived; keep last data.
            return self.data
        self._schedule_recheck(status)
        return status

    @callback
    def apply_status(self, status: SolityStatus | None) -> None:
        """Push a status captured during an open/close command."""
        if status is not None:
            self.async_set_updated_data(status)

    @callback
    def _schedule_recheck(self, status: SolityStatus) -> None:
        """Re-read soon while the deadbolt reads retracted.

        A read taken while someone is using the door says 'unlocked'; without
        this the stale value would stay until the next regular poll.
        """
        self.cancel_recheck()
        if status.is_locked is not False:
            self._rechecks = 0
            return
        if self._rechecks >= UNLOCKED_RECHECK_MAX:
            return
        self._rechecks += 1

        @callback
        def _fire(_now) -> None:
            self._recheck_cancel = None
            self.hass.async_create_task(self.async_request_refresh())

        self._recheck_cancel = async_call_later(
            self.hass, UNLOCKED_RECHECK_SECONDS, _fire
        )

    @callback
    def cancel_recheck(self) -> None:
        if self._recheck_cancel is not None:
            self._recheck_cancel()
            self._recheck_cancel = None

    # ---- settings ----------------------------------------------------------

    @property
    def function(self) -> SolityFunction | None:
        return self.client.function

    async def async_set_volume_step(self, step: int) -> None:
        """Set the volume as the app shows it (0-6); keeps the mute setting."""
        f = self.function
        mute = f is not None and f.mute == 1
        await self.client.async_set_volume(mute, step + 1)

    async def async_set_mute(self, mute: bool) -> None:
        """Turn mute (etiquette mode) on/off; keeps the volume level."""
        f = self.function
        level = f.volume if f is not None and f.volume else 1
        await self.client.async_set_volume(mute, level)

    @callback
    def _on_function(self, _function: SolityFunction) -> None:
        self._function_read_at = time.monotonic()
        self.async_update_listeners()

    # ---- access events -----------------------------------------------------

    @callback
    def add_access_listener(
        self, listener: Callable[[SolityAccess], None]
    ) -> CALLBACK_TYPE:
        self._access_listeners.append(listener)

        @callback
        def _remove() -> None:
            if listener in self._access_listeners:
                self._access_listeners.remove(listener)

        return _remove

    @callback
    def _on_events(self, events: list[SolityEvent]) -> None:
        now = time.monotonic()
        self._live_recent = [
            r for r in self._live_recent if now - r[3] < LIVE_DEDUP_SECONDS
        ]
        # Oldest first, so listeners end on the newest event.
        ordered = sorted(
            events,
            key=lambda e: e.logged_at or datetime.max,
        )
        for ev in ordered:
            if ev.live:
                self._live_recent.append((ev.event, ev.media, ev.slot, now))
            elif self._is_live_duplicate(ev):
                _LOGGER.debug("Solity BLE log entry already seen live: %s", ev.raw.hex())
                continue
            access = self._to_access(ev)
            _LOGGER.debug("Solity BLE access: %s %s", access.event_type, access.summary)
            for listener in list(self._access_listeners):
                listener(access)

    def _is_live_duplicate(self, ev: SolityEvent) -> bool:
        for i, (event, media, slot, _t) in enumerate(self._live_recent):
            if event == ev.event and media == ev.media and (
                slot == ev.slot or ev.event != EVENT_OPEN
            ):
                del self._live_recent[i]
                return True
        return False

    def _to_access(self, ev: SolityEvent) -> SolityAccess:
        if ev.event == EVENT_OPEN:
            event_type = EVENT_TYPE_OPEN
        elif ev.event == EVENT_CLOSE:
            event_type = EVENT_TYPE_CLOSE
        else:
            event_type = EVENT_TYPE_OTHER

        if event_type == EVENT_TYPE_OTHER:
            method = f"기타 이벤트 {ev.media}" if ev.media is not None else "기타 이벤트"
        elif ev.media is None:
            method = "알 수 없음"
        else:
            method = MEDIA_NAMES.get(ev.media, f"방법 {ev.media}")

        # Only credential methods carry a meaningful slot (실내/원격/스마트오픈
        # report a stray 1).
        slot = ev.slot if ev.media in SLOT_MEDIA and ev.slot else None
        person = None
        if slot is not None and ev.media is not None:
            person = self.slot_names.get((ev.media, slot))

        if ev.logged_at is not None:
            at = ev.logged_at.replace(tzinfo=dt_util.get_default_time_zone())
        else:
            at = dt_util.now()

        return SolityAccess(
            event_type=event_type,
            method=method,
            method_code=ev.media,
            slot=slot,
            person=person,
            at=at,
            battery=ev.battery,
            source="live" if ev.live else "log",
        )
