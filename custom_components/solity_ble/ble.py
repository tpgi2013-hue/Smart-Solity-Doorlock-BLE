"""BLE transport for a Solity WELKOM lock with the Bluetooth pack.

Reproduces the Solity app's BLE handshake over Home Assistant's Bluetooth
proxy mesh, bypassing the cloud entirely:

    connect -> notify(48400003)
    0x10 EXCHANGE_KEY (plaintext)   -> lock replies 0x90 with a receive key
    session IV = appKey[0:8] + receiveKey[0:8]
    0x11 AUTH_APP   (AES-128-CBC)   -> lock replies 0x91, result 0 = authed
    0x21 OPEN / 0x22 CLOSE (AES-CBC)-> lock replies 0xA1 / 0xA2, result 0 = done

Right after auth the lock pushes a 0xD1 status frame (deadbolt, sub-latch,
battery, registered-credential counts, system mode). Every BLE session
captures it, so open/close/status all return a fresh ``SolityStatus``.

Access log: the lock queues every open/close (method + credential slot +
time). ``0x5D INQUIRE_MODULE_LOG`` hands out queued entries in ``0xDD`` and
removes them from the lock (``saveCnt`` = how many are left), exactly like
the Solity app does before uploading them. While a session is up the lock
also pushes ``0x53 / 0x54 / 0x55`` event frames the moment the door is used.

Settings: ``0x5A`` -> ``0xDA`` reads volume / mute / manual lock / auto-lock
time / double lock / two-factor auth / voice. Volume can be written
(``0x27`` mute + level -> ``0xA7`` result).

Warm sessions: ``async_prewarm`` connects and authenticates ahead of time and
holds the session until ``async_release`` (or a safety cap). A command arriving
while held skips the connection setup (~1-3 s) and only pays for the command
itself. Without a hold every command connects, runs and disconnects.

Frame: ``48 <len> <cmd> <data...> <checksum>`` with ``len = len(data)+1`` and
``checksum = (len + cmd + sum(data)) & 0xFF``. The AES key is fixed across
(non-China) locks; the per-lock secret is ``appKey`` — the owner account's
``regDeviceAppKey`` (base64).
"""
from __future__ import annotations

import asyncio
import base64
import contextlib
import logging
import time
from dataclasses import dataclass, field
from collections.abc import Callable
from datetime import datetime

from bleak.backends.characteristic import BleakGATTCharacteristic
from bleak_retry_connector import (
    BleakClientWithServiceCache,
    establish_connection,
)
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from homeassistant.components import bluetooth
from homeassistant.core import HomeAssistant

_LOGGER = logging.getLogger(__name__)

WRITE_UUID = "48400002-b5a3-f393-e0a9-e50e24dcca9e"
NOTIFY_UUID = "48400003-b5a3-f393-e0a9-e50e24dcca9e"

AES_KEY = b"H-GANG BLE MODE1"  # fixed, non-China firmware
STX = 0x48

CMD_EXCHANGE_KEY = 0x10
CMD_AUTH_APP = 0x11
CMD_OPEN = 0x21
CMD_CLOSE = 0x22
CMD_STATUS_REQ = 0x51  # ask the lock for its status
CMD_FUNCTION_REQ = 0x5A  # DOOR_LOCK_FUNCTION: read settings
CMD_VOLUME = 0x27  # set volume: mute(0/1) + level(1-7)
CMD_LOG_REQ = 0x5D  # INQUIRE_MODULE_LOG: hand out queued access-log entries
ACK_EXCHANGE_KEY = 0x90
ACK_AUTH_APP = 0x91
ACK_OPEN = 0xA1
ACK_CLOSE = 0xA2
ACK_STATUS = 0xD1  # status reply (to 0x51), carries the DoorLockStatus payload
ACK_FUNCTION = 0xDA
ACK_VOLUME = 0xA7
ACK_LOG = 0xDD
ACK_ERROR = 0xFF

# Event frames pushed by the lock while connected / log entry event byte
EVENT_OPEN = 0x53
EVENT_CLOSE = 0x54
EVENT_ETC = 0x55
EVENT_FRAMES = (EVENT_OPEN, EVENT_CLOSE, EVENT_ETC)

# Safety cap on 0x5D pages read in one session.
LOG_MAX_PAGES = 20
LOG_RECV_TIMEOUT = 4.0
# After the lock ignores a log/settings request, skip those extras this long
# so later sessions (opens!) don't each wait out the timeout.
EXTRA_BACKOFF_SECONDS = 3600

# Standard manual-open parameters (app clickStateIcon, BLE path):
#   code = 0, address = 0, second = 7
OPEN_SUFFIX = bytes([0, 0, 7])
CLOSE_SUFFIX = bytes()

CONNECT_ATTEMPTS = 4
RECV_TIMEOUT = 6.0
CMD_RECV_TIMEOUT = 8.0
# After a command the lock may push one more 0xD1; it arrives within ~0.2 s.
STATUS_DRAIN_TIMEOUT = 0.4
# Pause before retrying a failed command on a fresh connection, so the retry
# carries a new time-key second (precaution; the lock's rule is not documented).
RETRY_DELAY = 1.1
# OPEN/CLOSE result byte: the deadbolt is already in the asked position.
RESULT_ALREADY = 1


class SolityBleError(Exception):
    """A BLE command failed."""


class SolityBleRejected(SolityBleError):
    """The lock answered a command with a non-zero result."""

    def __init__(self, cmd: int, result: int) -> None:
        super().__init__(f"command 0x{cmd:02X} rejected (result={result})")
        self.cmd = cmd
        self.result = result


@dataclass
class SolityStatus:
    """Parsed 0xD1 door-lock status frame."""

    deadbolt: int | None = None
    sub_latch: int | None = None
    battery: int | None = None
    pw_info: int | None = None
    count_card: int | None = None
    count_remote: int | None = None
    count_fingerprint: int | None = None
    count_mastercard: int | None = None
    system_mode: int | None = None
    count_face: int | None = None
    count_vein: int | None = None
    user_pw_info: bytes = field(default=b"")

    @property
    def is_locked(self) -> bool | None:
        """Real deadbolt state (1 = thrown/locked, 0 = retracted)."""
        if self.deadbolt is None:
            return None
        return self.deadbolt == 1


def _parse_status(data: bytes) -> SolityStatus:
    """Decode a DoorLockStatus payload (byte layout from the Solity app)."""

    def g(i: int) -> int | None:
        return data[i] if i < len(data) else None

    return SolityStatus(
        deadbolt=g(0),
        sub_latch=g(1),
        battery=g(2),
        pw_info=g(3),
        count_card=g(4),
        count_remote=g(5),
        count_fingerprint=g(6),
        count_mastercard=g(7),
        system_mode=g(8),
        count_face=g(9),
        count_vein=g(10),
        user_pw_info=bytes(data[11:]) if len(data) > 11 else b"",
    )


@dataclass
class SolityEvent:
    """One access event: from the queued log (0xDD) or pushed live (0x53-0x55)."""

    event: int  # EVENT_OPEN / EVENT_CLOSE / EVENT_ETC
    media: int | None  # how (DoorLock.Event.Data: 1 pw, 5 card, 8 fingerprint ...)
    slot: int | None  # which credential slot (opens only)
    battery: int | None
    logged_at: datetime | None  # lock's own clock (log entries); None = live
    live: bool = False
    raw: bytes = field(default=b"")


@dataclass
class SolityLogPage:
    """One 0xDD reply."""

    remaining: int  # saveCnt
    entries: list[SolityEvent]


@dataclass
class SolityFunction:
    """Parsed 0xDA settings frame (DoorLockFunction)."""

    go_out: int | None = None
    double_lock: int | None = None  # 0 off / 1 inside / 2 outside
    mute: int | None = None  # 1 = mute (etiquette mode)
    volume: int | None = None  # 1-7
    imaginary_number: int | None = None
    always_open: int | None = None  # 1 = manual lock (auto-lock off)
    two_factor_auth: int | None = None
    voice_type: int | None = None
    lock_time: int | None = None  # auto-lock delay, seconds
    raw: bytes = field(default=b"")


def _parse_function(data: bytes) -> SolityFunction:
    def g(i: int) -> int | None:
        return data[i] if i < len(data) else None

    return SolityFunction(
        go_out=g(0),
        double_lock=g(1),
        mute=g(2),
        volume=g(3),
        imaginary_number=g(4),
        always_open=g(5),
        two_factor_auth=g(6),
        voice_type=g(7),
        lock_time=g(8),
        raw=bytes(data),
    )


def _parse_log(data: bytes) -> SolityLogPage:
    """Decode a 0xDD payload: saveCnt, sendCnt, then 10-byte entries.

    Entry: yy mm dd hh mi ss | event | media (or ETC code) | slot | battery.
    """
    if len(data) < 2:
        return SolityLogPage(remaining=0, entries=[])
    remaining, count = data[0], data[1]
    entries: list[SolityEvent] = []
    off = 2
    for _ in range(count):
        e = data[off : off + 10]
        if len(e) < 10:
            break
        off += 10
        try:
            when = datetime(2000 + e[0], e[1], e[2], e[3], e[4], e[5])
        except ValueError:
            when = None
        entries.append(
            SolityEvent(
                event=e[6],
                media=e[7],
                slot=e[8] if e[6] == EVENT_OPEN else None,
                battery=e[9],
                logged_at=when,
                raw=bytes(e),
            )
        )
    return SolityLogPage(remaining=remaining, entries=entries)


def _parse_live_event(cmd: int, data: bytes) -> SolityEvent:
    """Decode a pushed 0x53/0x54/0x55 frame: command, add(slot), battery."""

    def g(i: int) -> int | None:
        return data[i] if i < len(data) else None

    return SolityEvent(
        event=cmd,
        media=g(0),
        slot=g(1) if cmd == EVENT_OPEN else None,
        battery=g(2),
        logged_at=None,
        live=True,
        raw=bytes(data),
    )


def _valid_plain(frame: bytes) -> bool:
    """True for an unencrypted, checksum-correct frame."""
    if len(frame) < 4 or frame[0] != STX:
        return False
    n = frame[1]
    if 3 + n > len(frame):
        return False
    body = frame[3 : 2 + n]
    return frame[2 + n] == (n + frame[2] + sum(body)) & 0xFF


def parse_app_key(raw: str) -> bytes:
    """Decode the base64 ``regDeviceAppKey`` into its key bytes."""
    try:
        key = base64.b64decode(raw, validate=True)
    except Exception as err:  # noqa: BLE001
        raise SolityBleError(f"appKey is not valid base64: {err}") from err
    if len(key) < 8:
        raise SolityBleError(f"appKey too short ({len(key)} bytes, need >= 8)")
    return key


def _time_key() -> bytes:
    """7-byte current-time key: year(hi,lo), month, day, hour, minute, second."""
    n = datetime.now()
    return bytes(
        [(n.year >> 8) & 0xFF, n.year & 0xFF, n.month, n.day, n.hour, n.minute, n.second]
    )


def _build(cmd: int, data: bytes) -> bytes:
    length = (len(data) + 1) & 0xFF
    checksum = (length + cmd + sum(data)) & 0xFF
    return bytes([STX, length, cmd]) + data + bytes([checksum])


def _pad(data: bytes) -> bytes:
    pad = 16 - (len(data) % 16)
    return data + bytes([pad]) * pad


def _encrypt(data: bytes, iv: bytes) -> bytes:
    enc = Cipher(algorithms.AES(AES_KEY), modes.CBC(iv)).encryptor()
    return enc.update(_pad(data)) + enc.finalize()


def _decrypt(data: bytes, iv: bytes) -> bytes:
    # App decrypts with NoPadding and reads the frame by its length field.
    dec = Cipher(algorithms.AES(AES_KEY), modes.CBC(iv)).decryptor()
    return dec.update(data) + dec.finalize()


class SolityBleClient:
    """Sends OPEN / CLOSE / status / log / settings reads to one lock over BLE."""

    def __init__(self, hass: HomeAssistant, mac: str, app_key: bytes) -> None:
        self.hass = hass
        self.mac = mac.upper()
        self.app_key = app_key
        self._lock = asyncio.Lock()  # one BLE operation at a time per lock
        self._client: BleakClientWithServiceCache | None = None
        self._iv: bytes | None = None
        self._queue: asyncio.Queue[bytes] = asyncio.Queue()
        self._status: SolityStatus | None = None
        self._hold_handle: asyncio.TimerHandle | None = None
        self._hold_listener: Callable[[], None] | None = None
        # Access log: read (and so take over) the lock's queued entries in
        # every session. Off = leave them for the Solity app.
        self.read_log = True
        self._event_listener: Callable[[list[SolityEvent]], None] | None = None
        self._function: SolityFunction | None = None
        self._function_listener: Callable[[SolityFunction], None] | None = None
        self._log_skip_until = 0.0
        self._function_skip_until = 0.0

    # ---- public API -----------------------------------------------------

    async def async_open(self) -> SolityStatus | None:
        """Retract the deadbolt. Returns the status captured this session."""
        return await self._run(CMD_OPEN, OPEN_SUFFIX, ACK_OPEN)

    async def async_close(self) -> SolityStatus | None:
        """Throw the deadbolt. Returns the status captured this session."""
        return await self._run(CMD_CLOSE, CLOSE_SUFFIX, ACK_CLOSE)

    async def async_read_status(self, read_function: bool = False) -> SolityStatus | None:
        """Connect, authenticate, request status (0x51), and parse 0xD1.

        Also drains the access log (when ``read_log``) and, if asked, reads
        the settings frame in the same connection.
        """
        return await self._run(
            CMD_STATUS_REQ, b"", ACK_STATUS, read_function=read_function
        )

    async def async_set_volume(self, mute: bool, level: int) -> SolityFunction | None:
        """Write mute + volume level (1-7), then re-read the settings frame."""
        if not 1 <= level <= 7:
            raise SolityBleError(f"volume level out of range: {level}")
        await self._run(
            CMD_VOLUME, bytes([1 if mute else 0, level]), ACK_VOLUME, read_function=True
        )
        return self._function

    @property
    def function(self) -> SolityFunction | None:
        """Last settings frame read from the lock."""
        return self._function

    def set_event_listener(
        self, listener: Callable[[list[SolityEvent]], None] | None
    ) -> None:
        """Receive access events (queued log entries and live pushes)."""
        self._event_listener = listener

    def set_function_listener(
        self, listener: Callable[[SolityFunction], None] | None
    ) -> None:
        """Receive every freshly read settings frame."""
        self._function_listener = listener

    def _emit(self, events: list[SolityEvent]) -> None:
        if not events or self._event_listener is None:
            return
        try:
            self._event_listener(events)
        except Exception:  # noqa: BLE001
            _LOGGER.exception("Solity BLE event listener failed")

    @property
    def holding(self) -> bool:
        """True while a prewarmed session is being held open."""
        return self._hold_handle is not None

    def set_hold_listener(self, listener: Callable[[], None] | None) -> None:
        """Register a callback fired whenever ``holding`` may have changed."""
        self._hold_listener = listener

    def _notify_hold(self) -> None:
        if self._hold_listener is not None:
            self._hold_listener()

    async def async_prewarm(self, max_seconds: float) -> None:
        """Connect + authenticate now and hold the session for up to ``max_seconds``.

        A command sent while held reuses the session (no connect delay) and the
        hold ends with it. ``async_release`` ends the hold early. Calling again
        while held restarts the ``max_seconds`` timer without reconnecting.
        """
        async with self._lock:
            self._cancel_hold()
            try:
                await self._ensure_session()
            except BaseException:
                await self._teardown()
                self._notify_hold()
                raise
            self._hold_handle = self.hass.loop.call_later(
                max_seconds, self._hold_expired
            )
        self._notify_hold()

    async def async_release(self) -> None:
        """End a prewarm hold now and drop the session.

        The person who triggered the standby has usually just come in (card,
        fingerprint, password), so the access log is read before hanging up.
        """
        async with self._lock:
            if self._hold_handle is None and self._client is None:
                return
            self._cancel_hold()
            await self._drain_log_safely()
            await self._teardown()
        self._notify_hold()

    async def async_shutdown(self) -> None:
        """Drop any warm session (integration unload)."""
        self._hold_listener = None
        async with self._lock:
            self._cancel_hold()
            await self._teardown()

    # ---- session handling -------------------------------------------------

    def _is_warm(self) -> bool:
        return (
            self._client is not None
            and self._client.is_connected
            and self._iv is not None
        )

    def _cancel_hold(self) -> None:
        if self._hold_handle is not None:
            self._hold_handle.cancel()
            self._hold_handle = None

    def _hold_expired(self) -> None:
        handle = self._hold_handle
        self.hass.async_create_task(self._release(handle))

    async def _release(self, handle: asyncio.TimerHandle | None) -> None:
        async with self._lock:
            if self._hold_handle is not handle:
                return  # window was restarted, released or consumed by a command
            self._hold_handle = None
            await self._drain_log_safely()
            await self._teardown()
        self._notify_hold()

    async def _teardown(self) -> None:
        client, self._client, self._iv = self._client, None, None
        if client is None:
            return
        with contextlib.suppress(Exception):
            await client.stop_notify(NOTIFY_UUID)
        with contextlib.suppress(Exception):
            await client.disconnect()

    def _on_notify(self, _char: BleakGATTCharacteristic, data: bytearray) -> None:
        raw = bytes(data)
        iv = self._iv
        if iv is not None:
            # Live door events can arrive at any time (also while a session is
            # only held for standby, when nobody reads the queue): handle them
            # right here instead of queueing.
            frame = _decode(raw, iv)
            if len(frame) >= 3 and frame[0] == STX and frame[2] in EVENT_FRAMES:
                self._note(frame)
                return
        self._queue.put_nowait(raw)

    def _note(self, frame: bytes) -> None:
        if len(frame) < 3 or frame[0] != STX:
            return
        payload = frame[3 : 3 + (frame[1] - 1)]
        cmd = frame[2]
        if cmd == ACK_STATUS:
            _LOGGER.debug("Solity BLE 0xD1 status frame: %s", frame.hex())
            self._status = _parse_status(payload)
        elif cmd == ACK_FUNCTION:
            _LOGGER.debug("Solity BLE 0xDA function frame: %s", frame.hex())
            self._function = _parse_function(payload)
            if self._function_listener is not None:
                try:
                    self._function_listener(self._function)
                except Exception:  # noqa: BLE001
                    _LOGGER.exception("Solity BLE function listener failed")
        elif cmd in EVENT_FRAMES:
            _LOGGER.debug("Solity BLE live event frame: %s", frame.hex())
            self._emit([_parse_live_event(cmd, payload)])

    async def _await(self, want: int, iv: bytes | None, timeout: float) -> bytes:
        while True:
            raw = await asyncio.wait_for(self._queue.get(), timeout)
            frame = raw if iv is None else _decode(raw, iv)
            if len(frame) < 3 or frame[0] != STX:
                continue
            if frame[2] == ACK_ERROR:
                raise SolityBleError("lock reported receive error (0xFF)")
            self._note(frame)
            if frame[2] == want:
                return frame

    async def _ensure_session(self) -> None:
        """Have a connected, authenticated session (reusing a warm one)."""
        if self._is_warm():
            return
        await self._teardown()
        try:
            await self._connect_and_auth()
        except TimeoutError as err:
            raise SolityBleError("timed out waiting for lock response") from err
        except SolityBleError:
            raise
        except Exception as err:  # noqa: BLE001
            raise SolityBleError(f"BLE error: {err}") from err

    async def _connect_and_auth(self) -> None:
        ble_device = bluetooth.async_ble_device_from_address(
            self.hass, self.mac, connectable=True
        )
        if ble_device is None:
            raise SolityBleError(
                f"{self.mac} not reachable by any Bluetooth proxy right now"
            )
        self._queue = asyncio.Queue()
        self._status = None
        client = await establish_connection(
            BleakClientWithServiceCache,
            ble_device,
            self.mac,
            max_attempts=CONNECT_ATTEMPTS,
        )
        self._client = client
        await client.start_notify(NOTIFY_UUID, self._on_notify)

        # 1) EXCHANGE_KEY (plaintext) -> 0x90 with the receive key
        await client.write_gatt_char(
            WRITE_UUID,
            _build(CMD_EXCHANGE_KEY, _time_key() + self.app_key),
            response=True,
        )
        exch = await self._await(ACK_EXCHANGE_KEY, None, RECV_TIMEOUT)
        receive_key = exch[3 : 3 + (exch[1] - 1)]
        if len(receive_key) < 8:
            raise SolityBleError(f"short receiveKey ({len(receive_key)}B)")

        # 2) session IV = appKey[0:8] + receiveKey[0:8]
        iv = (bytes(self.app_key[:8]) + bytes(receive_key[:8]) + bytes(16))[:16]

        # 3) AUTH_APP (encrypted) -> 0x91 result 0
        await client.write_gatt_char(
            WRITE_UUID,
            _encrypt(_build(CMD_AUTH_APP, _time_key() + self.app_key), iv),
            response=True,
        )
        auth = await self._await(ACK_AUTH_APP, iv, RECV_TIMEOUT)
        if auth[3] != 0:
            raise SolityBleError(f"auth rejected (result={auth[3]})")
        self._iv = iv
        _LOGGER.debug("Solity BLE session ready (%s)", self.mac)

    # ---- commands -------------------------------------------------------

    async def _run(
        self, cmd: int, suffix: bytes, ack: int, read_function: bool = False
    ) -> SolityStatus | None:
        try:
            return await self._run_locked(cmd, suffix, ack, read_function)
        finally:
            self._notify_hold()

    async def _run_locked(
        self, cmd: int, suffix: bytes, ack: int, read_function: bool
    ) -> SolityStatus | None:
        async with self._lock:
            self._cancel_hold()
            warm = self._is_warm()
            try:
                try:
                    result = await self._command(cmd, suffix, ack)
                except SolityBleError as err:
                    if isinstance(err, SolityBleRejected) and err.result == RESULT_ALREADY:
                        # "Already in that state" (e.g. opened by keypad or
                        # from inside) — a new connection gets the same
                        # answer. Let the caller re-read the real state
                        # instead of spending a second connection here.
                        raise
                    # A warm session the lock already dropped, or a command
                    # that landed while the session was ending, fails.
                    # Retry once on a brand-new connection.
                    _LOGGER.warning(
                        "Solity BLE 0x%02X failed on %s session (%s), retrying on a new connection",
                        cmd,
                        "warm" if warm else "cold",
                        err,
                    )
                    await self._teardown()
                    await asyncio.sleep(RETRY_DELAY)
                    result = await self._command(cmd, suffix, ack)
                # The command is done (door already open etc.); extras ride on
                # the same connection and never fail the command.
                if read_function:
                    await self._read_function_safely()
                await self._drain_log_safely()
                return result
            finally:
                await self._teardown()

    async def _command(self, cmd: int, suffix: bytes, ack: int) -> SolityStatus | None:
        warm = self._is_warm()
        await self._ensure_session()
        client, iv = self._client, self._iv
        assert client is not None and iv is not None
        try:
            cmd_data = _time_key() + self.app_key + suffix
            await client.write_gatt_char(
                WRITE_UUID, _encrypt(_build(cmd, cmd_data), iv), response=True
            )
            done = await self._await(ack, iv, CMD_RECV_TIMEOUT)
            # OPEN/CLOSE reply with a result byte; the 0xD1 status reply is
            # the payload itself (captured by _note), not a result.
            if cmd in (CMD_OPEN, CMD_CLOSE, CMD_VOLUME) and done[3] != 0:
                raise SolityBleRejected(cmd, done[3])

            # Briefly drain to capture a pushed 0xD1 status.
            with contextlib.suppress(TimeoutError):
                while True:
                    raw = await asyncio.wait_for(
                        self._queue.get(), STATUS_DRAIN_TIMEOUT
                    )
                    frame = _decode(raw, iv)
                    if len(frame) >= 3 and frame[0] == STX and frame[2] != ACK_ERROR:
                        self._note(frame)

            _LOGGER.debug(
                "Solity BLE 0x%02X OK (%s, %s session)",
                cmd,
                self.mac,
                "warm" if warm else "cold",
            )
            return self._status
        except TimeoutError as err:
            raise SolityBleError("timed out waiting for lock response") from err
        except SolityBleError:
            raise
        except Exception as err:  # noqa: BLE001
            raise SolityBleError(f"BLE error: {err}") from err

    # ---- extras on an open session ----------------------------------------

    async def _send(self, cmd: int, extra: bytes = b"") -> None:
        client, iv = self._client, self._iv
        assert client is not None and iv is not None
        data = _time_key() + self.app_key + extra
        await client.write_gatt_char(
            WRITE_UUID, _encrypt(_build(cmd, data), iv), response=True
        )

    async def _read_function_safely(self) -> None:
        """Read the settings frame (0x5A -> 0xDA) on the current session."""
        if not self._is_warm() or time.monotonic() < self._function_skip_until:
            return
        try:
            await self._send(CMD_FUNCTION_REQ)
            await self._await(ACK_FUNCTION, self._iv, LOG_RECV_TIMEOUT)
        except TimeoutError:
            self._function_skip_until = time.monotonic() + EXTRA_BACKOFF_SECONDS
            _LOGGER.warning("Solity BLE: no reply to settings read (0x5A), pausing it")
        except Exception as err:  # noqa: BLE001
            _LOGGER.debug("Solity BLE settings read failed: %s", err)

    async def _drain_log_safely(self) -> None:
        """Take every queued access-log entry (0x5D -> 0xDD, page by page)."""
        if (
            not self.read_log
            or not self._is_warm()
            or time.monotonic() < self._log_skip_until
        ):
            return
        total = 0
        last_raw: bytes | None = None
        try:
            for _ in range(LOG_MAX_PAGES):
                await self._send(CMD_LOG_REQ)
                frame = await self._await(ACK_LOG, self._iv, LOG_RECV_TIMEOUT)
                _LOGGER.debug("Solity BLE 0xDD log frame: %s", frame.hex())
                payload = frame[3 : 3 + (frame[1] - 1)]
                if payload == last_raw:
                    break  # lock repeated the page: not a draining queue
                last_raw = payload
                page = _parse_log(payload)
                total += len(page.entries)
                self._emit(page.entries)
                if page.remaining <= 0 or not page.entries:
                    break
        except TimeoutError:
            if total == 0:
                self._log_skip_until = time.monotonic() + EXTRA_BACKOFF_SECONDS
                _LOGGER.warning("Solity BLE: no reply to log read (0x5D), pausing it")
        except Exception as err:  # noqa: BLE001
            _LOGGER.debug("Solity BLE log read stopped: %s", err)
        if total:
            _LOGGER.debug("Solity BLE read %d access-log entries", total)


def _decode(raw: bytes, iv: bytes) -> bytes:
    """A notification as a frame: plaintext if it already is one, else decrypt."""
    if _valid_plain(raw):
        return raw
    return _decrypt(raw, iv)
