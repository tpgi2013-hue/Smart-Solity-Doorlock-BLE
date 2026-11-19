"""Constants for the Solity BLE (direct) integration."""

DOMAIN = "solity_ble"

CONF_NAME = "name"
CONF_MAC = "mac"
CONF_APP_KEY = "app_key"
CONF_STATUS_MINUTES = "status_minutes"

# How often to read lock status over BLE (battery, deadbolt, counts).
# 0 disables periodic polling (status then updates only on open/close).
DEFAULT_STATUS_MINUTES = 30
MIN_STATUS_MINUTES = 0
MAX_STATUS_MINUTES = 1440

# How long to show 'unlocked' after a BLE open before assuming the deadbolt
# auto-relocked, when no status frame confirms the real state. Matches the
# open command's auto-relock window (second = 7) plus a small margin.
OPTIMISTIC_UNLOCK_SECONDS = 9

MANUFACTURER = "SOLITY"
MODEL = "WELKOM (BLE)"

# Safety cap for a prewarm hold: the session is dropped after this long even
# if nobody switches the prewarm off (e.g. radar stuck on).
PREWARM_MAX_SECONDS = 20

# While a status read shows the deadbolt retracted (door just used / left
# open), re-read this often until it reports locked, at most this many times.
UNLOCKED_RECHECK_SECONDS = 15
UNLOCKED_RECHECK_MAX = 8

# ---- access log ----------------------------------------------------------

# Read (and take over) the lock's queued access log in every BLE session.
CONF_READ_LOG = "read_log"
DEFAULT_READ_LOG = True
# Slot names, one per line: "지문 3 = 재현", "카드 1 = 엄마", "비밀번호 2 = 손님".
CONF_SLOT_NAMES = "slot_names"

# A queued log entry for the same open/close as a live event pushed this long
# ago (or less) is the same event: don't report it twice.
LIVE_DEDUP_SECONDS = 600

# How an open/close was made (DoorLock.Event.Data in the Solity app).
MEDIA_NAMES: dict[int, str] = {
    1: "비밀번호",
    2: "마스터 비밀번호",
    3: "게스트 비밀번호",
    4: "마스터 카드",
    5: "카드",
    6: "리모컨",
    7: "원격",
    8: "지문",
    9: "스마트터치",
    10: "방문자 비밀번호",
    11: "스마트오픈",
    12: "이중인증(카드)",
    13: "이중인증(지문)",
    32: "실내",
}

# Remote (app / HA) open: media code of the lock's '원격' log entries.
REMOTE_MEDIA = 7
# An HA open is matched to the lock's next '원격' entry read within this long.
REMOTE_LABEL_SECONDS = 180
# Automation / script runs remembered to name who sent an open.
OPENER_CONTEXTS_KEPT = 30

# Plain password: shown without its slot number unless that slot has a name.
PASSWORD_MEDIA = 1

# Methods whose log entries name a credential slot.
SLOT_MEDIA = frozenset({1, 2, 3, 4, 5, 6, 8, 10, 12, 13})

# Words accepted in CONF_SLOT_NAMES -> media codes they cover.
SLOT_NAME_ALIASES: dict[str, tuple[int, ...]] = {
    "비밀번호": (1,),
    "비번": (1,),
    "마스터비밀번호": (2,),
    "마스터비번": (2,),
    "카드": (5, 12),
    "마스터카드": (4,),
    "리모컨": (6,),
    "지문": (8, 13),
    "방문자비밀번호": (10,),
    "방문자비번": (10,),
}

EVENT_TYPE_OPEN = "open"
EVENT_TYPE_CLOSE = "close"
EVENT_TYPE_OTHER = "other"

# ---- settings (0x5A) -----------------------------------------------------

# Re-read the settings frame at most this often during regular polls.
FUNCTION_REFRESH_HOURS = 6
