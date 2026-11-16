"""KINOSPUTNIK UHF AX.25/CAN beacon parser.

Based on the user-supplied «Прием маяка УКВ.docx» (the short-beacon layout).
Assumptions (validated with example timestamps/power values):
  AX.25 header: 16 bytes (no FCS in posted telegram hex)
  CAN: 4-byte big-endian ID, 8-byte data for 0x10..0x1C, 5 for 0x1D,
       2-byte data for 0x1E and 0x1F markers
  Short telemetry: 8-byte RF header + 40-byte uhf_short_telemetry_s.
  Integers are big-endian, CDS day epoch = 2000-01-01 12:00:00 UTC.

Extended (109-byte) beacon mapping and checksums have NOT been documented;
this module only extracts/preserves them, it does not invent sensor labels.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
import re
from typing import Any

UTC = timezone.utc
CDS_EPOCH = datetime(2000, 1, 1, 12, tzinfo=UTC)
HEADER_LEN = 16
RAW_RE = re.compile(r"Полученные данные\s*\(RAW\)\s*:\s*\*?\s*([0-9a-fA-F\s]+)", re.I)
SAT_RE = re.compile(r"Спутник\s*\[([^\]]+)\]", re.I)
REC_RE = re.compile(r"Дата при[её]ма:\s*([0-9-]+\s+[0-9:]+)\s*UTC", re.I)
STATION_RE = re.compile(r"При[её]мная станция:\s*([\w-]+)", re.I)
FLOAT_FIELDS = {
    "azimuth_deg": r"Азимут спутника:\s*([\d,.]+)",
    "elevation_deg": r"Элевация спутника:\s*([\d,.]+)",
    "latitude_deg": r"Широта:\s*([\d,.-]+)",
    "longitude_deg": r"Долгота:\s*([\d,.-]+)",
    "altitude_km": r"Высота орбиты:\s*([\d,.]+)",
    "distance_km": r"Дистанция:\s*([\d,.]+)",
}


@dataclass
class CANFrame:
    can_id: str
    data_hex: str
    dlc: int

    @property
    def tag(self) -> int:
        return int(self.can_id[-2:], 16)

    @property
    def family(self) -> int:
        return int(self.can_id[2:4], 16)


@dataclass
class Packet:
    satellite: str
    received_utc: str
    station: str
    raw_hex: str
    azimuth_deg: float | None
    elevation_deg: float | None
    latitude_deg: float | None
    longitude_deg: float | None
    altitude_km: float | None
    distance_km: float | None
    frames: list[CANFrame]
    short: dict[str, Any] | None
    extended: dict[str, Any] | None
    issues: list[str]


def _extract(pattern: re.Pattern | str, text: str) -> str | None:
    match = re.search(pattern, text, re.I) if isinstance(pattern, str) else pattern.search(text)
    return match.group(1).strip() if match else None


def message_blocks(text: str) -> list[str]:
    """Split pasted Telegram export with multiple satellite message bodies."""
    starts = [m.start() for m in re.finditer(r"(?:\*\*)?🛰\s*Спутник\s*\[", text)]
    if not starts:
        return [text]
    return [text[a:(starts[i + 1] if i + 1 < len(starts) else len(text))]
            for i, a in enumerate(starts)]


def parse_message(text: str) -> Packet | None:
    satellite = _extract(SAT_RE, text)
    raw_match = RAW_RE.search(text)
    if not satellite or not raw_match:
        return None
    raw_hex = re.sub(r"\s", "", raw_match.group(1)).upper()
    if not raw_hex or len(raw_hex) % 2:
        raise ValueError("Нечётное число HEX-символов в RAW")
    raw = bytes.fromhex(raw_hex)
    if len(raw) < HEADER_LEN:
        raise ValueError("Пакет короче AX.25 заголовка (16 байт)")
    rx = _extract(REC_RE, text)
    received_utc = datetime.strptime(rx, "%Y-%m-%d %H:%M:%S").replace(tzinfo=UTC).isoformat() if rx else ""
    coords: dict[str, float | None] = {}
    for field, pattern in FLOAT_FIELDS.items():
        value = _extract(pattern, text)
        coords[field] = float(value.replace(",", ".")) if value is not None else None
    frames, issues = parse_can(raw[HEADER_LEN:])
    short = decode_short(frames)
    if short and received_utc:
        from datetime import datetime as dt
        delta = (dt.fromisoformat(received_utc) - dt.fromisoformat(short["satellite_utc"])).total_seconds()
        short["rx_satellite_delta_s"] = round(delta, 6)
    extended = extract_extended(frames)
    return Packet(
        satellite=satellite, received_utc=received_utc,
        station=_extract(STATION_RE, text) or "", raw_hex=raw_hex,
        frames=frames, short=short, extended=extended, issues=issues, **coords,
    )


def parse_can(payload: bytes) -> tuple[list[CANFrame], list[str]]:
    pos, frames, issues = 0, [], []
    while pos < len(payload):
        if len(payload) - pos < 4:
            issues.append(f"Остаток {len(payload) - pos} байт в позиции {pos}")
            break
        can_id = int.from_bytes(payload[pos:pos + 4], "big")
        # 0x00XX011E/1F are 2-byte markers; 0x10XX0110..1C are data.
        fam = (can_id >> 24) & 0xFF
        sub = (can_id >> 8) & 0xFF
        tag = can_id & 0xFF
        if sub == 0x01 and fam == 0x00 and tag in (0x1E, 0x1F):
            n = 2
        elif sub == 0x01 and fam == 0x10 and 0x10 <= tag <= 0x1C:
            n = 8
        elif sub == 0x01 and fam == 0x10 and tag == 0x1D:
            n = 5
        else:
            issues.append(f"Неизвестный ID 0x{can_id:08X} при смещении {pos}")
            break
        if len(payload) - pos < 4 + n:
            issues.append(f"Неполные данные CAN ID=0x{can_id:08X} при смещении {pos}")
            break
        frames.append(CANFrame(f"{can_id:08X}", payload[pos + 4:pos + 4 + n].hex().upper(), n))
        pos += 4 + n
    return frames, issues


def decode_short(frames: list[CANFrame]) -> dict[str, Any] | None:
    """Decode only a complete 48-byte short beacon, not a 109-byte extended one."""
    for i, f in enumerate(frames):
        if f.tag != 0x1E or f.dlc != 2 or f.data_hex != "0030":
            continue
        next_six = frames[i + 1:i + 7]
        if len(next_six) != 6 or any(
            x.tag != 0x10 + j or x.dlc != 8 or x.can_id[2:4] != f.can_id[2:4]
            for j, x in enumerate(next_six)
        ):
            continue
        content = b"".join(bytes.fromhex(x.data_hex) for x in next_six)
        if len(content) != 48:
            continue
        rf_prefix = content[:8]
        s = content[8:]
        # device_status: CDS=8, mode=1, err=1, bitfields=1, proto=1,
        # uptime=4, temperature=4, power=8, last_commands=4 = 32.
        # rf_status=8.
        day = int.from_bytes(s[0:2], "big")
        ms = int.from_bytes(s[2:6], "big")
        us = int.from_bytes(s[6:8], "big")
        sat_time = CDS_EPOCH + timedelta(days=day, milliseconds=ms, microseconds=us)
        uptime = int.from_bytes(s[12:16], "big")
        current = int.from_bytes(s[20:22], "big", signed=True)
        voltage = int.from_bytes(s[22:24], "big")
        power_tenth_mw = int.from_bytes(s[24:26], "big")
        return {
            "satellite_utc": sat_time.isoformat(),
            "cds_day": day,
            "mode": s[8],
            "error_counter": s[9],
            "boot_attempt_count": s[10] & 0x0F,
            "running_app": (s[10] >> 6) & 1,
            "protocol_version_hex": f"0x{s[11]:02X}",
            "uptime_s": uptime,
            "board_temp_c": int.from_bytes(s[16:17], "big", signed=True),
            "mcu_temp_c": int.from_bytes(s[17:18], "big", signed=True),
            "temperature_flags_hex": f"0x{s[18]:02X}",
            "temperature0_invalid": bool(s[18] & 1),
            "temperature1_invalid": bool(s[18] & 2),
            "current_ma": current,
            "voltage_mv": voltage,
            "power_mw": power_tenth_mw * 10,
            "power_flags_hex": f"0x{s[26]:02X}",
            "current_invalid": bool(s[26] & 4),
            "voltage_invalid": bool(s[26] & 2),
            "power_invalid": bool(s[26] & 1),
            "power_alert_flags_hex": f"0x{s[27]:02X}",
            "last_commands_hex": s[28:32].hex().upper(),
            "rf_status_hex": s[32:40].hex().upper(),
            "rf_prefix_hex": rf_prefix.hex().upper(),
            "can_family": f"0x{f.can_id[2:4]}",
        }
    return None


def extract_extended(frames: list[CANFrame]) -> dict[str, Any] | None:
    # 109-byte beacon is spread across two Telegram messages. Only preserve
    # fragment bytes and IDs until a reliable extended-beacon field map exists.
    started = any(x.tag == 0x1E and x.data_hex == "006D" for x in frames)
    candidates = []
    active = False
    for f in frames:
        if f.tag == 0x1E:
            active = f.data_hex == "006D"
        elif f.tag == 0x1F:
            active = False
        elif f.can_id.startswith("10") and (active or 0x19 <= f.tag <= 0x1D):
            candidates.append(f)
    if not candidates:
        return None
    return {
        "kind": "start" if started else "continuation",
        "declared_bytes": 109,
        "fragment_bytes": sum(f.dlc for f in candidates),
        "can_ids": [f.can_id for f in candidates],
        "hex": "".join(f.data_hex for f in candidates),
        "complete": sum(f.dlc for f in candidates) == 109,
    }


def public_row(packet: Packet) -> dict[str, Any]:
    base = {k: v for k, v in asdict(packet).items() if k not in ("frames", "short", "extended", "raw_hex")}
    base.update(packet.short or {})
    base["can_count"] = len(packet.frames)
    base["packet_bytes"] = len(packet.raw_hex) // 2
    base["extended_fragment_bytes"] = packet.extended["fragment_bytes"] if packet.extended else 0
    return base
