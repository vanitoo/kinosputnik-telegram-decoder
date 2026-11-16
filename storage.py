"""SQLite store: Telegram messages, raw AX.25, decoded UHF and CAN frames."""
import json
import sqlite3
from pathlib import Path
from dataclasses import asdict

from decoder import Packet

SCHEMA = """
PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS packets (
  id INTEGER PRIMARY KEY,
  source TEXT NOT NULL,
  message_id INTEGER NOT NULL,
  satellite TEXT NOT NULL,
  station TEXT NOT NULL,
  received_utc TEXT,
  latitude_deg REAL,
  longitude_deg REAL,
  azimuth_deg REAL,
  elevation_deg REAL,
  altitude_km REAL,
  distance_km REAL,
  raw_hex TEXT NOT NULL,
  details_json TEXT NOT NULL,
  UNIQUE(source, message_id)
);
CREATE TABLE IF NOT EXISTS can_frames (
  packet_id INTEGER NOT NULL,
  frame_idx INTEGER NOT NULL,
  can_id TEXT NOT NULL,
  dlc INTEGER NOT NULL,
  data_hex TEXT NOT NULL,
  PRIMARY KEY(packet_id, frame_idx),
  FOREIGN KEY(packet_id) REFERENCES packets(id)
);
CREATE TABLE IF NOT EXISTS telemetry (
  packet_id INTEGER PRIMARY KEY,
  satellite_utc TEXT,
  board_temp_c INTEGER,
  mcu_temp_c INTEGER,
  voltage_mv INTEGER,
  current_ma INTEGER,
  power_mw INTEGER,
  uptime_s INTEGER,
  mode INTEGER,
  error_counter INTEGER,
  app INTEGER,
  temp0_invalid INTEGER,
  temp1_invalid INTEGER,
  power_invalid INTEGER,
  voltage_invalid INTEGER,
  current_invalid INTEGER,
  other_json TEXT NOT NULL,
  FOREIGN KEY(packet_id) REFERENCES packets(id)
);
CREATE TABLE IF NOT EXISTS extended_reassembled (
  start_packet_id INTEGER PRIMARY KEY,
  end_packet_id INTEGER NOT NULL,
  bytes INTEGER NOT NULL,
  full_hex TEXT NOT NULL,
  FOREIGN KEY(start_packet_id) REFERENCES packets(id),
  FOREIGN KEY(end_packet_id) REFERENCES packets(id)
);
"""


def connect(path: str) -> sqlite3.Connection:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(path)
    db.executescript(SCHEMA)
    return db


def store(db: sqlite3.Connection, source: str, message_id: int, p: Packet) -> bool:
    details = json.dumps({"short": p.short, "extended": p.extended, "issues": p.issues}, ensure_ascii=False)
    with db:
        cur = db.execute("""INSERT OR IGNORE INTO packets
          (source, message_id, satellite, station, received_utc, latitude_deg,
           longitude_deg, azimuth_deg, elevation_deg, altitude_km,
           distance_km, raw_hex, details_json)
          VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""", (
          source, message_id, p.satellite, p.station, p.received_utc,
          p.latitude_deg, p.longitude_deg, p.azimuth_deg, p.elevation_deg,
          p.altitude_km, p.distance_km, p.raw_hex, details))
        if cur.rowcount == 0:
            return False
        pid = cur.lastrowid
        db.executemany("""INSERT INTO can_frames(packet_id,frame_idx,can_id,dlc,data_hex)
          VALUES(?,?,?,?,?)""", [(pid, i, f.can_id, f.dlc, f.data_hex) for i, f in enumerate(p.frames)])
        if p.short:
            s = p.short
            db.execute("""INSERT INTO telemetry
              (packet_id,satellite_utc,board_temp_c,mcu_temp_c,voltage_mv,current_ma,power_mw,
               uptime_s,mode,error_counter,app,temp0_invalid,temp1_invalid,
               power_invalid,voltage_invalid,current_invalid,other_json)
              VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""", (
              pid, s["satellite_utc"], s["board_temp_c"], s["mcu_temp_c"],
              s["voltage_mv"], s["current_ma"], s["power_mw"], s["uptime_s"],
              s["mode"], s["error_counter"], s["running_app"],
              int(s["temperature0_invalid"]), int(s["temperature1_invalid"]),
              int(s["power_invalid"]), int(s["voltage_invalid"]),
              int(s["current_invalid"]), json.dumps(s, ensure_ascii=False)))
    attempt_reassembly(db)
    return True


def attempt_reassembly(db: sqlite3.Connection) -> None:
    """Match 72B start with 37B continuation if station and UTC differ <=2s.

    Saves only raw data. No guessed decoding of the extended fields.
    """
    starts = db.execute("""SELECT id, station, received_utc, details_json FROM packets
      WHERE id NOT IN (SELECT start_packet_id FROM extended_reassembled)
      ORDER BY id DESC LIMIT 250""").fetchall()
    continuations = db.execute("""SELECT id, station, received_utc, details_json FROM packets
      WHERE id NOT IN (SELECT end_packet_id FROM extended_reassembled)
      ORDER BY id DESC LIMIT 250""").fetchall()
    from datetime import datetime
    for start_id, station, received, detail_str in starts:
        ext = json.loads(detail_str).get("extended")
        if not ext or ext.get("kind") != "start" or ext["fragment_bytes"] != 72 or not received:
            continue
        for end_id, end_station, end_received, end_detail_str in continuations:
            if end_id == start_id or station != end_station or not end_received:
                continue
            sec = abs((datetime.fromisoformat(received) - datetime.fromisoformat(end_received)).total_seconds())
            tail = json.loads(end_detail_str).get("extended")
            if sec > 2 or not tail or tail.get("kind") != "continuation" or tail["fragment_bytes"] != 37:
                continue
            if ext["can_ids"][-1][-2:] != "18" or tail["can_ids"][0][-2:] != "19":
                continue
            with db:
                db.execute("""INSERT OR IGNORE INTO extended_reassembled
                   (start_packet_id,end_packet_id,bytes,full_hex)
                   VALUES(?,?,?,?)""", (start_id, end_id, 109, ext["hex"] + tail["hex"]))
            break
