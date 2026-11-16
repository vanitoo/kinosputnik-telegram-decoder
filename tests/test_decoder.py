import sys
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from decoder import parse_message, message_blocks  # noqa: E402
from storage import connect, store  # noqa: E402

SAMPLE = (ROOT / "samples/messages.txt").read_text(encoding="utf-8")


class DecodeTests(unittest.TestCase):
    def test_short_telemetry(self):
        p = parse_message(message_blocks(SAMPLE)[0])
        self.assertEqual(len(bytes.fromhex(p.raw_hex)), 214)
        self.assertEqual(len(p.frames), 18)
        s = p.short
        self.assertEqual(s["board_temp_c"], 22)
        self.assertEqual(s["mcu_temp_c"], 41)
        self.assertEqual(s["voltage_mv"], 27259)
        self.assertEqual(s["current_ma"], 117)
        self.assertEqual(s["power_mw"], 3200)
        self.assertEqual(s["uptime_s"], 61478)
        self.assertEqual(s["error_counter"], 33)
        self.assertEqual(s["running_app"], 1)
        self.assertTrue(s["satellite_utc"].startswith("2026-11-15T20:57:31.031299"))
        self.assertEqual(p.issues, [])
        self.assertEqual(p.extended["fragment_bytes"], 72)

    def test_continuation(self):
        p = parse_message(message_blocks(SAMPLE)[1])
        self.assertIsNone(p.short)
        self.assertEqual(p.issues, [])
        self.assertEqual(p.extended["fragment_bytes"], 37)

    def test_next_short(self):
        p = parse_message(message_blocks(SAMPLE)[2])
        s = p.short
        self.assertEqual(s["board_temp_c"], 22)
        self.assertEqual(s["mcu_temp_c"], 42)
        self.assertEqual(s["current_ma"], 130)
        self.assertEqual(s["voltage_mv"], 27253)
        self.assertEqual(s["power_mw"], 3540)

    def test_storage_idempotency_and_reassembly(self):
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            db = connect(str(Path(td) / "test.db"))
            blocks = message_blocks(SAMPLE)
            for i, block in enumerate(blocks, start=1):
                self.assertTrue(store(db, "sample", i, parse_message(block)))
            self.assertFalse(store(db, "sample", 1, parse_message(blocks[0])))
            self.assertEqual(db.execute("SELECT COUNT(*) FROM packets").fetchone()[0], 3)
            self.assertEqual(db.execute("SELECT COUNT(*) FROM telemetry").fetchone()[0], 2)
            x = db.execute("SELECT bytes,LENGTH(full_hex) FROM extended_reassembled").fetchone()
            self.assertEqual(x, (109, 218))
            db.close()

if __name__ == "__main__":
    unittest.main()
