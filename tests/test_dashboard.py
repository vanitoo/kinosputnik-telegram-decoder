import tempfile
import unittest
from datetime import timedelta
from pathlib import Path
from dashboard import inspect_raw, extended_fields, EPOCH, forecast, load_data
from storage import connect


class DashboardTests(unittest.TestCase):
    def test_short_and_unknown_tail(self):
        body = bytes.fromhex("0032011e0030")
        for tag in range(0x10,0x16):
            body += bytes((0x10,0x32,1,tag))+bytes(8)
        body += bytes.fromhex("0032011f1234aabbccdd")
        r=inspect_raw((bytes(16)+body).hex())
        self.assertEqual(r["blocks"][0]["fragment_bytes"],48)
        self.assertTrue(r["blocks"][0]["closed"])
        self.assertEqual(r["unknown"][0]["hex"],"AABBCCDD")

    def test_continuation(self):
        body=b"".join(bytes((16,50,1,i))+bytes(5 if i==0x1d else 8) for i in range(0x19,0x1e))
        body+=bytes.fromhex("0032011f1234")
        r=inspect_raw((bytes(16)+body).hex())
        self.assertTrue(r["blocks"][0]["continuation"])
        self.assertEqual(r["blocks"][0]["fragment_bytes"],37)

    def test_extended_timestamp(self):
        b=bytearray(21)
        b[2:6]=bytes.fromhex("08090065")
        b[8:10]=(10).to_bytes(2,"big")
        b[10:14]=(2000).to_bytes(4,"big")
        b[17:21]=(123).to_bytes(4,"big")
        dt=EPOCH+timedelta(days=10,seconds=2)
        r=extended_fields(b.hex(),dt.isoformat())
        self.assertEqual(r["uptime_candidate_s"],123)
        self.assertIsNone(extended_fields(b.hex(),(dt+timedelta(hours=1)).isoformat()))

    def test_empty_database(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp)/"data.db"
            connect(str(p)).close()
            d=load_data(p)
            self.assertEqual(d["counts"]["packets"],0)
            self.assertEqual(d["packets"],[])

    def test_missing_tle(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(forecast(Path(tmp)/"absent.tle")["status"],"unavailable")


if __name__=="__main__":
    unittest.main()
