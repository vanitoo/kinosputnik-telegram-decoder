"""Local, read-only KINOSPUTNIK dashboard. Standard library; Skyfield optional."""
import argparse
import json
import math
import sqlite3
from contextlib import closing
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit, parse_qs

ROOT = Path(__file__).resolve().parent
UTC = timezone.utc
EPOCH = datetime(2000, 1, 1, 12, tzinfo=UTC)


def inspect_raw(raw_hex):
    raw = bytes.fromhex(raw_hex)
    p = raw[16:]
    blocks, unknown = [], []
    i = 0
    while i + 4 <= len(p):
        lead, node, sub, tag = p[i:i+4]
        start = i
        continuation = lead == 16 and sub == 1 and 0x19 <= tag <= 0x1d
        if lead == 0 and sub == 1 and tag == 0x1e and i+6 <= len(p):
            declared = int.from_bytes(p[i+4:i+6], "big")
            if declared not in (48, 109):
                break
            i += 6
            first = 0x10
            need = declared
        elif continuation:
            declared = 109
            first = tag
            need = 109-(tag-0x10)*8
        else:
            break
        result = bytearray()
        ids = []
        while len(result) < need:
            n = min(8, need-len(result))
            expected = bytes((16,node,1,first+len(result)//8))
            if p[i:i+4] != expected or i+4+n > len(p):
                break
            ids.append(expected.hex().upper())
            result.extend(p[i+4:i+4+n])
            i += 4+n
        closed = (len(result)==need and p[i:i+4]==bytes((0,node,1,0x1f))
                  and i+6 <= len(p))
        end_hex = p[i+4:i+6].hex().upper() if closed else None
        if closed:
            i += 6
        blocks.append(dict(offset=start, node=f"{node:02X}", declared=declared,
                           fragment_bytes=len(result), continuation=continuation,
                           closed=closed, trailer_hex=end_hex, ids=ids,
                           hex=result.hex().upper()))
        if not result:
            break
    if i < len(p):
        candidates = []
        for at in range(i,len(p)-3):
            a,b,c,d=p[at:at+4]
            if c==1 and ((a==0 and d in (0x1e,0x1f)) or
                         (a==16 and 0x10<=d<=0x1d)):
                candidates.append(dict(offset=at, id=p[at:at+4].hex().upper()))
        unknown.append(dict(offset=i, hex=p[i:].hex().upper(), candidate_ids=candidates[:60]))
    return dict(raw_bytes=len(raw), header_hex=raw[:16].hex().upper(),
                blocks=blocks, unknown=unknown,
                integrity="not_verified")


def extended_fields(raw_hex, received):
    """Empirical offsets, not the manufacturer's extended field map."""
    b = bytes.fromhex(raw_hex)
    if len(b)<21 or b[2:6]!=bytes.fromhex("08090065"):
        return None
    day=int.from_bytes(b[8:10],"big")
    ms=int.from_bytes(b[10:14],"big")
    us=int.from_bytes(b[14:16],"big")
    if ms>=86400000 or us>=1000 or not received:
        return None
    dt=EPOCH+timedelta(days=day,milliseconds=ms,microseconds=us)
    delta=(datetime.fromisoformat(received)-dt).total_seconds()
    if abs(delta)>300:
        return None
    uptime=int.from_bytes(b[17:21],"big")
    return dict(timestamp_utc=dt.isoformat(), rx_delta_s=round(delta,6),
                status_hex=f"{b[16]:02X}", uptime_candidate_s=uptime,
                boot_candidate_utc=(dt-timedelta(seconds=uptime)).isoformat(),
                confidence="experimental")


def load_data(path, limit=5000):
    """One consistent SQLite read snapshot. Never mutate the collector DB."""
    with closing(sqlite3.connect(Path(path).resolve().as_uri()+"?mode=ro",
                                 uri=True, timeout=5)) as db:
        db.row_factory=sqlite3.Row
        db.execute("BEGIN")
        counts={t:db.execute("SELECT count(*) FROM "+t).fetchone()[0]
                for t in ("packets","can_frames","telemetry","extended_reassembled")}
        rows=db.execute("""SELECT p.id,p.message_id,p.source,p.satellite,p.station,
             p.received_utc,p.latitude_deg,p.longitude_deg,p.altitude_km,
             p.elevation_deg,p.azimuth_deg,p.distance_km,p.raw_hex,p.details_json,
             t.board_temp_c,t.mcu_temp_c,t.voltage_mv,t.current_ma,t.power_mw,
             t.error_counter,t.uptime_s,t.app,t.mode,t.satellite_utc,
             t.temp0_invalid,t.temp1_invalid,t.voltage_invalid,t.current_invalid,
             t.power_invalid,t.other_json,e.full_hex
             FROM packets p LEFT JOIN telemetry t ON p.id=t.packet_id
             LEFT JOIN extended_reassembled e ON p.id=e.start_packet_id
             ORDER BY p.received_utc DESC,p.id DESC LIMIT ?""",(limit,)).fetchall()
    packets=[]
    for row in reversed(rows):
        r=dict(row)
        detail=json.loads(r.pop("details_json"))
        other=json.loads(r.pop("other_json") or "{}")
        full=r.pop("full_hex")
        try:
            report=inspect_raw(r["raw_hex"])
            fragment=next((b for b in report["blocks"] if b["declared"]==109 and not b["continuation"]),None)
            ext=extended_fields(full or (fragment["hex"] if fragment else ""),r["received_utc"])
        except (ValueError, TypeError, OverflowError) as exc:
            report=dict(raw_bytes=len(r["raw_hex"])//2,blocks=[],unknown=[{"error":str(exc)}])
            ext=None
        r.update(analysis=report, extended=ext, assembled=bool(full), full_hex=full,
                 issues=detail.get("issues",[]), short_fields=other)
        # Invalid source measurements must not become valid-looking chart data.
        for field,flag in (("board_temp_c","temp0_invalid"),("mcu_temp_c","temp1_invalid"),
                           ("voltage_mv","voltage_invalid"),("current_ma","current_invalid"),
                           ("power_mw","power_invalid")):
            if r[flag]:
                r[field]=None
        r["kind"]=("unknown" if report["unknown"] or r["issues"] else
                   "short" if r["satellite_utc"] else
                   "extended" if report["blocks"] else "unknown")
        packets.append(r)
    return dict(counts=counts,packets=packets,limit=limit,
                generated_utc=datetime.now(UTC).isoformat())


def forecast(path, latitude=None, longitude=None, now=None):
    """Predict using a manually verified local TLE; no hidden network lookup."""
    path=Path(path)
    if not path.is_file():
        return {"status":"unavailable","message":"Нет TLE: сохраните проверенные элементы в data/kinosputnik.tle"}
    try:
        from skyfield.api import EarthSatellite, load, wgs84
    except ImportError:
        return {"status":"unavailable","message":"Установите skyfield: python -m pip install skyfield"}
    lines=[s.strip() for s in path.read_text(encoding="utf-8-sig").splitlines() if s.strip()]
    pair=next(((a,b) for a,b in zip(lines,lines[1:]) if a.startswith("1 ") and b.startswith("2 ")),None)
    if pair is None or pair[0][2:7]!=pair[1][2:7]:
        raise ValueError("Неверный TLE: нужны две строки одного объекта")
    ts=load.timescale(builtin=True)
    sat=EarthSatellite(*pair,"KINOSPUTNIK (TLE)",ts)
    now=now or datetime.now(UTC)
    epoch=sat.epoch.utc_datetime()
    age=(now-epoch).total_seconds()/86400
    if abs(age)>14:
        return dict(status="unavailable",message="TLE старше 14 суток или датирован будущим: обновите элементы",tle_epoch=epoch.isoformat(),age_days=age)
    moments=[now+timedelta(seconds=i*30) for i in range(361)]
    points=[]
    for dt in moments:
        geo=sat.at(ts.from_datetime(dt))
        sp=wgs84.subpoint(geo)
        vals=[float(sp.latitude.degrees),float(sp.longitude.degrees),float(sp.elevation.km)]
        if not all(math.isfinite(x) for x in vals):
            raise ValueError("SGP4 не смог рассчитать положение")
        points.append(dict(utc=dt.isoformat(),lat=vals[0],lon=vals[1],alt=vals[2]))
    passes=[]
    if latitude is not None and longitude is not None:
        observer=wgs84.latlon(latitude,longitude)
        times,events=sat.find_events(observer,ts.from_datetime(now),
                       ts.from_datetime(now+timedelta(hours=24)),altitude_degrees=10)
        for t,event in zip(times,events):
            alt,az,_=(sat-observer).at(t).altaz()
            passes.append(dict(utc=t.utc_datetime().isoformat(),event=int(event),
                               elevation_deg=float(alt.degrees),azimuth_deg=float(az.degrees)))
    return dict(status="ok",tle_epoch=epoch.isoformat(),age_days=age,
                catalog_number=int(sat.model.satnum),points=points,passes=passes,
                message="SGP4: расчёт, не телеметрия. Идентичность TLE проверяет оператор.")


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db",default=str(ROOT/"data"/"satellite.db"))
    parser.add_argument("--tle",default=str(ROOT/"data"/"kinosputnik.tle"))
    parser.add_argument("--port",type=int,default=8080)
    parser.add_argument("--limit",type=int,default=5000)
    parser.add_argument("--export",type=Path,help="Автономный HTML-снимок с RAW")
    a=parser.parse_args()
    if not 1<=a.limit<=20000:
        parser.error("--limit должен быть от 1 до 20000")
    page=(ROOT/"dashboard.html").read_text(encoding="utf-8")
    if a.export:
        payload=json.dumps(load_data(a.db,a.limit),ensure_ascii=False).replace("<",r"\u003c")
        a.export.write_text(page.replace("/* SNAPSHOT */ null",payload),encoding="utf-8")
        print(a.export)
        return
    load_data(a.db,1)
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            url=urlsplit(self.path)
            try:
                if url.path=="/":
                    body=page.encode("utf-8")
                    mime="text/html; charset=utf-8"
                elif url.path in ("/api/data","/api/orbit"):
                    if url.path=="/api/data":
                        result=load_data(a.db,a.limit)
                    else:
                        q=parse_qs(url.query)
                        lat=float(q["lat"][0]) if "lat" in q else None
                        lon=float(q["lon"][0]) if "lon" in q else None
                        if (lat is None)!=(lon is None) or (lat is not None and not (-90<=lat<=90 and -180<=lon<=180)):
                            raise ValueError("Некорректные координаты наблюдателя")
                        result=forecast(a.tle,lat,lon)
                    body=json.dumps(result,ensure_ascii=False,allow_nan=False).encode("utf-8")
                    mime="application/json; charset=utf-8"
                else:
                    self.send_error(404)
                    return
                self.send_response(200)
                self.send_header("Content-Type",mime)
                self.send_header("Cache-Control","no-store")
                self.send_header("X-Content-Type-Options","nosniff")
                self.end_headers()
                self.wfile.write(body)
            except (sqlite3.Error,ValueError,OSError,ImportError) as exc:
                self.send_error(500,str(exc))
    server=ThreadingHTTPServer(("127.0.0.1",a.port),Handler)
    print(f"KINOSPUTNIK Orbit Monitor: http://127.0.0.1:{a.port}",flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__=="__main__":
    main()
