"""KINOSPUTNIK decoder: local demo, text import, Telegram history and live feed."""
import argparse
import asyncio
import csv
import json
import logging
import os
from pathlib import Path
import re
import sqlite3

from decoder import message_blocks, parse_message, public_row
from storage import connect, store

ROOT = Path(__file__).resolve().parent


def show(packet, message_id):
    s = packet.short
    head = f"[{packet.received_utc or 'без времени'}] {packet.station} #{message_id}"
    if s:
        validity = " ⚠ НЕДОСТОВЕРНЫЕ ФЛАГИ" if any(s[k] for k in
            ("temperature0_invalid", "temperature1_invalid", "power_invalid", "voltage_invalid", "current_invalid")) else ""
        print(f"{head} | {s['board_temp_c']}°C / {s['mcu_temp_c']}°C | "
              f"{s['voltage_mv']/1000:.3f} В | {s['current_ma']} мА | "
              f"{s['power_mw']/1000:.3f} Вт | ошибок {s['error_counter']}"
              f" | App{s['running_app']}{validity}")
    else:
        frag = packet.extended
        detail = f"extended {frag['fragment_bytes']} байт" if frag else "неизвестный тип"
        print(f"{head} | {detail} | CAN: {len(packet.frames)}")
    if packet.issues:
        print("  Ошибки разбора:", "; ".join(packet.issues))


def import_text(path, db, source="local-import"):
    data = Path(path).read_text(encoding="utf-8-sig")
    added = 0
    for i, body in enumerate(message_blocks(data), start=1):
        try:
            packet = parse_message(body)
            if packet and packet.satellite.casefold() == "kinosputnik":
                if store(db, source, i, packet):
                    added += 1
                    show(packet, i)
        except Exception as exc:
            print(f"[Сообщение {i}] Пропущено: {exc}")
    print(f"Новых пакетов: {added}")


def export_csv(db, out_path):
    old_factory = db.row_factory
    db.row_factory = sqlite3.Row
    rows = db.execute("""SELECT p.message_id,p.received_utc,p.station,p.latitude_deg,p.longitude_deg,
           p.altitude_km,p.distance_km,t.satellite_utc,t.board_temp_c,t.mcu_temp_c,
           t.voltage_mv,t.current_ma,t.power_mw,t.uptime_s,t.mode,t.error_counter,t.app
           FROM telemetry t JOIN packets p ON p.id=t.packet_id ORDER BY p.received_utc,p.id""").fetchall()
    db.row_factory = old_factory
    out = Path(out_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    headers = ["message_id", "received_utc", "station", "latitude_deg", "longitude_deg",
               "altitude_km", "distance_km", "satellite_utc", "board_temp_c", "mcu_temp_c",
               "voltage_mv", "current_ma", "power_mw", "uptime_s", "mode", "error_counter", "app"]
    with out.open("w", encoding="utf-8-sig", newline="") as fh:
        writer = csv.writer(fh, delimiter=";")
        writer.writerow(headers)
        writer.writerows(tuple(row) for row in rows)
    print(f"CSV: {out} ({len(rows)} строк)")


def topic_of(message):
    r = getattr(message, "reply_to", None)
    if not r:
        return None
    return getattr(r, "reply_to_top_id", None) or getattr(r, "reply_to_msg_id", None)


def is_in_topic(message, topic_id):
    if topic_id is None:
        return True
    if message.id == topic_id:
        return True
    r = getattr(message, "reply_to", None)
    if not r:
        return False
    return getattr(r, "reply_to_top_id", None) == topic_id or (
        getattr(r, "reply_to_top_id", None) is None and
        getattr(r, "reply_to_msg_id", None) == topic_id
    )


async def watch_telegram(args, db):
    from dotenv import load_dotenv
    from telethon import TelegramClient, events

    load_dotenv(ROOT / ".env")
    api_id = os.environ.get("TG_API_ID")
    api_hash = os.environ.get("TG_API_HASH")
    if not api_id or not api_hash:
        raise SystemExit("Укажите TG_API_ID и TG_API_HASH в .env (получить на my.telegram.org).")
    session = str(ROOT / "telegram_session")
    client = TelegramClient(session, int(api_id), api_hash)
    await client.start()  # Telegram phone/code/2FA login on first run.
    link = args.link
    link_match = re.search(r"(?:https?://)?t\.me/([\w]+)/([0-9]+)", link)
    if not link_match:
        raise SystemExit("Ожидается ссылка вида https://t.me/SatNetworkDB/492030")
    username, example_id = link_match.group(1), int(link_match.group(2))
    chat = await client.get_entity(username)
    forum = bool(getattr(chat, "forum", False))
    example = await client.get_messages(chat, ids=example_id)
    if args.topic == "auto":
        topic = topic_of(example) if example is not None and forum else None
        if forum and topic is None:
            raise SystemExit("Не удалось распознать тему у сообщения. Задайте --topic ID или --topic all")
    elif args.topic == "all":
        topic = None
    else:
        topic = int(args.topic)
    print(f"Подключено: @{username}; forum={forum}; topic={topic if topic else 'весь чат'}; "
          f"спутник=KINOSPUTNIK")

    def consume(message):
        if not message or not is_in_topic(message, topic):
            return
        if "KINOSPUTNIK" not in (message.raw_text or "").upper():
            return
        try:
            packet = parse_message(message.raw_text or "")
            if packet and packet.satellite.upper() == "KINOSPUTNIK" and store(db, username, message.id, packet):
                show(packet, message.id)
        except Exception as exc:
            logging.warning("Ошибка в сообщении %s: %s", message.id, exc)

    @client.on(events.NewMessage(chats=chat))
    async def on_message(event):
        consume(event.message)

    # Handler registered before history scan, preventing dropped live arrivals.
    # Duplicate IDs from the overlap are harmless: SQLite de-duplicates them.
    if args.history:
        existing = []
        async for message in client.iter_messages(chat, limit=args.history):
            existing.append(message)
        for message in reversed(existing):
            consume(message)
        print(f"История обработана: просмотрено {len(existing)} сообщений")

    if args.once:
        await client.disconnect()
        return
    print("Отслеживание новых сообщений запущено. Выход: Ctrl+C")
    try:
        await client.run_until_disconnected()
    finally:
        await client.disconnect()


def main():
    parser = argparse.ArgumentParser(description="KINOSPUTNIK: Telegram → AX.25/CAN → SQLite")
    parser.add_argument("--db", default=str(ROOT / "data" / "satellite.db"))
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("demo", help="Расшифровать тестовые сообщения из samples/")
    src = sub.add_parser("import-file", help="Импорт текста, скопированного из Telegram")
    src.add_argument("path")
    watcher = sub.add_parser("watch", help="Telegram: история + новые сообщения")
    watcher.add_argument("--link", default="https://t.me/SatNetworkDB/492030")
    watcher.add_argument("--topic", default="auto", help="auto, all, или числовой ID темы")
    watcher.add_argument("--history", type=int, default=500, help="Сколько последних сообщений просмотреть")
    watcher.add_argument("--once", action="store_true", help="Только история, без мониторинга")
    export = sub.add_parser("export-csv", help="Сохранить телеметрию в CSV")
    export.add_argument("path", nargs="?", default=str(ROOT / "data" / "telemetry.csv"))
    args = parser.parse_args()
    db = connect(args.db)
    if args.command == "demo":
        import_text(ROOT / "samples" / "messages.txt", db, source="sample")
    elif args.command == "import-file":
        import_text(args.path, db)
    elif args.command == "watch":
        try:
            asyncio.run(watch_telegram(args, db))
        except KeyboardInterrupt:
            print("Остановлено")
    elif args.command == "export-csv":
        export_csv(db, args.path)
    db.close()


if __name__ == "__main__":
    main()
