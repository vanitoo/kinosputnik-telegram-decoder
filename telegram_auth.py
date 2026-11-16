"""User Telegram sign-in for Telethon 1.x: safe proxy failover, QR and 2FA.

The Telegram login itself is never retried when another proxy is selected.
"""
from __future__ import annotations

import asyncio
import getpass
import logging
from urllib.parse import unquote, urlsplit

log = logging.getLogger(__name__)


def telethon_proxy(proxy_url: str) -> dict:
    """Convert TG_PROXY URL into the documented Telethon/python-socks dict.

    Unlike an HTTP proxy healthcheck, this only configures a *real* MTProto
    connection. Percent-escaped passwords and IPv6 hosts are handled correctly.
    """
    parsed = urlsplit(proxy_url)
    scheme = parsed.scheme.lower()
    if scheme not in ("socks5", "socks4", "http"):
        raise ValueError(
            f"Прокси {scheme or '(без схемы)'} не поддерживается Telethon 1.x. "
            "Используй socks5://, socks4:// или http:// (HTTP CONNECT)."
        )
    if not parsed.hostname or not parsed.port:
        raise ValueError("Для TG_PROXY нужны адрес и порт прокси")
    proxy = {
        "proxy_type": scheme,
        "addr": parsed.hostname,
        "port": parsed.port,
        "rdns": True,
    }
    if parsed.username is not None:
        proxy["username"] = unquote(parsed.username)
        proxy["password"] = unquote(parsed.password or "")
    return proxy


async def connect_client(session: str, api_id: int, api_hash: str, manager):
    """Connect and check MTProto on proxy candidates before attempting sign-in."""
    from telethon import TelegramClient, errors
    from proxy_manager import mask_proxy_url

    # Network-only retries: no send_code_request and no QR until a stable
    # MTProto connection is confirmed, to avoid Telegram login rate limits.
    if manager.has_proxies:
        initial = manager.get_proxy()
        candidates = [initial] + [p for p in manager.proxies if p != initial]
    else:
        candidates = [None]
    failures = []
    for proxy_url in candidates:
        try:
            proxy = telethon_proxy(proxy_url) if proxy_url else None
        except ValueError as exc:
            failures.append(str(exc))
            continue
        label = mask_proxy_url(proxy_url) if proxy_url else "напрямую"
        client = TelegramClient(
            session, api_id, api_hash, proxy=proxy,
            connection_retries=1, request_retries=2, timeout=12,
        )
        try:
            await asyncio.wait_for(client.connect(), timeout=30)
            if not client.is_connected():
                raise ConnectionError("MTProto не подключился")
            # This invokes Telegram directly, not https://api.telegram.org.
            await asyncio.wait_for(client.is_user_authorized(), timeout=20)
            print(f"MTProto соединение установлено: {label}")
            return client
        except errors.RPCError:
            # Bad API ID/hash, authorization errors etc. are not proxy failures.
            await client.disconnect()
            raise
        except Exception as exc:
            failures.append(f"{label}: {type(exc).__name__}: {exc}")
            log.warning("MTProto через %s не работает: %s", label, type(exc).__name__)
            await client.disconnect()
    raise ConnectionError("Не удалось подключиться к Telegram (MTProto). " + " | ".join(failures))


async def _finish_2fa(client) -> None:
    from telethon import errors

    print("Telegram запросил пароль двухэтапной аутентификации (2FA).")
    for attempt in range(3):
        password = getpass.getpass("Пароль 2FA (не отображается): ")
        try:
            await client.sign_in(password=password)
            return
        except errors.PasswordHashInvalidError:
            print(f"Неверный пароль 2FA ({attempt + 1}/3).")
    raise RuntimeError("Не удалось войти: три неверных пароля 2FA.")


def _show_qr(url: str) -> None:
    import qrcode

    code = qrcode.QRCode(border=2)
    code.add_data(url)
    code.make(fit=True)
    # ASCII output works in PowerShell, Windows Terminal, and SSH.
    matrix = code.get_matrix()
    print()
    for row in matrix:
        print("".join("██" if dark else "  " for dark in row))
    print()
    print("Telegram на телефоне → Настройки → Устройства → Подключить устройство")
    print("Отсканируй QR с экрана. Не пересылай его другим людям.")


async def _qr_login(client, *, timeout: int = 90) -> None:
    from telethon import errors

    qr = await client.qr_login()
    for attempt in range(3):
        _show_qr(qr.url)
        try:
            await qr.wait(timeout=timeout)
            return
        except errors.SessionPasswordNeededError:
            await _finish_2fa(client)
            return
        except (asyncio.TimeoutError, TimeoutError):
            if attempt == 2:
                raise RuntimeError("QR истёк. Запусти команду login ещё раз.")
            print("Срок действия QR закончился, создаю новый...")
            await qr.recreate()


async def _code_login(client, phone: str | None = None) -> None:
    from telethon import errors

    phone = (phone or input("Номер Telegram (+7...): ")).strip()
    if not phone.startswith("+"):
        raise ValueError("Введи номер в международном формате, например +79991234567")
    sent = await client.send_code_request(phone)
    delivery = type(getattr(sent, "type", None)).__name__
    print(f"Telegram принял запрос. Тип доставки: {delivery}.")
    print("Проверь сервисный чат Telegram на уже авторизованных устройствах. "
          "SMS может не отправляться. Не запрашивай код многократно.")
    for attempt in range(3):
        code = input("Код из Telegram (Enter для отмены): ").strip().replace(" ", "")
        if not code:
            raise RuntimeError("Авторизация отменена: код не получен.")
        try:
            await client.sign_in(phone=phone, code=code,
                                 phone_code_hash=sent.phone_code_hash)
            return
        except errors.SessionPasswordNeededError:
            await _finish_2fa(client)
            return
        except errors.PhoneCodeInvalidError:
            print(f"Неверный код ({attempt + 1}/3).")
        except errors.PhoneCodeExpiredError as exc:
            raise RuntimeError("Код истёк. Запусти login заново или выбери --auth qr.") from exc
    raise RuntimeError("Слишком много неверных кодов. Не повторяй запрос сразу.")


async def ensure_authorized(client, *, method: str = "qr", phone: str | None = None) -> None:
    """Login once on an established connection; reuse an existing session."""
    if await client.is_user_authorized():
        print("Telegram-сессия уже авторизована. Повторный код не нужен.")
        return
    if method == "qr":
        await _qr_login(client)
    elif method == "code":
        await _code_login(client, phone)
    else:
        raise ValueError("Способ авторизации: qr или code")
    if not await client.is_user_authorized():
        raise RuntimeError("Telegram не подтвердил авторизацию.")
    print("Telegram: авторизация успешна. Сессия сохранена локально.")
