import sys
import types
import unittest
from unittest.mock import patch

from telegram_auth import telethon_proxy, connect_client, ensure_authorized, _code_login, _qr_login


class ProxyTests(unittest.TestCase):
    def test_special_characters_and_ipv6(self):
        p = telethon_proxy("socks5://my%40user:p%3A%40ss@[2001:db8::1]:1080")
        self.assertEqual((p["addr"], p["port"]), ("2001:db8::1", 1080))
        self.assertEqual((p["username"], p["password"]), ("my@user", "p:@ss"))

    def test_https_rejected_not_silently_downgraded(self):
        with self.assertRaises(ValueError):
            telethon_proxy("https://localhost:1080")

    def test_http_connect_proxy(self):
        self.assertEqual(telethon_proxy("http://localhost:3128")["port"], 3128)


class FakeClient:
    instances = []

    def __init__(self, session, api_id, api_hash, **kwargs):
        self.proxy = kwargs.get("proxy")
        self.connected = False
        self.authorized = False
        self.calls = []
        self.instances.append(self)

    async def connect(self):
        self.calls.append("connect")
        if self.proxy and self.proxy["addr"] == "bad":
            raise ConnectionError("bad proxy")
        self.connected = True

    def is_connected(self):
        return self.connected

    async def is_user_authorized(self):
        return self.authorized

    async def disconnect(self):
        self.connected = False
        self.calls.append("disconnect")


class AuthTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        FakeClient.instances.clear()
        self.fake_errors = types.SimpleNamespace(RPCError=type("RPCError", (Exception,), {}))

    async def test_proxy_failover_does_not_try_login(self):
        from proxy_manager import ProxyManager
        pm = ProxyManager(["socks5://bad:1080", "socks5://good:1080"], mode="failover")
        t = types.SimpleNamespace(TelegramClient=FakeClient, errors=self.fake_errors)
        with patch.dict(sys.modules, {"telethon": t}):
            client = await connect_client("some_session", 123, "hash", pm)
        self.assertEqual(client.proxy["addr"], "good")
        self.assertEqual(FakeClient.instances[0].calls, ["connect", "disconnect"])
        self.assertEqual(FakeClient.instances[1].calls, ["connect"])

    async def test_existing_session_skips_login(self):
        c = FakeClient("session", 123, "hash")
        c.authorized = True
        await ensure_authorized(c, method="qr")
        self.assertEqual(c.calls, [])

    async def test_phone_code_then_2fa(self):
        class PasswordRequired(Exception):
            pass
        class PasswordInvalid(Exception):
            pass
        class PhoneCodeInvalid(Exception):
            pass
        class PhoneCodeExpired(Exception):
            pass
        err = types.SimpleNamespace(SessionPasswordNeededError=PasswordRequired,
                                    PasswordHashInvalidError=PasswordInvalid,
                                    PhoneCodeInvalidError=PhoneCodeInvalid,
                                    PhoneCodeExpiredError=PhoneCodeExpired)

        class AuthClient(FakeClient):
            async def send_code_request(self, phone):
                self.calls.append("send_code")
                return types.SimpleNamespace(type="app", phone_code_hash="token")

            async def sign_in(self, **kwargs):
                if "password" in kwargs:
                    self.authorized = True
                    self.calls.append("password")
                    return
                self.assert_hash(kwargs)
                self.calls.append("sign_code")
                raise PasswordRequired()

            def assert_hash(self, kwargs):
                if kwargs["phone_code_hash"] != "token":
                    raise AssertionError("phone_code_hash lost")

        c = AuthClient("session", 123, "hash")
        with patch.dict(sys.modules, {"telethon": types.SimpleNamespace(errors=err)}), \
             patch("builtins.input", return_value="987654"), \
             patch("getpass.getpass", return_value="password"):
            await _code_login(c, phone="+79998887766")
        self.assertEqual(c.calls, ["send_code", "sign_code", "password"])
        self.assertTrue(c.authorized)

    async def test_qr_2fa(self):
        class PasswordRequired(Exception):
            pass
        class PasswordInvalid(Exception):
            pass
        calls = []

        class QR:
            url = "tg://login?token=test"

            async def wait(self, timeout):
                calls.append("wait")
                raise PasswordRequired()

        class QRClient(FakeClient):
            async def qr_login(self):
                calls.append("qr_login")
                return QR()

            async def sign_in(self, **kwargs):
                calls.append("2fa")
                self.authorized = True

        c = QRClient("session", 123, "hash")
        err = types.SimpleNamespace(SessionPasswordNeededError=PasswordRequired,
                                    PasswordHashInvalidError=PasswordInvalid)
        with patch.dict(sys.modules, {"telethon": types.SimpleNamespace(errors=err)}), \
             patch("telegram_auth._show_qr"), \
             patch("getpass.getpass", return_value="secret"):
            await _qr_login(c)
        self.assertEqual(calls, ["qr_login", "wait", "2fa"])
        self.assertTrue(c.authorized)


if __name__ == "__main__":
    unittest.main()
