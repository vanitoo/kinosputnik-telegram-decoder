import unittest

from proxy_manager import (
    ProxyManager,
    ProxyMode,
    mask_proxy_url,
    to_telethon_proxy,
)


class ProxyModeTests(unittest.TestCase):
    def test_normalize_aliases(self):
        self.assertEqual(ProxyMode.normalize("fallback"), ProxyMode.FAILOVER)
        self.assertEqual(ProxyMode.normalize(""), ProxyMode.OFF)
        self.assertEqual(ProxyMode.normalize("none"), ProxyMode.OFF)
        self.assertEqual(ProxyMode.normalize("STICKY"), ProxyMode.STICKY)

    def test_normalize_unknown(self):
        self.assertEqual(ProxyMode.normalize("bogus"), ProxyMode.FAILOVER)


class ParsingTests(unittest.TestCase):
    def test_from_env_string_separators(self):
        pm = ProxyManager.from_env_string(
            "http://a:1,socks5://b:2;http://c:3\nhttp://d:4")
        self.assertEqual(len(pm.proxies), 4)
        self.assertTrue(pm.has_proxies)

    def test_empty_disables(self):
        pm = ProxyManager.from_env_string("")
        self.assertFalse(pm.has_proxies)
        self.assertEqual(pm.mode, ProxyMode.OFF)
        self.assertIsNone(pm.get_proxy())

    def test_mask_proxy_url(self):
        self.assertEqual(
            mask_proxy_url("socks5://user:secretpass@host:1080"),
            "socks5://user:***@host:1080")
        self.assertEqual(mask_proxy_url("http://host:3128"), "http://host:3128")


class TelethonAdapterTests(unittest.TestCase):
    # Telethon-совместимые числовые константы: SOCKS4=1, SOCKS5=2, HTTP=3
    # (одинаковы в PySocks и python_socks).
    def test_socks5_with_auth(self):
        self.assertEqual(
            to_telethon_proxy("socks5://user:pass@1.2.3.4:1080"),
            (2, "1.2.3.4", 1080, True, "user", "pass"))

    def test_socks5_without_auth(self):
        self.assertEqual(
            to_telethon_proxy("socks5://1.2.3.4:1080"),
            (2, "1.2.3.4", 1080, True, None, ""))

    def test_http(self):
        self.assertEqual(
            to_telethon_proxy("http://proxy.local:3128"),
            (3, "proxy.local", 3128, True, None, ""))

    def test_http_with_auth(self):
        self.assertEqual(
            to_telethon_proxy("http://user123:secretpass@31.76.31.132:3128"),
            (3, "31.76.31.132", 3128, True, "user123", "secretpass"))

    def test_socks4(self):
        self.assertEqual(
            to_telethon_proxy("socks4://host:1080"),
            (1, "host", 1080, True, None, ""))

    def test_unsupported_scheme(self):
        with self.assertRaises(ValueError):
            to_telethon_proxy("mtproxy://secret@host:443")

    def test_missing_port(self):
        with self.assertRaises(ValueError):
            to_telethon_proxy("socks5://host")

    def test_telethon_kwargs(self):
        pm = ProxyManager.from_env_string("socks5://h:1080")
        kwargs = pm.telethon_kwargs()
        self.assertIn("proxy", kwargs)


class FailoverTests(unittest.TestCase):
    def setUp(self):
        self.pm = ProxyManager.from_env_string(
            "http://a:1,http://b:2,http://c:3", mode="failover")

    def test_primary_first(self):
        self.assertEqual(self.pm.get_proxy(), "http://a:1")

    def test_failover_switches_and_returns(self):
        self.pm.mark_proxy_failed("http://a:1")
        self.assertEqual(self.pm.get_proxy(), "http://b:2")
        self.pm.reset_proxy("http://a:1")
        self.assertEqual(self.pm.get_proxy(), "http://a:1")

    def test_all_failed_rotates(self):
        for url in list(self.pm.proxies):
            self.pm.mark_proxy_failed(url)
        self.assertIsNotNone(self.pm.get_proxy())  # новый круг проверки

    def test_next_proxy(self):
        self.assertEqual(self.pm.next_proxy(), "http://b:2")
        self.assertEqual(self.pm.next_proxy(), "http://c:3")
        self.assertEqual(self.pm.next_proxy(), "http://a:1")

    def test_rotate_mode_index_zero(self):
        pm = ProxyManager.from_env_string("http://a:1,http://b:2", mode="rotate")
        self.assertEqual(pm.get_proxy(), "http://a:1")
        self.assertEqual(pm.get_proxy(), "http://b:2")
        # Индекс 0 должен выбираться корректно (regression: `or active[0]`).
        self.assertEqual(pm.get_proxy(), "http://a:1")

    def test_sticky_keeps_current(self):
        pm = ProxyManager.from_env_string("http://a:1,http://b:2", mode="sticky")
        self.assertEqual(pm.get_proxy(), "http://a:1")
        self.assertEqual(pm.get_proxy(), "http://a:1")
        pm.mark_proxy_failed("http://a:1")
        self.assertEqual(pm.get_proxy(), "http://b:2")

    def test_status_shape(self):
        status = self.pm.get_status()
        self.assertEqual(status["mode"], "failover")
        self.assertEqual(status["total"], 3)
        self.assertTrue(status["proxies"][0]["primary"])


if __name__ == "__main__":
    unittest.main()
