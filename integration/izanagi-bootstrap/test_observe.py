import unittest

from observe import loopback


class ListenerBoundaryTests(unittest.TestCase):
    def test_loopback_ipv4_and_ipv6(self):
        for endpoint in ("127.0.0.1:18081", "[::1]:5901"):
            with self.subTest(endpoint=endpoint):
                self.assertTrue(loopback(endpoint))

    def test_wildcard_external_and_unparseable_are_not_loopback(self):
        for endpoint in ("0.0.0.0:22221", "[::]:22221", "*:5901",
                         "10.0.2.2:18081", "192.0.2.1:18081", "localhost:18081"):
            with self.subTest(endpoint=endpoint):
                self.assertFalse(loopback(endpoint))


if __name__ == "__main__":
    unittest.main()
