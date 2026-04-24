import socket
import unittest
from unittest.mock import patch

import app


class FakeHTTPServer:
    created = []
    served = []
    fail_ipv6_bind = False

    address_family = socket.AF_INET
    daemon_threads = False

    def __init__(self, server_address, handler_class):
        self.server_address = server_address
        self.handler_class = handler_class
        self.config = None
        self.address_family_at_init = self.address_family
        self.closed = False
        self.socket = FakeServerSocket()
        self.server_bind()
        if self.fail_ipv6_bind and self.address_family_at_init == socket.AF_INET6:
            raise OSError("ipv6 unavailable")
        FakeHTTPServer.created.append(self)

    def server_bind(self):
        pass

    def serve_forever(self):
        FakeHTTPServer.served.append(self)

    def server_close(self):
        self.closed = True


class FakeServerSocket:
    def __init__(self):
        self.options = []

    def setsockopt(self, *args):
        self.options.append(args)


class FakeUDPSocket:
    def setsockopt(self, *args):
        pass

    def bind(self, address):
        self.address = address

    def close(self):
        pass


class FakeThread:
    def __init__(self, target, args=(), daemon=False):
        self.target = target
        self.args = args
        self.daemon = daemon

    def start(self):
        if getattr(self.target, "__name__", "") == "serve_forever":
            self.target(*self.args)


class FakeExecutor:
    def __init__(self, max_workers):
        self.max_workers = max_workers

    def shutdown(self, wait=False):
        self.wait = wait


class FakeConfigManager:
    def __init__(self, path):
        self.path = path

    def get_snapshot(self):
        return None, {
            "dns_port": 5353,
            "listen_host": "127.0.0.1",
            "web_host": "0.0.0.0",
            "web_port": 8080,
        }

    def get_availability_probe_interval(self):
        return 3600


def stop_server_loop(_seconds):
    raise KeyboardInterrupt


class WebServerBootstrapTests(unittest.TestCase):
    def setUp(self):
        FakeHTTPServer.created = []
        FakeHTTPServer.served = []
        FakeHTTPServer.fail_ipv6_bind = False

    @patch("app.time.sleep", stop_server_loop)
    @patch("app.ThreadPoolExecutor", FakeExecutor)
    @patch("app.threading.Thread", FakeThread)
    @patch("app.ConfigManager", FakeConfigManager)
    @patch("app.ThreadingHTTPServer", FakeHTTPServer)
    @patch("app.socket.socket", return_value=FakeUDPSocket())
    def test_web_server_binds_ipv4_and_ipv6_when_host_is_unspecified_ipv4(self, _socket_factory):
        app.run_servers()

        families = [server.address_family_at_init for server in FakeHTTPServer.created]
        addresses = [server.server_address[0] for server in FakeHTTPServer.created]

        self.assertEqual(families, [socket.AF_INET, socket.AF_INET6])
        self.assertEqual(addresses, ["0.0.0.0", "::"])
        self.assertEqual(FakeHTTPServer.served, FakeHTTPServer.created)
        self.assertTrue(all(server.closed for server in FakeHTTPServer.created))
        self.assertIn(
            (socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1),
            FakeHTTPServer.created[1].socket.options,
        )

    @patch("app.time.sleep", stop_server_loop)
    @patch("app.ThreadPoolExecutor", FakeExecutor)
    @patch("app.threading.Thread", FakeThread)
    @patch("app.ConfigManager", FakeConfigManager)
    @patch("app.ThreadingHTTPServer", FakeHTTPServer)
    @patch("app.socket.socket", return_value=FakeUDPSocket())
    def test_web_server_keeps_ipv4_running_when_ipv6_bind_fails(self, _socket_factory):
        FakeHTTPServer.fail_ipv6_bind = True

        app.run_servers()

        self.assertEqual(len(FakeHTTPServer.created), 1)
        self.assertEqual(FakeHTTPServer.created[0].address_family_at_init, socket.AF_INET)
        self.assertEqual(FakeHTTPServer.served, FakeHTTPServer.created)
        self.assertTrue(FakeHTTPServer.created[0].closed)


if __name__ == "__main__":
    unittest.main()
