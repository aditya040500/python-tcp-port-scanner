import errno
import socket
import unittest
from unittest.mock import patch

import port_scanner


class ParsePortsTests(unittest.TestCase):
    def test_parses_ports_and_ranges_without_duplicates(self):
        self.assertEqual(
            port_scanner.parse_ports("22,80,8000-8002,80"),
            [22, 80, 8000, 8001, 8002],
        )

    def test_rejects_invalid_ports_and_ranges(self):
        invalid_values = ["", "80,,443", "abc", "80-", "20-10", "0", "65536"]
        for value in invalid_values:
            with self.subTest(value=value):
                with self.assertRaises(port_scanner.argparse.ArgumentTypeError):
                    port_scanner.parse_ports(value)


class PositiveTimeoutTests(unittest.TestCase):
    def test_accepts_positive_finite_timeout(self):
        self.assertEqual(port_scanner.positive_timeout("0.5"), 0.5)

    def test_rejects_invalid_timeout_values(self):
        invalid_values = ["abc", "0", "-1", "nan", "inf"]
        for value in invalid_values:
            with self.subTest(value=value):
                with self.assertRaises(port_scanner.argparse.ArgumentTypeError):
                    port_scanner.positive_timeout(value)


class ScanPortTests(unittest.TestCase):
    def scan_with_mocked_socket(self, connect_result, socket_error=0, ready=False):
        fake_connection = FakeSocket(connect_result, socket_error)
        address_info = [
            (
                socket.AF_INET,
                socket.SOCK_STREAM,
                socket.IPPROTO_TCP,
                "",
                ("127.0.0.1", 8080),
            )
        ]
        select_result = ([], [fake_connection], []) if ready else ([], [], [])

        with (
            patch.object(port_scanner.socket, "getaddrinfo", return_value=address_info),
            patch.object(port_scanner.socket, "socket", return_value=fake_connection),
            patch.object(port_scanner.select, "select", return_value=select_result) as wait,
        ):
            result = port_scanner.scan_port("127.0.0.1", 8080, 1.0)

        return result, wait.call_count

    def test_immediate_connection_success_is_open(self):
        result, select_calls = self.scan_with_mocked_socket(0)

        self.assertEqual(result, "OPEN")
        self.assertEqual(select_calls, 0)

    def test_immediate_connection_refusal_is_closed(self):
        result, select_calls = self.scan_with_mocked_socket(10061)

        self.assertEqual(result, "CLOSED")
        self.assertEqual(select_calls, 0)

    def test_windows_pending_connection_refusal_is_closed(self):
        result, select_calls = self.scan_with_mocked_socket(
            10035, socket_error=10061, ready=True
        )

        self.assertEqual(result, "CLOSED")
        self.assertEqual(select_calls, 1)

    def test_pending_connection_timeout_is_inconclusive(self):
        result, select_calls = self.scan_with_mocked_socket(
            errno.EWOULDBLOCK, socket_error=0, ready=False
        )

        self.assertEqual(result, "INCONCLUSIVE")
        self.assertEqual(select_calls, 1)


class FakeSocket:
    def __init__(self, connect_result, socket_error):
        self.connect_result = connect_result
        self.socket_error = socket_error

    def __enter__(self):
        return self

    def __exit__(self, exception_type, exception, traceback):
        return False

    def setblocking(self, blocking):
        self.blocking = blocking

    def connect_ex(self, address):
        return self.connect_result

    def getsockopt(self, level, option):
        return self.socket_error


if __name__ == "__main__":
    unittest.main()
