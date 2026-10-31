import contextlib
import errno
import io
import socket
import sys
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
        invalid_values = [
            "",
            "80,,443",
            "abc",
            "80-",
            "20-10",
            "0",
            "65536",
            "²",
            "9" * 5000,
        ]
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
    def scan_with_mocked_socket(
        self, connect_result, socket_error=0, ready=False, include_diagnostic=False
    ):
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
            scanner = (
                port_scanner._scan_port_with_diagnostic
                if include_diagnostic
                else port_scanner.scan_port
            )
            result = scanner("127.0.0.1", 8080, 1.0)

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
            errno.EWOULDBLOCK,
            socket_error=0,
            ready=False,
            include_diagnostic=True,
        )

        self.assertEqual(result, ("INCONCLUSIVE", "connection timed out"))
        self.assertEqual(select_calls, 1)

    def test_socket_error_is_inconclusive_with_diagnostic(self):
        fake_connection = FakeSocket(10051, 0)
        address_info = [
            (
                socket.AF_INET,
                socket.SOCK_STREAM,
                socket.IPPROTO_TCP,
                "",
                ("127.0.0.1", 8080),
            )
        ]

        with (
            patch.object(
                port_scanner.socket, "getaddrinfo", return_value=address_info
            ),
            patch.object(
                port_scanner.socket, "socket", return_value=fake_connection
            ),
        ):
            result = port_scanner._scan_port_with_diagnostic(
                "127.0.0.1", 8080, 1.0
            )

        self.assertEqual(result, ("INCONCLUSIVE", "network is unreachable"))

    def test_os_socket_exception_is_inconclusive_with_diagnostic(self):
        address_info = [
            (
                socket.AF_INET,
                socket.SOCK_STREAM,
                socket.IPPROTO_TCP,
                "",
                ("127.0.0.1", 8080),
            )
        ]

        with (
            patch.object(
                port_scanner.socket, "getaddrinfo", return_value=address_info
            ),
            patch.object(
                port_scanner.socket,
                "socket",
                side_effect=OSError("network is unreachable"),
            ),
        ):
            result = port_scanner._scan_port_with_diagnostic(
                "127.0.0.1", 8080, 1.0
            )

        self.assertEqual(
            result,
            ("INCONCLUSIVE", "socket error: network is unreachable"),
        )

    def test_reuses_pre_resolved_addresses_and_applies_scanned_port(self):
        fake_connection = FakeSocket(0, 0)
        resolved_addresses = [
            (
                socket.AF_INET,
                socket.SOCK_STREAM,
                socket.IPPROTO_TCP,
                "",
                ("192.0.2.10", 0),
            )
        ]

        with (
            patch.object(port_scanner.socket, "getaddrinfo") as resolve,
            patch.object(
                port_scanner.socket, "socket", return_value=fake_connection
            ),
        ):
            result = port_scanner.scan_port(
                "example.test", 8080, 1.0, resolved_addresses
            )

        self.assertEqual(result, "OPEN")
        resolve.assert_not_called()
        self.assertEqual(fake_connection.address, ("192.0.2.10", 8080))


class MainTests(unittest.TestCase):
    def test_malformed_port_argument_exits_with_helpful_error(self):
        output = io.StringIO()
        with (
            patch.object(sys, "argv", ["port_scanner.py", "--ports", "²"]),
            contextlib.redirect_stderr(output),
        ):
            with self.assertRaises(SystemExit) as error:
                port_scanner.main()

        self.assertEqual(error.exception.code, 2)
        self.assertIn("Port numbers must contain ASCII digits only", output.getvalue())

    def test_hostname_resolution_error_is_reported_to_user(self):
        output = io.StringIO()
        with (
            patch.object(
                sys,
                "argv",
                ["port_scanner.py", "bad.invalid", "--ports", "80"],
            ),
            patch.object(
                port_scanner.socket,
                "getaddrinfo",
                side_effect=socket.gaierror("name not known"),
            ),
            contextlib.redirect_stderr(output),
        ):
            with self.assertRaises(SystemExit) as error:
                port_scanner.main()

        self.assertEqual(error.exception.code, 2)
        self.assertIn(
            "Could not resolve target 'bad.invalid'", output.getvalue()
        )

    def test_resolves_target_once_and_reuses_results_for_each_port(self):
        resolved_addresses = [
            (
                socket.AF_INET,
                socket.SOCK_STREAM,
                socket.IPPROTO_TCP,
                "",
                ("127.0.0.1", 0),
            )
        ]
        output = io.StringIO()
        with (
            patch.object(
                sys,
                "argv",
                ["port_scanner.py", "example.test", "--ports", "80,443"],
            ),
            patch.object(
                port_scanner.socket,
                "getaddrinfo",
                return_value=resolved_addresses,
            ) as resolve,
            patch.object(
                port_scanner,
                "_scan_port_with_diagnostic",
                return_value=("CLOSED", None),
            ) as scan,
            contextlib.redirect_stdout(output),
        ):
            port_scanner.main()

        resolve.assert_called_once_with(
            "example.test", 0, type=socket.SOCK_STREAM
        )
        self.assertEqual(scan.call_count, 2)
        for call in scan.call_args_list:
            self.assertIs(call.args[3], resolved_addresses)

    def test_prints_diagnostic_for_inconclusive_result(self):
        resolved_addresses = [
            (
                socket.AF_INET,
                socket.SOCK_STREAM,
                socket.IPPROTO_TCP,
                "",
                ("127.0.0.1", 0),
            )
        ]
        output = io.StringIO()
        with (
            patch.object(sys, "argv", ["port_scanner.py", "--ports", "80"]),
            patch.object(
                port_scanner.socket,
                "getaddrinfo",
                return_value=resolved_addresses,
            ),
            patch.object(
                port_scanner,
                "_scan_port_with_diagnostic",
                return_value=("INCONCLUSIVE", "connection timed out"),
            ),
            contextlib.redirect_stdout(output),
        ):
            port_scanner.main()

        self.assertIn("80       INCONCLUSIVE", output.getvalue())
        self.assertIn("Reason: connection timed out", output.getvalue())


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
        self.address = address
        return self.connect_result

    def getsockopt(self, level, option):
        return self.socket_error


if __name__ == "__main__":
    unittest.main()
