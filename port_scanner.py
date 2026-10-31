"""A simple TCP connect scanner for authorized, educational use."""

import argparse
import errno
import math
import select
import socket
import time


def _parse_port_number(port_text):
    """Parse an ASCII port number or raise a command-line input error."""
    if not port_text.isascii() or not port_text.isdecimal():
        raise argparse.ArgumentTypeError(
            "Port numbers must contain ASCII digits only."
        )

    try:
        return int(port_text)
    except ValueError as error:
        raise argparse.ArgumentTypeError(
            "Port number is too long or invalid."
        ) from error


def parse_ports(port_text):
    """Parse comma-separated ports and ranges into a unique list of ports."""
    ports = []
    seen_ports = set()

    for item in port_text.split(","):
        item = item.strip()
        if not item:
            raise argparse.ArgumentTypeError("Port list cannot contain an empty item.")

        if "-" in item:
            if item.count("-") != 1:
                raise argparse.ArgumentTypeError(f"Invalid port range: {item}")
            start_text, end_text = item.split("-")
            start_port = _parse_port_number(start_text)
            end_port = _parse_port_number(end_text)
            if start_port > end_port:
                raise argparse.ArgumentTypeError(
                    f"Range start must not exceed range end: {item}"
                )
            item_ports = range(start_port, end_port + 1)
        else:
            item_ports = [_parse_port_number(item)]

        for port in item_ports:
            if not 1 <= port <= 65535:
                raise argparse.ArgumentTypeError(
                    f"Port numbers must be between 1 and 65535: {port}"
                )
            if port not in seen_ports:
                ports.append(port)
                seen_ports.add(port)

    return ports


def positive_timeout(timeout_text):
    """Convert a timeout to a positive number of seconds."""
    try:
        timeout = float(timeout_text)
    except ValueError as error:
        raise argparse.ArgumentTypeError("Timeout must be a number.") from error

    if not math.isfinite(timeout) or timeout <= 0:
        raise argparse.ArgumentTypeError("Timeout must be a finite number greater than zero.")
    return timeout


def _is_connection_refused(error_code):
    """Return whether a platform socket error means the connection was refused."""
    return error_code in {errno.ECONNREFUSED, 10061}


def _socket_error_message(error_code):
    """Create a concise explanation for a socket error code."""
    if error_code is None:
        return "socket error (no system error code)"
    if error_code in {errno.ETIMEDOUT, 10060}:
        return "connection timed out"
    if error_code in {errno.ENETUNREACH, 10051}:
        return "network is unreachable"
    if error_code in {errno.EHOSTUNREACH, 10065}:
        return "host is unreachable"
    if error_code in {errno.ECONNRESET, 10054}:
        return "connection was reset"
    if error_code in {errno.EACCES, 10013}:
        return "permission denied"
    return f"socket error {error_code}"


def _exception_message(error):
    """Describe an operating-system socket exception for scan output."""
    error_code = getattr(error, "winerror", None) or error.errno
    if error_code in {errno.ETIMEDOUT, 10060} or isinstance(
        error, TimeoutError
    ):
        return "connection timed out"
    detail = str(error).strip()
    return f"socket error: {detail}" if detail else _socket_error_message(error_code)


def scan_port(target, port, timeout, resolved_addresses=None):
    """Return OPEN, CLOSED, or INCONCLUSIVE for one TCP port."""
    status, _ = _scan_port_with_diagnostic(
        target, port, timeout, resolved_addresses
    )
    return status


def _scan_port_with_diagnostic(target, port, timeout, resolved_addresses=None):
    """Return a status and optional explanation for one TCP port."""
    if resolved_addresses is None:
        try:
            addresses = socket.getaddrinfo(
                target, port, type=socket.SOCK_STREAM
            )
        except OSError as error:
            return "INCONCLUSIVE", f"name resolution failed: {error}"
    else:
        # Reuse the scan's DNS answers while applying the port being scanned.
        addresses = [
            (
                family,
                socket_type,
                protocol,
                canonical_name,
                (address[0], port, *address[2:]),
            )
            for family, socket_type, protocol, canonical_name, address
            in resolved_addresses
        ]

    deadline = time.monotonic() + timeout
    diagnostics = []

    for family, socket_type, protocol, _, address in addresses:
        remaining_time = deadline - time.monotonic()
        if remaining_time <= 0:
            diagnostics.append("connection timed out")
            return "INCONCLUSIVE", "; ".join(dict.fromkeys(diagnostics))

        try:
            with socket.socket(family, socket_type, protocol) as connection:
                connection.setblocking(False)
                result = connection.connect_ex(address)

                if result == 0:
                    return "OPEN", None
                if _is_connection_refused(result):
                    continue
                if result not in {
                    errno.EINPROGRESS,
                    errno.EWOULDBLOCK,
                    errno.EALREADY,
                    10035,  # WSAEWOULDBLOCK: connection attempt is pending on Windows.
                    10036,  # WSAEINPROGRESS: connection attempt is pending on Windows.
                    10037,  # WSAEALREADY: connection attempt is still in progress.
                }:
                    diagnostics.append(_socket_error_message(result))
                    continue

                _, writable, exceptional = select.select(
                    [], [connection], [connection], remaining_time
                )
                if not writable and not exceptional:
                    result = connection.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
                    if _is_connection_refused(result):
                        continue
                    if result == 0:
                        diagnostics.append("connection timed out")
                        continue
                    diagnostics.append(_socket_error_message(result))
                    continue

                result = connection.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
                if result == 0:
                    return "OPEN", None
                if _is_connection_refused(result):
                    continue
                diagnostics.append(_socket_error_message(result))
        except OSError as error:
            error_code = getattr(error, "winerror", None) or error.errno
            if _is_connection_refused(error_code):
                continue
            diagnostics.append(_exception_message(error))

    if diagnostics or not addresses:
        if not diagnostics:
            diagnostics.append("no usable network addresses were found")
        return "INCONCLUSIVE", "; ".join(dict.fromkeys(diagnostics))
    return "CLOSED", None


def main():
    parser = argparse.ArgumentParser(
        description="Scan selected TCP ports on a target you are authorized to test."
    )
    parser.add_argument(
        "target",
        nargs="?",
        default="127.0.0.1",
        help="hostname or IP address (default: 127.0.0.1)",
    )
    parser.add_argument(
        "-p",
        "--ports",
        required=True,
        type=parse_ports,
        help="port list, for example 80 or 22,80,8000-8002",
    )
    parser.add_argument(
        "-t",
        "--timeout",
        type=positive_timeout,
        default=1.0,
        help="connection timeout in seconds (default: 1.0)",
    )
    args = parser.parse_args()

    try:
        resolved_addresses = socket.getaddrinfo(
            args.target, 0, type=socket.SOCK_STREAM
        )
    except OSError as error:
        parser.error(f"Could not resolve target '{args.target}': {error}")

    results = []
    for port in args.ports:
        status, diagnostic = _scan_port_with_diagnostic(
            args.target, port, args.timeout, resolved_addresses
        )
        results.append((port, status, diagnostic))

    print("====================================")
    print("        PYTHON PORT SCANNER")
    print("====================================")
    print(f"Target: {args.target}")
    print("Scan type: TCP Connect Scan")
    print(f"Ports scanned: {len(results)}")
    print()
    print("PORT     STATUS")
    print("------------------------------------")
    for port, status, diagnostic in results:
        print(f"{port:<8} {status}")
        if diagnostic:
            print(f"         Reason: {diagnostic}")
    print("------------------------------------")
    open_count = sum(status == "OPEN" for _, status, _ in results)
    print(f"Open ports found: {open_count}")
    print("Scan completed.")


if __name__ == "__main__":
    main()
