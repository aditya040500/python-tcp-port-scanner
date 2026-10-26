"""A simple TCP connect scanner for authorized, educational use."""

import argparse
import errno
import math
import select
import socket
import time


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
            if not start_text.isdigit() or not end_text.isdigit():
                raise argparse.ArgumentTypeError(f"Invalid port range: {item}")
            start_port = int(start_text)
            end_port = int(end_text)
            if start_port > end_port:
                raise argparse.ArgumentTypeError(
                    f"Range start must not exceed range end: {item}"
                )
            item_ports = range(start_port, end_port + 1)
        else:
            if not item.isdigit():
                raise argparse.ArgumentTypeError(f"Invalid port: {item}")
            item_ports = [int(item)]

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


def scan_port(target, port, timeout, resolved_addresses=None):
    """Return OPEN, CLOSED, or INCONCLUSIVE for one TCP port."""
    if resolved_addresses is None:
        try:
            addresses = socket.getaddrinfo(
                target, port, type=socket.SOCK_STREAM
            )
        except OSError:
            return "INCONCLUSIVE"
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
    inconclusive_result = False

    for family, socket_type, protocol, _, address in addresses:
        remaining_time = deadline - time.monotonic()
        if remaining_time <= 0:
            return "INCONCLUSIVE"

        try:
            with socket.socket(family, socket_type, protocol) as connection:
                connection.setblocking(False)
                result = connection.connect_ex(address)

                if result == 0:
                    return "OPEN"
                if result == errno.ECONNREFUSED or result == 10061:
                    continue
                if result not in {
                    errno.EINPROGRESS,
                    errno.EWOULDBLOCK,
                    errno.EALREADY,
                    10035,  # WSAEWOULDBLOCK: connection attempt is pending on Windows.
                    10036,  # WSAEINPROGRESS: connection attempt is pending on Windows.
                    10037,  # WSAEALREADY: connection attempt is still in progress.
                }:
                    inconclusive_result = True
                    continue

                _, writable, exceptional = select.select(
                    [], [connection], [connection], remaining_time
                )
                if not writable and not exceptional:
                    result = connection.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
                    if result == errno.ECONNREFUSED or result == 10061:
                        continue
                    inconclusive_result = True
                    continue

                result = connection.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
                if result == 0:
                    return "OPEN"
                if result == errno.ECONNREFUSED or result == 10061:
                    continue
                inconclusive_result = True
        except OSError:
            inconclusive_result = True

    if inconclusive_result or not addresses:
        return "INCONCLUSIVE"
    return "CLOSED"


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
        status = scan_port(
            args.target, port, args.timeout, resolved_addresses
        )
        results.append((port, status))

    print("====================================")
    print("        PYTHON PORT SCANNER")
    print("====================================")
    print(f"Target: {args.target}")
    print("Scan type: TCP Connect Scan")
    print(f"Ports scanned: {len(results)}")
    print()
    print("PORT     STATUS")
    print("------------------------------------")
    for port, status in results:
        print(f"{port:<8} {status}")
    print("------------------------------------")
    open_count = sum(status == "OPEN" for _, status in results)
    print(f"Open ports found: {open_count}")
    print("Scan completed.")


if __name__ == "__main__":
    main()
