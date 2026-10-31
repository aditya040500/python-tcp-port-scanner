# Python TCP Port Scanner

A small command-line tool that checks selected TCP ports on a hostname or IP address using a TCP connect scan. The default target is `127.0.0.1` (your own computer).

## Features

- Scan one TCP port, a comma-separated list, or one or more port ranges.
- Set a connection timeout in seconds.
- Show each port's result and the total number of open ports.
- Validate port numbers and timeout values, and report hostname-resolution errors clearly.
- Resolve a target hostname once per scan and reuse those addresses for each selected port.
- Uses Python's built-in libraries; no extra packages are required.

## Technologies

- Python 3
- `socket`, `select`, `argparse`, `errno`, `math`, and `time` from the Python standard library

## Prerequisites

- Windows 10 or later
- Python 3 installed and available with the `py` launcher
- Visual Studio Code with the project folder open

## Installation

1. Install Python 3 for Windows and make sure the Python launcher (`py`) is available.
2. Download or clone this project, then open its folder in Visual Studio Code.
3. No additional packages need to be installed; the scanner uses Python's standard library.

Check that Python is available in PowerShell:

```powershell
py --version
```

## Run in VS Code on Windows

1. Open the project folder in VS Code.
2. Open **Terminal > New Terminal**. The examples below use PowerShell.
3. Run the scanner with a required `--ports` argument. If you omit the target, it scans `127.0.0.1`.

Scan one port on your own computer:

```powershell
py .\port_scanner.py --ports 80
```

Scan several individual ports:

```powershell
py .\port_scanner.py --ports 22,80,443
```

Scan a port range on localhost:

```powershell
py .\port_scanner.py --ports 8000-8010
```

Choose a target and timeout explicitly:

```powershell
py .\port_scanner.py 127.0.0.1 --ports 22,80,8000-8002 --timeout 0.5
```

Port lists can combine individual ports and ranges, separated by commas. Valid ports are from 1 through 65535. The timeout must be a finite number greater than zero.
If not specified, the timeout is 1 second per selected port.

## Understanding the results

- **OPEN** — The TCP connection succeeded.
- **CLOSED** — The connection was refused at every resolved address for that port. A refusal means the TCP connection was actively rejected; it does not identify why it was rejected.
- **INCONCLUSIVE** — The scanner could not determine the port state because of a timeout or another network error. **INCONCLUSIVE does not mean CLOSED.**

For an `INCONCLUSIVE` result, the scanner prints a short `Reason` line, such as `connection timed out` or `socket error: network is unreachable`. This message describes why the scan could not classify the port; it does not change the result into `CLOSED`.

A timeout alone does not prove that a port is filtered or closed. Network conditions, firewall behavior, or an unreachable target can prevent a reliable result.

## Hypothetical sample output

This example is hypothetical. The results shown are illustrative and are not predictions of what a scan will find on your computer.

```text
====================================
        PYTHON PORT SCANNER
====================================
Target: 127.0.0.1
Scan type: TCP Connect Scan
Ports scanned: 5

PORT     STATUS
------------------------------------
22       CLOSED
80       CLOSED
8000     OPEN
8080     OPEN
9000     CLOSED
------------------------------------
Open ports found: 2
Scan completed.
```

## How it works

The program resolves the target once, then loops through the selected ports using those same resolved addresses. For each port, it attempts a TCP connection with the configured timeout. It uses the connection result to report `OPEN`, `CLOSED`, or `INCONCLUSIVE`, then prints a summary. If the hostname cannot be resolved, the program stops with a helpful error instead of starting the scan.

## Authorized use and safety

Use this scanner only on your own computer or on systems you are explicitly authorized to test. Keep scans limited to the target and ports you are permitted to assess. A port being open does not indicate that its service is vulnerable or secure.

## Limitations

- This is a basic TCP connect scanner. It does not scan UDP ports, identify services, detect vulnerabilities, or determine whether a system is secure.
- Results depend on the target's network behavior. Timeouts and other errors are reported as `INCONCLUSIVE`, not as proof that a port is closed or filtered.
- **Current Windows testing limitation:** After stopping a temporary HTTP server on localhost port 8000, the scan still returned `INCONCLUSIVE`. The Windows diagnostic reported `connect_ex` result `10035`, which means the nonblocking connection was still in progress. In this execution environment, `select` did not report the connection as ready before the timeout and `SO_ERROR` was `0`, so a live refused-connection (`CLOSED`) result could not be verified. The scanner leaves that outcome `INCONCLUSIVE` rather than guessing that it is closed.
- The scanner checks ports sequentially, so scanning a large range can take time.

## Tests

Run the standard-library test suite from the project folder:

```powershell
py -m unittest discover -s tests -v
```

The tests use mocked socket outcomes, so they do not scan external systems.

## Project structure

```text
port scanner 2/
├── port_scanner.py
├── README.md
└── tests/
    └── test_port_scanner.py
```
