# Advanced Python Port Scanner

Advanced multithreaded TCP port scanner written in Python with support for service detection, banner grabbing, HTTPS scanning, and exporting results to JSON or CSV.

---

## Features

- Fast multithreaded TCP scanning
- Configurable port ranges
- Basic service detection
- Banner grabbing support
- HTTPS/TLS banner grabbing
- Colored terminal output
- JSON export
- CSV export
- Adjustable timeout and thread count
- Hostname resolution support

---

## Installation

Clone the repository:

```bash
git clone https://github.com/kennen900/Port-scanner-python.git
```

Install required dependencies:

```bash
pip install colorama
```

---

## Usage

Basic scan:

```bash
python scanner.py 192.168.1.1
```

Scan a specific port range:

```bash
python scanner.py 192.168.1.1 -p 1-65535
```

Change number of threads:

```bash
python scanner.py 192.168.1.1 -t 300
```

Change timeout:

```bash
python scanner.py 192.168.1.1 --timeout 1
```

Export results to JSON:

```bash
python scanner.py 192.168.1.1 --json
```

Export results to CSV:

```bash
python scanner.py 192.168.1.1 --csv
```

Full example:

```bash
python scanner.py scanme.nmap.org -p 1-1000 -t 200 --timeout 0.5 --json --csv
```

---

## Command Line Arguments

| Argument | Description |
|----------|-------------|
| `IP` | Target IP address or hostname |
| `-p`, `--ports` | Port range to scan |
| `-t`, `--threads` | Number of threads |
| `--timeout` | Socket timeout |
| `--json` | Save results to JSON |
| `--csv` | Save results to CSV |

---

## Example Output

```bash
[*] Scanning 192.168.1.1
[*] Ports: 1-1024
[*] Threads: 100

[OPEN] Port 22    Service: SSH         Banner: OpenSSH 8.2
[OPEN] Port 80    Service: HTTP        Banner: Apache/2.4.41
[OPEN] Port 443   Service: HTTPS       Banner: nginx

==================================================
[+] Scan completed in 2.34s
[+] Open ports found: 3
==================================================
```

---

## Project Structure

```bash
.
├── scanner.py
├── README.md
├── scan_results.json
├── requirements.txt
└── scan_results.csv
```

---

## Technologies Used

- Python 3
- socket
- ssl
- concurrent.futures
- argparse
- colorama

---

## Security Notice

This tool is intended for:

- Educational purposes
- Authorized security testing
- Network administration

Do not scan systems without permission.

Unauthorized port scanning may be illegal in your country.

---

## Author

Developed by kennen900