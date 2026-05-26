import socket
import ssl
import time
import argparse
import json
import csv
from concurrent.futures import ThreadPoolExecutor
from threading import Lock
from colorama import Fore, Style, init

####
init(autoreset=True)

open_ports = []
lock = Lock()
####


parser = argparse.ArgumentParser(description="Advanced Python Port Scanner")
parser.add_argument("IP", help="Target IP address or hostname")
parser.add_argument("-p", "--ports", help="Port range", default="1-1024")
parser.add_argument("-t", "--threads", type=int, default=100, help="Number of threads")
parser.add_argument("--timeout", type=float, default=0.3, help="Socket timeout")
parser.add_argument("--json", action="store_true", help="Save results to JSON")
parser.add_argument("--csv", action="store_true", help="Save results to CSV")

args = parser.parse_args()

if args.threads > 500:
    print(Fore.RED + "Too many threads (max recommended: 500)")
    exit()

# TARGET

try:
    TARGET = socket.gethostbyname(args.IP)
except:
    print(Fore.RED + "Invalid hostname or TARGET")
    exit()

start_port, end_port = map(int, args.ports.split("-"))

# SERVICE DETECTION
COMMON_SERVICES = {
    20: "FTP Data",
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    67: "DHCP",
    68: "DHCP",
    69: "TFTP",
    80: "HTTP",
    110: "POP3",
    111: "RPCBind",
    119: "NNTP",
    123: "NTP",
    135: "MSRPC",
    139: "NetBIOS",
    143: "IMAP",
    161: "SNMP",
    389: "LDAP",
    443: "HTTPS",
    445: "SMB",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP Proxy",
}

# BANNER GRABBING

def grab_banner(sock, port):
    try:
        if port in [80,8080,8000]:
            sock.send(b"HEAD / HTTP/1.1\r\nHost: target\r\n\r\n")
        elif port == 443:
            try:
                context = ssl.create_default_context()

                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as ssock:
                    ssock.settimeout(args.timeout)
                    ssock.connect((TARGET, port))

                with context.wrap_socket(ssock, server_hostname=TARGET) as tls:
                    tls.send(b"HEAD / HTTP/1.1\r\nHost: target\r\n\r\n")
                    return tls.recv(1024).decode(errors="ignore").strip()

            except:
                return "No banner"
        
        banner = sock.recv(1024).decode(errors="ignore").strip()
        return banner if banner else "No banner"
    
    except:
        return "No banner"
    
# PORT SCAN

def check_port(port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:


        sock.settimeout(args.timeout)

        try:
            result = sock.connect_ex((TARGET,port))

            if result == 0:
                service = COMMON_SERVICES.get(port, "Unknown")

                banner = grab_banner(sock,port)
                print(Fore.GREEN + f"[OPEN] Port {port:<5} Service: {service:<12} Banner: {banner}")

                with lock:
                    open_ports.append({"port": port,
                                       "service": service,
                                       "banner": banner})
                    
        except socket.error:
            pass

# START SCAN
            
print(Fore.CYAN + f"\n[*] Scanning {TARGET}")
print(Fore.CYAN +f"[*] Ports: {start_port}-{end_port}")
print(Fore.CYAN +f"[*] Threads: {args.threads}\n")

start_time = time.time()

PORTS = range(start_port, end_port + 1)
    

with ThreadPoolExecutor(max_workers=args.threads) as executor:
    executor.map(check_port, PORTS)

# RESULTS

end_time = time.time()
print("\n" + "=" * 50)

print(Fore.YELLOW +f"[+] Scan completed in {end_time - start_time:.2f}s")
print(Fore.YELLOW +f"[+] Open ports found: {len(open_ports)}")    

# SAVE JSON

if args.json:
    with open("scan_results.json", "w") as f:
        json.dump(open_ports, f, indent=4)

    print(Fore.BLUE +"[+] Results saved to scan_results.json")

# SAVE CSV

if args.csv:
    with open("scan_results.csv", "w", newline="") as f:
         writer = csv.DictWriter(f,fieldnames=["port","service","banner"])
 
         writer.writeheader()
         writer.writerows(open_ports)

    print(Fore.BLUE +"[+] Results saved to scan_results.csv")
print("=" * 50)