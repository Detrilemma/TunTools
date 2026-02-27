#! /usr/bin/python3

import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
import re
import os
import resource

def is_port_open(ip, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(2)
    try:
        s.connect((ip, port))
        return (ip, port, True)
    except:
        return (ip, port, False)
    finally:
        try:
            s.close()
        except OSError:
            pass


def detect_service(ip, port):
    """Attempt to identify HTTP, FTP, Telnet, or SSH on an open port via banner grabbing."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(10)
        s.connect((ip, port))
        try:
            # SSH and FTP send banners immediately; send HTTP probe for others
            s.sendall(b"GET / HTTP/1.0\r\nHost: " + ip.encode() + b"\r\n\r\n")
            banner = s.recv(1024)
        except:
            banner = b""
        finally:
            try:
                s.close()
            except OSError:
                pass

        if banner.startswith(b"SSH-"):
            return "ssh"
        if banner.startswith(b"220") or b"FTP" in banner[:64]:
            return "ftp"
        if banner.startswith(b"\xff") or b"\xff\xfd" in banner[:8]:
            return "telnet"
        if b"HTTP/" in banner[:16] or b"<html" in banner.lower()[:64]:
            return "http"
        return None
    except:
        return None


network = input("Network to scan (e.g. 192.168.1.): ")
start_ip = input("Starting IP (e.g. 1): ")
end_ip = input("Ending IP (e.g. 254): ")
print("Additional ports to try to scan (ports 21-23 and 80 are always included)")
ports_str = input("Ports (e.g. 1024-2000 2048): ")

port_ranges = re.split(r'[,\s]', ports_str.strip())
ports = []
for port_range in port_ranges:
    if '-' in port_range:
        start_port, end_port = map(int, port_range.split('-'))
        ports.extend(range(start_port, end_port + 1))
    elif not port_range.isdigit():
        continue
    else:
        ports.append(int(port_range))

# Suppress proxychains chain debug output written directly to fd 2
_devnull = open(os.devnull, 'w')
os.dup2(_devnull.fileno(), 2)

# Cap workers at 200 — the SOCKS proxy is the bottleneck, not local fd limits.
# Too many concurrent connections causes the proxy to silently drop connections.
soft_limit, _ = resource.getrlimit(resource.RLIMIT_NOFILE)
MAX_WORKERS = min(500, soft_limit - 50)

all_ips = [f"{network}.{ip}" for ip in range(int(start_ip), int(end_ip) + 1)]
PROBE_PORTS_DICT = {21: 'ftp', 22: 'ssh', 23: 'telnet', 80: 'http'}
PROBE_PORTS = list(PROBE_PORTS_DICT.keys())

print(f"[*] Phase 1: scanning ports {PROBE_PORTS} on {len(all_ips)} addresses...")
live_hosts = set()
probe_targets = [(ip, port) for ip in all_ips for port in PROBE_PORTS]
with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
    futures = {executor.submit(is_port_open, ip, port): (ip, port) for ip, port in probe_targets}
    for future in as_completed(futures):
        ip, port, open_ = future.result()
        if open_:
            print(f"[+] {ip} port [{port}] is open ({PROBE_PORTS_DICT[port]})")
            live_hosts.add(ip)

if start_ip == end_ip:
    live_hosts = {f"{network}.{start_ip}"}  # If only one IP, assume it's live even if probes failed

if ports:
    extra_ports = [p for p in ports if p not in PROBE_PORTS]
    if extra_ports:
        print(f"[*] Phase 2: scanning {len(extra_ports)} additional port(s) on {len(live_hosts)} live hosts...")
        targets = [(ip, port) for ip in live_hosts for port in extra_ports]
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            futures = {executor.submit(is_port_open, ip, port): (ip, port) for ip, port in targets}
            for future in as_completed(futures):
                ip, port, open_ = future.result()
                if open_:
                    service = detect_service(ip, port)
                    if service:
                        print(f"[+] {ip} port [{port}] is open ({service})")
                    else:
                        print(f"[+] {ip} port [{port}] is open")