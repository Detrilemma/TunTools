#! /usr/bin/python3

import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
import re
import os
import resource
import ftplib
import urllib.request
import urllib.parse
from html.parser import HTMLParser

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


class LinkParser(HTMLParser):
    """Extract href and src attributes from HTML."""
    def __init__(self):
        super().__init__()
        self.links = []

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == 'a' and 'href' in attrs:
            self.links.append(attrs['href'])
        elif tag in ('img', 'script', 'link') and 'src' in attrs:
            self.links.append(attrs['src'])
        elif tag == 'link' and 'href' in attrs:
            self.links.append(attrs['href'])


def http_recursive_download(ip, port, base_dir):
    """Recursively download all reachable pages/files from an HTTP server."""
    base_url = f"http://{ip}:{port}"
    visited = set()

    def fetch(path):
        if path in visited:
            return
        visited.add(path)

        url = base_url + path
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            resp = urllib.request.urlopen(req, timeout=10)
            data = resp.read()
        except Exception as e:
            print(f"  [!] HTTP error {url}: {e}")
            return

        # Build local file path
        local_path = path.lstrip('/')
        if not local_path or local_path.endswith('/'):
            local_path = local_path + 'index.html'
        local_file = os.path.join(base_dir, local_path)
        os.makedirs(os.path.dirname(local_file) or base_dir, exist_ok=True)

        with open(local_file, 'wb') as f:
            f.write(data)
        print(f"  [>] Saved {url} -> {local_file}")

        # Parse links from HTML responses
        content_type = resp.headers.get('Content-Type', '')
        if 'html' in content_type:
            parser = LinkParser()
            try:
                parser.feed(data.decode('utf-8', errors='ignore'))
            except Exception:
                return
            for link in parser.links:
                parsed = urllib.parse.urlparse(link)
                # Only follow relative links or links to the same host
                if parsed.netloc and parsed.netloc != f"{ip}:{port}":
                    continue
                next_path = parsed.path or '/'
                if not next_path.startswith('/'):
                    next_path = '/' + next_path
                fetch(next_path)

    print(f"[*] HTTP recursive download: {base_url} -> {base_dir}/")
    fetch('/')


def ftp_recursive_download(ip, port, base_dir):
    """Recursively download all files from an FTP server (anonymous login)."""

    class NatFTP(ftplib.FTP):
        """FTP subclass that ignores the IP in PASV responses and always connects
        back to the original server IP. Required when the server is behind NAT
        or accessed through a SOCKS proxy."""
        def __init__(self, target_ip):
            super().__init__()
            self._target_ip = target_ip

        def makepasv(self):
            _, data_port = super().makepasv()
            return self._target_ip, data_port

    try:
        ftp = NatFTP(ip)
        ftp.set_pasv(True)
        ftp.connect(ip, port, timeout=20)
        ftp.login()  # anonymous
    except Exception as e:
        print(f"  [!] FTP connect failed {ip}:{port}: {e}")
        return

    print(f"[*] FTP recursive download: ftp://{ip}:{port} -> {base_dir}/")

    def download_dir(remote_path, local_path):
        os.makedirs(local_path, exist_ok=True)
        try:
            entries = []
            ftp.retrlines(f"LIST {remote_path}", entries.append)
        except Exception as e:
            print(f"  [!] FTP LIST failed {remote_path}: {e}")
            return

        for entry in entries:
            parts = entry.split(None, 8)
            if len(parts) < 9:
                continue
            name = parts[8]
            is_dir = entry.startswith('d')
            remote_item = remote_path.rstrip('/') + '/' + name
            local_item = os.path.join(local_path, name)

            if is_dir:
                download_dir(remote_item, local_item)
            else:
                try:
                    with open(local_item, 'wb') as f:
                        ftp.retrbinary(f"RETR {remote_item}", f.write)
                    print(f"  [>] Saved ftp://{ip}{remote_item} -> {local_item}")
                except Exception as e:
                    print(f"  [!] FTP RETR failed {remote_item}: {e}")

    download_dir('/', base_dir)
    ftp.quit()


def auto_grab(ip, port, service):
    """Download content from HTTP or FTP service automatically."""
    base_dir = os.path.join(os.getcwd(), ip)
    if service == 'http':
        http_recursive_download(ip, port, base_dir)
    elif service == 'ftp':
        ftp_recursive_download(ip, port, base_dir)



network = input("Network to scan (e.g. 192.168.1.): ")
start_ip = input("Starting IP (e.g. 1): ")
end_ip = input("Ending IP (e.g. 254): ")
print("Additional ports to try to get FTP or HTTP content from (ports 80 and 21 are always included)")
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
PROBE_PORTS = [21, 80, 22, 23]

print(f"[*] Phase 1: scanning ports {PROBE_PORTS} on {len(all_ips)} addresses...")
live_hosts = set()
probe_targets = [(ip, port) for ip in all_ips for port in PROBE_PORTS]
with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
    futures = {executor.submit(is_port_open, ip, port): (ip, port) for ip, port in probe_targets}
    for future in as_completed(futures):
        ip, port, open_ = future.result()
        if open_:
            print(f"[+] {ip} port [{port}] is open")
            live_hosts.add(ip)
            if port == 80:
                auto_grab(ip, port, 'http')
            elif port == 21:
                auto_grab(ip, port, 'ftp')

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
                        if service in ('http', 'ftp'):
                            auto_grab(ip, port, service)
                    else:
                        print(f"[+] {ip} port [{port}] is open")