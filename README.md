# TunTools

A collection of Python network scanning and content-grabbing scripts designed to work through a SOCKS proxy via `proxychains`.

---

## Installation

These scripts are standalone Python 3 files with no external dependencies. To install on a Debian/Ubuntu-based VM:

1. Copy the script content into a new file, for example:
   ```bash
   nano grabby_scan.py
   # paste the contents, then save and exit (Ctrl+X, Y, Enter)
   ```

2. Make it executable:
   ```bash
   chmod +x grabby_scan.py
   ```

3. Run it:
   ```bash
   proxychains ./grabby_scan.py
   ```

Repeat steps 1–2 for each script you want to use.

---

## Running scripts

All scripts are run the same way:

```bash
proxychains ./<script>.py
```

---

## Scripts

### `serv_scan.py` — Service-Identifying Port Scanner

An extended scanner that always probes ports 21, 22, 23, and 80 first, then optionally scans additional user-specified ports. Identifies the service running on any extra open ports via banner grabbing.

**Prompts:**
| Prompt | Example |
|--------|---------|
| Network prefix | `192.168.1.` |
| Starting host | `1` |
| Ending host | `254` |
| Additional ports | `1024-2000 8080` (or Enter to skip) |

**How it works:**

**Phase 1** — Always scans ports `21 (ftp)`, `22 (ssh)`, `23 (telnet)`, `80 (http)` on every IP in the range. Any IP with at least one open probe port is marked as a live host.

**Phase 2** — If additional ports were entered, scans those ports *only on live hosts* from Phase 1. Each open port is banner-grabbed to detect whether it is running HTTP, FTP, SSH, or Telnet. Unknown services are reported as just open.

**Output:**
```
[*] Phase 1: scanning ports [21, 22, 23, 80] on 254 addresses...
[+] 192.168.1.39 port [21] is open (ftp)
[+] 192.168.1.42 port [22] is open (ssh)
[*] Phase 2: scanning 977 additional port(s) on 2 live hosts...
[+] 192.168.1.39 port [8080] is open (http)
[+] 192.168.1.42 port [2222] is open
```

**Single vs range:**
- **Range**: Phase 1 determines live hosts through active scanning. Phase 2 targets only those confirmed live hosts, saving significant time by skipping dead IPs.
- **Single IP** (same value for start and end): the script assumes the target is live and skips the liveness check, so Phase 2 always runs against that IP even if Phase 1 found no open probe ports. Useful when you know the host is up but its probe ports are all closed.

---

### `grabby_scan.py` — Scanner with Automatic Content Grabbing

Extends `serv_scan.py` by automatically downloading all content from any discovered HTTP or FTP service. Mirrors site structure locally, similar to `wget -r`.

**Prompts:**
| Prompt | Example |
|--------|---------|
| Network prefix | `192.168.1.` |
| Starting host | `1` |
| Ending host | `254` |
| Additional ports | `8080 2121` (or Enter to skip) |

**How it works:**

**Phase 1** — Scans ports `21 (ftp)`, `22 (ssh)`, `23 (telnet)`, and `80 (http)` on every IP. Any open port marks the host as live. Ports 21 and 80 additionally trigger an immediate recursive download if open. Ports 22 and 23 are used for host liveness detection only.

**Phase 2** — Scans user-specified extra ports on live hosts only. Banner-grabs each open port. If identified as HTTP or FTP, triggers a recursive download.

**Grabbing behaviour:**

*HTTP* — Fetches `/`, parses all `<a href>`, `<img src>`, `<script src>`, and `<link href>` tags, then recursively fetches each linked path on the same host. Only follows links that stay on the same server; external links are ignored.

*FTP* — Logs in anonymously, walks the full directory tree with `LIST`, and downloads every file with `RETR`. Works correctly through SOCKS/NAT by ignoring the IP advertised in the server's PASV response.

**Saved file structure:**
```
./<ip>/
    80/             <- HTTP content from port 80
        index.html
        images/
            logo.png
    21/             <- FTP content from port 21
        pub/
            readme.txt
    8080/           <- Additional port, if HTTP/FTP was detected
        index.html
```

Files are saved relative to the directory the script is run from.

**Output:**
```
[*] Phase 1: scanning ports [21, 22, 23, 80] on 254 addresses...
[+] 192.168.1.39 port [80] is open
[*] HTTP recursive download: http://192.168.1.39:80 -> ./192.168.1.39/80/
  [>] Saved http://192.168.1.39:80/ -> ./192.168.1.39/80/index.html
  [>] Saved http://192.168.1.39:80/about.html -> ./192.168.1.39/80/about.html
[+] 192.168.1.39 port [21] is open
[*] FTP recursive download: ftp://192.168.1.39:21 -> ./192.168.1.39/21/
  [>] Saved ftp://192.168.1.39/pub/notes.txt -> ./192.168.1.39/21/pub/notes.txt
```

**Single vs range:**
- **Range**: live host detection runs in Phase 1. Phase 2 extra-port scans and grabs only target confirmed live hosts.
- **Single IP** (same value for start and end): the IP is assumed live regardless of Phase 1 results. Phase 2 always runs, ensuring a deep service scan and grab even if ports 21, 22, 23, and 80 are all closed.

---

## Notes

### Running through proxychains

All scripts suppress proxychains' chain debug output internally by redirecting fd 2 to `/dev/null` after user input is collected. You do not need to run with `proxychains -q`.

### Worker count

All scripts auto-detect a safe worker count from the system's file descriptor limit, capped at 500. The SOCKS proxy is typically the throughput bottleneck before local limits become relevant. If you see missed results on large scans, the proxy may be dropping connections — reduce `MAX_WORKERS` in the script.

### Timeouts

All connection attempts use a 2-second timeout. Banner-grabbing uses a 10-second timeout. Through a SOCKS/Tor proxy these values may need to be increased if the network is slow.
