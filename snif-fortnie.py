from __future__ import annotations
import functools, queue, subprocess, threading, time, re, os
from datetime import datetime
from ipaddress import ip_address

import psutil, requests, tkinter as tk
from colorama import Fore, Style, init
from scapy.all import sniff, UDP, IP, IPv6

# ────────── CONFIG ───────────────────────────────────────────────────────────
# Names of network interfaces to sniff on (as they appear in ncpa.cpl)
INTERFACE = ["Ethernet", "Germanu"]

# Allowed executable paths (Fortnite or other UDP games)
EXE_WHITELIST   = {
    r"C:\Program Files\Epic Games\Fortnite\FortniteGame\Binaries\Win64\FortniteClient-Win64-Shipping.exe",
    r"C:\Program Files\Epic Games\Fortnite\FortniteGame\Binaries\Win64\FortniteLauncher.exe",
}

REFRESH_SEC     = 1
API_URL         = "https://api.ipapi.is/?q={ip}"
TIMEOUT_SEC     = 2                # timeout HTTP lookup
PING_COUNT      = 3                # ping packets
PING_TIMEOUT_MS = 800              # single packet timeout

# ── BLACKLIST IP (for avoid spam when launch fortnite) ────────────────────────────────────────────────────────
BLACKLIST_IPS: set[str] = {
    "44.198.247.11","35.86.57.246","44.230.113.121","52.41.253.108","34.81.184.184",
    "44.192.143.240","54.72.57.38","44.237.247.68","34.87.49.231","18.133.162.149",
    "35.237.14.31","34.87.167.158","35.228.66.4","3.129.132.172","3.129.132.110",
    "3.129.132.114","34.133.188.100","34.135.129.44","34.67.222.217","34.71.204.240",
    "40.172.242.214","18.88.1.174","18.203.144.66","3.101.95.156","3.101.95.110",
    "13.244.131.229","3.101.95.175","3.101.95.137","16.78.175.98","35.240.153.227",
    "108.137.115.89","52.215.117.65","35.234.48.74","18.133.162.190","15.161.170.166",
    "34.88.62.102","13.37.148.3","35.152.93.186","44.192.142.31","3.25.159.13",
    "3.129.132.16","34.88.196.221","51.84.98.223","54.251.3.166","35.198.197.12",
    "13.37.152.32","13.245.42.55","3.66.90.29","35.152.36.236","18.133.101.207",
    "13.245.72.164","51.84.95.24","34.75.199.141","13.213.163.87","51.84.121.221",
    "3.66.90.156","13.245.225.73","34.88.43.140","15.184.13.1","34.138.232.184",
    "18.142.4.73","75.2.9.147","18.88.1.126","15.228.25.138","15.161.174.31",
    "34.243.129.20","78.12.236.48","15.236.8.96","34.83.118.95","3.66.90.162",
    "40.172.211.170","13.228.152.186","16.78.224.94","108.137.109.187","34.81.219.75",
    "44.192.143.151","78.12.199.26","35.230.86.136","15.228.25.118","34.127.86.244",
    "3.29.76.37","15.184.13.112","15.184.13.186","78.12.119.48","3.25.159.51",
    "78.13.5.188","3.25.159.42","15.237.20.100","51.112.150.166","3.66.90.173",
    "99.83.150.159","18.133.162.202","51.84.84.158","15.184.13.113","34.139.51.62",
    "18.88.1.178","3.109.193.190","13.234.252.166","34.82.62.62","3.109.26.178",
    "3.110.24.16","35.194.146.185","15.228.25.140","35.72.18.156","15.228.25.156",
    "35.72.18.108","35.72.18.106","3.37.220.181","3.37.110.21","3.36.37.201",
    "35.72.18.102","3.25.159.65","3.37.5.207","18.88.1.169",
}
# ─────────────────────────────────────────────────────────────────────────────

init(autoreset=True)

fortnite_udp_ports: set[int] = set()
local_ips = {a.address for addrs in psutil.net_if_addrs().values() for a in addrs}
notified_ips: set[str] = set()
notify_q: queue.Queue[str] = queue.Queue()

# ---------- BLACKLIST HELPERS ----------
_BLACKLIST_IPS_CANON: set[str] = set()

def _canon_ip(ip: str) -> str:
    try:
        return str(ip_address(ip))
    except Exception:
        return ip

def _init_blacklist():
    global _BLACKLIST_IPS_CANON
    _BLACKLIST_IPS_CANON = set(_canon_ip(x) for x in BLACKLIST_IPS)
    print(f"{Fore.YELLOW}[BL] Blacklist loaded: {len(_BLACKLIST_IPS_CANON)} IP{Style.RESET_ALL}")

def is_blacklisted_ip(ip: str) -> bool:
    return _canon_ip(ip) in _BLACKLIST_IPS_CANON

# ---------- LOOKUP ----------
@functools.lru_cache(maxsize=4096)
def ip_lookup(ip: str) -> tuple[str, str, str]:
    try:
        r = requests.get(API_URL.format(ip=ip), timeout=TIMEOUT_SEC)
        if r.ok:
            j = r.json()
            loc = j.get("location", {})
            city    = loc.get("city")    or ""
            country = loc.get("country") or ""
            dc      = j.get("datacenter", {}).get("datacenter") \
                   or j.get("company", {}).get("name") or ""
            return city, country, dc
    except Exception:
        pass
    return "", "", ""

# ---------- PING ----------
_PING_SAMPLE_RE = re.compile(
    r"(?:time|tempo|durata|tiempo|zeit|temps|t)\s*[=<]\s*(\d+)\s*ms",
    re.IGNORECASE,
)
_PING_AVG_RE = re.compile(
    r"(?:Average|Media|Medio)\s*=\s*(\d+)\s*ms",
    re.IGNORECASE,
)

def ping_avg_ms(ip: str, count: int = PING_COUNT, timeout_ms: int = PING_TIMEOUT_MS) -> int | None:
    ip_is_v6 = ":" in ip
    args = ["ping", "-n", str(count), "-w", str(timeout_ms), "-6" if ip_is_v6 else "-4", ip]

    try:
        total_to = count * (timeout_ms / 1000 + 0.5)
        res = subprocess.run(
            args,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="ignore",
            timeout=total_to,
        )
        out = res.stdout

        samples = [int(x) for x in _PING_SAMPLE_RE.findall(out)]
        if samples:
            return round(sum(samples) / len(samples))

        m = _PING_AVG_RE.search(out)
        if m:
            return int(m.group(1))

        if "Received = 0" in out or "Ricevuti = 0" in out:
            return None

    except Exception:
        pass
    return None

# ---------- AUDIO ----------
CHIME_FREQ = 600      # Hz
CHIME_MS   = 120      # beep ms
CHIME_VOL  = 0.05     # 0.0-1.0 volume

try:
    import winsound, math, struct, io, wave, threading as _th

    _CHIME_WAV: bytes | None = None

    def _build_chime():
        global _CHIME_WAV
        if _CHIME_WAV is not None:
            return
        sr = 44100
        n  = int(sr * CHIME_MS / 1000.0)
        amp = int(32767 * max(0.0, min(1.0, CHIME_VOL)))  # clamp

        frames = bytearray()
        twopi = 2.0 * math.pi
        step  = twopi * CHIME_FREQ / sr
        for i in range(n):
            sample = int(math.sin(step * i) * amp)
            frames += struct.pack("<h", sample)

        bio = io.BytesIO()
        with wave.open(bio, "wb") as w:
            w.setnchannels(1)
            w.setsampwidth(2)
            w.setframerate(sr)
            w.writeframes(frames)
        _CHIME_WAV = bio.getvalue()

    def _play_sync():
        winsound.PlaySound(_CHIME_WAV, winsound.SND_MEMORY | winsound.SND_NODEFAULT)

    def play_chime():
        _build_chime()
        _th.Thread(target=_play_sync, daemon=True).start()

except ImportError:
    def play_chime(): pass

# ---------- GUI ----------
def popup(root: tk.Tk, message: str, duration: int = 8, y_offset: int = 140):
    win = tk.Toplevel(root)
    win.overrideredirect(True)
    win.attributes("-topmost", True)
    win.attributes("-alpha", 0.0)

    w, h = 540, 190
    x = (root.winfo_screenwidth() - w) // 2
    win.geometry(f"{w}x{h}+{x}+{y_offset}")

    play_chime()
    bg = "#1e1e1e"
    frame = tk.Frame(win, bg=bg)
    frame.pack(fill="both", expand=True)

    # Title
    tk.Label(frame, text="Fortnite – Server detected (UDP)",
             font=("Segoe UI", 16, "bold"), fg="#ffffff", bg=bg
             ).pack(pady=(12, 0))

    info = tk.Frame(frame, bg=bg)
    info.pack(pady=(6, 12), padx=20, fill="both", expand=True)

    lines = [ln for ln in message.splitlines() if ln.strip()]
    rows = []
    for ln in lines:
        if ":" in ln:
            k, v = ln.split(":", 1)
            rows.append((k.strip(), v.strip()))
        else:
            rows.append(("", ln.strip()))

    # Costruisci griglia
    for r, (k, v) in enumerate(rows):
        tk.Label(info, text=(k + ":" if k else ""), font=("Segoe UI", 12, "bold"),
                 fg="#ffffff", bg=bg, anchor="e", width=11
                 ).grid(row=r, column=0, sticky="e", padx=(0, 4), pady=0)
        tk.Label(info, text=v, font=("Segoe UI", 12),
                 fg="#dddddd", bg=bg, anchor="w", justify="left", wraplength=360
                 ).grid(row=r, column=1, sticky="w", padx=(0, 0), pady=0)

    def fade(step: float):
        a = win.attributes("-alpha") + step
        win.attributes("-alpha", max(0, min(0.95, a)))
        if 0 < a < 0.95:
            root.after(30, fade, step)
        elif a >= 0.95:
            root.after(duration*1000, fade, -0.05)
        else:
            win.destroy()
    fade(+0.05)

def ui_thread():
    root = tk.Tk(); root.withdraw()
    def poll():
        try:
            while True:
                popup(root, notify_q.get_nowait())
        except queue.Empty:
            pass
        root.after(100, poll)
    poll(); root.mainloop()

# ---------- PORT REFRESH ----------
def update_ports():
    global fortnite_udp_ports, notified_ips
    prev_nonempty = False
    while True:
        ports = {c.laddr.port for p in psutil.process_iter(['exe'])
                 if (p.info['exe'] in EXE_WHITELIST)
                 for c in p.net_connections(kind='udp') if c.laddr}
        fortnite_udp_ports = ports
        now_nonempty = bool(ports)
        if prev_nonempty and not now_nonempty:
            notified_ips.clear()
        prev_nonempty = now_nonempty
        time.sleep(REFRESH_SEC)

# ---------- SERVER PROCESSOR (lookup + ping + notify) ----------
def process_server(remote_ip: str, remote_port: int):
    if is_blacklisted_ip(remote_ip):
        return

    city, country, dc = ip_lookup(remote_ip)
    avg_ms = ping_avg_ms(remote_ip)
    ping_txt = f"{avg_ms} ms" if avg_ms is not None else "timeout"

    loc  = f"{city}, {country}".strip(", ")
    host = dc or "?"

    stamp = datetime.now().strftime("%H:%M:%S")
    print(f"{Fore.MAGENTA}[{stamp}] UDP → {remote_ip}:{remote_port:<5} | {host} | {loc} | Ping {ping_txt}{Style.RESET_ALL}")

    notify_q.put(
        f"IP: {remote_ip}:{remote_port}\n"
        f"DataCenter: {host}\n"
        f"Geo: {loc}\n"
        f"Average Ping: {ping_txt}"
    )

# ---------- PACKET HANDLER ----------
def handler(pkt):
    if UDP not in pkt: return

    # IPv4 / IPv6
    if IP in pkt:
        src, dst = pkt[IP].src, pkt[IP].dst
    elif IPv6 in pkt:
        src, dst = pkt[IPv6].src, pkt[IPv6].dst
    else:
        return

    if src in local_ips:
        remote_ip, remote_port = dst, pkt[UDP].dport
    elif dst in local_ips:
        remote_ip, remote_port = src, pkt[UDP].sport
    else:
        return

    if remote_ip in local_ips:
        return
    if is_blacklisted_ip(remote_ip):
        return
    if not (pkt[UDP].sport in fortnite_udp_ports or pkt[UDP].dport in fortnite_udp_ports):
        return
    if remote_ip in notified_ips:
        return

    notified_ips.add(remote_ip)
    threading.Thread(target=process_server, args=(remote_ip, remote_port), daemon=True).start()

# ---------- MAIN ----------
if __name__ == "__main__":
    import argparse, sys
    ap = argparse.ArgumentParser()
    ap.add_argument("--test", action="store_true", help="Show test popup and exit")
    ap.add_argument("--no-ui", action="store_true", help="Disable popup (console only)")
    args = ap.parse_args()

    _init_blacklist()

    if not args.no_ui:
        threading.Thread(target=ui_thread,    daemon=True).start()
    threading.Thread(target=update_ports, daemon=True).start()

    if args.test:
        notify_q.put("IP: 1.1.1.1:443\nDataCenter: Cloudflare\nGeo: Sydney, AU\nAverage Ping: 17 ms")
        time.sleep(4); sys.exit(0)

    print("UDP-only sniffer started… (CTRL+C to exit)")
    try:
        sniff(iface=INTERFACE, store=False, prn=handler, filter="udp")
    except PermissionError:
        print(f"{Fore.RED}Permission error: run the terminal as Administrator.{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}Error sniff: {e}{Style.RESET_ALL}")