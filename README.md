# Fortnite Server Sniffer & Notifier (Windows)

A tiny helper that watches **UDP** traffic from Fortnite (or other whitelisted games), does an **ipapi.is** lookup, measures a quick **average ping**, and shows a neat **toast**. IPv4/IPv6 supported.

> **Note:** When the game runs **full-screen**, Windows may block the toast. You can always read everything in **CMD/PowerShell** (the script logs to console).

---

## Requirements

* **Npcap** (install with **“WinPcap API-compatible Mode”**)
  Download: [https://npcap.com/#:~:text=for%20Windows%207/2008R2%2C%208/2012%2C%208.1/2012R2%2C%2010/2016%2C%202019%2C%2011%20(x86%2C%20x64%2C%20and%20ARM64).](https://npcap.com/#:~:text=for%20Windows%207/2008R2%2C%208/2012%2C%208.1/2012R2%2C%2010/2016%2C%202019%2C%2011%20(x86%2C%20x64%2C%20and%20ARM64)).
* **Python 3.9+**
* Python packages:

  ```
  pip install scapy psutil requests colorama
  ```

---

## Quick start

1. Install **Npcap** and tick **WinPcap API-compatible Mode**.

2. Run from cmd:

   ```bash
   py fortnite_sniffer_notify.py
   ```

   Test popup:

   ```bash
   py fortnite_sniffer_notify.py --test
   ```

If you prefer no UI and only console:

```bash
py fortnite_sniffer_notify.py --no-ui
```

---

## Configure

Open `fortnite_sniffer_notify.py` and tweak:

* `INTERFACE` → your Windows adapter names (as shown in `ncpa.cpl`)
* `EXE_WHITELIST` → game executable paths (Fortnite by default)

There’s also a small IP **blacklist** to hide noisy startup services.

---

## Tips

* **Full screen**: toast may not show — keep **CMD/PowerShell** visible to read the logs.
* **Permission error**: re-run the terminal **as Administrator**. (but for me work no admin)
* **No packets**: check `EXE_WHITELIST` paths and that the game is running.

---

