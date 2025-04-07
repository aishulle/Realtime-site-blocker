# Realtime-site-blocker
 using Python, Scapy, and Windows Firewall

A lightweight Python tool that monitors DNS traffic in real-time and blocks access to unwanted websites by adding outbound firewall rules on Windows.

---

## Features

- Monitors DNS queries using `scapy`
-  Detects and logs domains from a customizable blocklist
-  Blocks resolved IP addresses using Windows Firewall
-  Prevents duplicate firewall rules for the same IP
- Lightweight and easy to use for personal networks

---

##  Blocked Websites

By default, the following domains (and any matching subdomains) are blocked:

- `facebook.com`
- `youtube.com`
- `reddit.com`
- `pinterest.com`

You can edit the `BLOCKLIST` in the script to include your own domains.

---

##  Requirements

- Python 3.x
- Run as **Administrator** (required to modify firewall rules)
- Install dependencies:

```bash
pip install scapy



