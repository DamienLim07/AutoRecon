# AutoRecon 🔍

**CTF-focused web reconnaissance tool**. This reconnaissance tool is adaptive, fast, and purpose-built for finding flags.

---

## Overview

AutoRecon orchestrates web recon tools at **native speed**. No Python overhead during scans. Tools run directly, with output being saved via `tee`, and Python post-processes results into a clean HTML report with **clickable paths**, **flag highlighting**, and a **sidebar TOC**.

Designed for CTF boxes where you need results fast and want everything in one place.

---

## Screenshots

These screenshots were taken with the "head-dump" Web Exploitation challenge from picoGym.

### CLI — Live Output
![CLI1](CLI1.png)
![CLI2](CLI2.png)

### HTML Report
![Report1](HTML1.png)
![Report2](HTML2.png)
![Report3](HTML3.png)

---

## Features

- **Service-based web detection** — detects web servers by service name, not just port number. Flask on 5000, Apache on 8888, anything Nmap identifies as HTTP gets scanned automatically
- **Skip Nmap** — use `--port` when you already know the port (common in CTF), jumps straight to recon
- **Quick CTF pre-checks** — instantly checks `robots.txt`, `sitemap.xml`, `flag.txt`, `flag.php` before full scan
- **Native speed scanning** — WhatWeb, Nikto, and Gobuster run at full speed via `tee`, no Python bottleneck
- **Gobuster clickable paths** — every path found becomes a clickable link in the report, open directly in browser
- **200 path previews** — automatically curls every 200 response, shows raw content preview, detects login pages and binary files
- **Flag pattern detection** — set your CTF flag prefix (e.g. `picoCTF`) and the tool highlights matches across all output post-scan
- **Organised output** — individual `.txt` files per tool per port, plus a timestamped HTML report
- **Auto-opens report** in your default browser when done
- **Terminal summary** — clean recap of open ports, 200 paths, flag matches, and non-web services

---

## Usage

```bash
# Basic — let Nmap discover ports
python3 recon.py <target>

# Skip Nmap — scan a known port directly (fastest for CTF)
python3 recon.py <target> --port 8080

# Set flag prefix for highlighting
python3 recon.py <target> -p picoCTF

# Full port scan — catches high ports like 50028, much slower
python3 recon.py <target> -f

# Custom wordlist
python3 recon.py <target> -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt

# Add extensions to Gobuster
python3 recon.py <target> -x php,html,txt

# Increase threads for faster Gobuster on stable networks
python3 recon.py <target> -t 100

# Full example
python3 recon.py verbal-sleep.picoctf.net --port 56131 -p picoCTF -t 80
```

---

## CLI Flags

| Flag | Default | Description |
|---|---|---|
| `target` | required | Target IP or hostname |
| `--port` | none | Skip Nmap, scan specific port directly |
| `--proto` | auto-detect | Protocol for `--port` (`http` or `https`) |
| `-f` / `--full` | off | Full Nmap scan (`-p-`) — all 65535 ports |
| `-w` / `--wordlist` | auto-detect | Gobuster wordlist path |
| `-t` / `--threads` | 40 | Gobuster thread count |
| `-x` / `--extensions` | none | Gobuster extensions e.g. `php,html,txt` |
| `-o` / `--output` | `./recon_output` | Output directory |
| `-p` / `--prefix` | prompt | Flag format prefix e.g. `picoCTF`, `LNC26` |

---

## Output Structure

```
recon_output/
├── nmap.txt                          # Nmap full output
├── whatweb_<port>.txt                # WhatWeb results
├── nikto_<port>.txt                  # Nikto results
├── gobuster_<port>.txt               # Gobuster results
├── precheck_<port>_<file>.txt        # Pre-check file contents
├── curl_<port>_<path>.txt            # Raw content of 200 paths
└── recon_<target>_<timestamp>.html   # Full HTML report
```

---

## Requirements

### Python
Python 3.6+ — stdlib only, no pip installs needed

### System Tools
```bash
sudo apt update && sudo apt install -y nmap gobuster nikto whatweb curl
```

### Wordlists
AutoRecon auto-detects wordlists from common Kali paths. To install SecLists:
```bash
sudo apt install seclists
```
Or specify your own with `-w`.

---

## Workflow

```
[Pre-scan]
  → Ask for flag prefix
  → Check all tools installed

[Phase 1 — Nmap]  (skipped if --port used)
  → Service version detection
  → Parse open ports, detect web services by service name

[Phase 2 — Quick CTF Pre-checks]
  → robots.txt, sitemap.xml, flag.txt, flag.php

[Phase 3 — Web Recon per port]
  → WhatWeb (tech fingerprinting)
  → Nikto (vulnerability scan)
  → Gobuster (directory bruteforce, native speed)
  → Curl all 200 paths → content preview, login detection, binary detection

[Phase 4 — Report]
  → Post-scan flag pattern search across all .txt files
  → Generate HTML report with clickable TOC
  → Auto-open in browser
  → Terminal summary
```

---

## ⚠️ Legal Disclaimer

For **authorized penetration testing and CTF competitions only**.

Only use against systems you own or have **explicit written permission** to test. Unauthorized use may violate Singapore's Computer Misuse Act and equivalent laws in your jurisdiction.

---

*Part of a growing CTF toolkit — hash identifier, steg multitool, and more coming soon.*
