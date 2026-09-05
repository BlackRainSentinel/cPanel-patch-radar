<div align="center">

```
██████╗ ██████╗ ███╗   ██╗███████╗██╗      
██╔══██╗██╔══██╗████╗  ██║██╔════╝██║      
██████╔╝███████║██╔██╗ ██║█████╗  ██║      
██╔═══╝ ██╔══██║██║╚██╗██║██╔══╝  ██║      
██║     ██║  ██║██║ ╚████║███████╗███████╗ 
╚═╝     ╚═╝  ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝
         RADAR :: cPanel/WHM CVE Audit
```

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-cPanel%2FWHM-orange.svg)](https://cpanel.net)
[![Shell](https://img.shields.io/badge/Shell-Bash-green.svg)](https://www.gnu.org/software/bash/)
[![CVEs Covered](https://img.shields.io/badge/CVEs%20Covered-12-red.svg)](#cve-coverage)
[![Maintained](https://img.shields.io/badge/Maintained-Yes-brightgreen.svg)](https://github.com/BlackRainSentinel/cPanel-patch-radar)

</div>

---

I work in the security unit of a hosting company. We manage 300+ cPanel servers and when the May 2026 CVE batch dropped, manually checking each one wasn't an option anymore — especially after seeing a few servers in our network get hit before patches were applied.

I wrote this to automate what I was doing by hand. Single file, no dependencies, runs anywhere cPanel is installed.

---

## What it does

Checks your cPanel/WHM server against 12 CVEs and security advisories from the May 2026 patch batch — including the critical auth bypass (CVE-2026-41940). Tells you what's vulnerable, what's patched, and can apply targeted fixes if you want.

No full `upcp --force`. No unnecessary reboots. Just checks the packages that matter and updates only what's broken.

---

## Quick Start

```bash
git clone https://github.com/BlackRainSentinel/cPanel-patch-radar.git
cd cPanel-patch-radar
chmod +x cPanel-patch-radar.sh
bash cPanel-patch-radar.sh
```

> Must be run as root on a cPanel/WHM server.

---

## Usage


```bash
# Just audit — no changes
bash cPanel-patch-radar.sh

# Audit and fix (confirms before each change)
bash cPanel-patch-radar.sh --fix

# Audit + fix + backup config files first
bash cPanel-patch-radar.sh --fix --backup

# Generate an HTML report (good for sending to clients)
bash cPanel-patch-radar.sh --report

# Everything at once
bash cPanel-patch-radar.sh --fix --backup --report

# Check one specific CVE
bash cPanel-patch-radar.sh --cve CVE-2026-41940
```

---

## Flags

| Flag | What it does |
|------|-------------|
| *(none)* | Audit only, zero changes |
| `--fix` | Targeted package update, asks confirmation first |
| `--backup` | Backs up config files before touching anything |
| `--report` | Saves an HTML report to `/var/log/cpanel-patch-radar/` |
| `--cve <ID>` | Run check for one CVE only |
| `--quiet` | No banner, just results |
| `--version` | Print version |
| `--help` | Print help |

---

## CVE Coverage

| CVE / Advisory | Severity | Package | Fixed |
|---|---|---|---|
| CVE-2026-41940 | 🔴 CRITICAL | cpanel | 2026-05-10 |
| CVE-2026-9256 | 🟠 HIGH | ea-nginx | 2026-05-22 |
| CVE-2026-33278 | 🟠 HIGH | cpanel-unbound | 2026-05-21 |
| CVE-2026-32993 | 🟠 HIGH | cpanel | 2026-05-13 |
| CVE-2026-32992 | 🟠 HIGH | cpanel | 2026-05-13 |
| CVE-2026-32991 | 🟡 MEDIUM | cpanel | 2026-05-13 |
| CVE-2026-29206 | 🟠 HIGH | cpanel | 2026-05-13 |
| CVE-2026-29205 | 🟠 HIGH | cpanel | 2026-05-13 |
| SEC-73755 | 🟠 HIGH | cpanel | 2026-05-19 |
| SEC-73728 | 🟠 HIGH | cpanel | 2026-05-19 |
| EasyApache4 v25.62 | 🟡 MEDIUM | ea-apache24 | 2026-05-21 |
| LiteSpeed Auto-Removal | 🔵 INFO | ea-lsws | 2026-05-19 |

---

## How fixes work

Each fix runs a targeted `yum update` on only the affected package:

```bash
yum update -y <package>
```

Before applying anything, the tool asks for confirmation. If you pass `--backup`, it copies the relevant config files first. The log goes to `/var/log/cpanel-patch-radar/`.

cPanel has a habit of shipping new bugs with every update cycle. I'd rather patch one package at a time than run a full update and deal with whatever breaks next.

---

## Output

Terminal output is color-coded — green for patched, red for vulnerable, yellow for warnings. Each result shows the CVE, severity, installed version, and fix date.

If you use `--report`, it generates a dark-themed HTML file you can attach to a ticket or send to a client without them needing to read raw terminal output.

---

## Requirements

- Root access
- cPanel/WHM (AlmaLinux 8/9 or CloudLinux 8/9)
- Bash 4.0+
- `rpm` and `yum` — already there on any cPanel server

---

## Disclaimer

Only run this on servers you own or have permission to audit. The author isn't responsible for misuse.

---

## Author
Telegram: [@danial_hmt](https://t.me/danial_hmt)  
