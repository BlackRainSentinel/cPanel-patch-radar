<div align="center">

```
   ___  ____  __   ____  ____  __       ____  __  ____  ____  _  _     ____  __   ____   __   ____
  / __)(  _ \/ _\ (  _ \(  __)(  )     (  _ \/ _\(_  _)/ ___\/ )( \   (  _ \/ _\ (    \ / _\ (  _ \
 ( (__  ) __/    \ ) __/ ) _)  ) (_/\   ) __/    \  )(  \___ \) __ (    )   /    \ ) D (    \  )   /
  \___)(__)  \_/\_/(__)  (____)(_____/  (__)  \_/\_/(__) (____/\_)(_/   (__\_)\_/\_/(____/\_/\_(__\_)
```

**cPanel/WHM CVE Audit & Remediation Tool**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-cPanel%2FWHM-orange.svg)](https://cpanel.net)
[![Shell](https://img.shields.io/badge/Shell-Bash-green.svg)](https://www.gnu.org/software/bash/)
[![CVEs Covered](https://img.shields.io/badge/CVEs%20Covered-12-red.svg)](#cve-coverage)
[![Maintained](https://img.shields.io/badge/Maintained-Yes-brightgreen.svg)](https://github.com/danialsobhani/cpanel-patch-radar)

</div>

---

**cpanel-patch-radar** is a single-file Bash tool for auditing cPanel/WHM servers against the latest CVEs and security advisories. It checks version status, reports vulnerabilities with severity levels, and can apply targeted package fixes — all with a clean terminal UI and optional HTML report for client delivery.

> Built by a Linux Security Specialist at a hosting provider. Real-world tested. No bloat.

---

## Features

- **12 CVEs & Advisories covered** (May 2026 batch + CVE-2026-41940)
- **Targeted package fixes** — only updates the vulnerable package, never a full `upcp --force`
- **Optional backup** before applying any fix
- **HTML report** — professional, dark-themed, ready to send to clients
- **Color-coded terminal output** — PASS / FAIL / WARN / FIXED / SKIP
- **Flag-based CLI** — scriptable, cron-friendly, no interactive prompts by default
- **Single file, zero dependencies** — just Bash + rpm/yum (standard on AlmaLinux/CloudLinux)
- **Audit log** saved to `/var/log/cpanel-patch-radar/`

---

## Quick Start

```bash
# Audit only (safe, no changes)
bash cpanel-patch-radar.sh

# Audit + fix (asks confirmation before each fix)
bash cpanel-patch-radar.sh --fix

# Audit + fix + backup before changes
bash cpanel-patch-radar.sh --fix --backup

# Audit + generate HTML report
bash cpanel-patch-radar.sh --report

# Full run: fix, backup, HTML report
bash cpanel-patch-radar.sh --fix --backup --report

# Check a single CVE
bash cpanel-patch-radar.sh --cve CVE-2026-41940
```

---

## Installation

```bash
git clone https://github.com/danialsobhani/cpanel-patch-radar.git
cd cpanel-patch-radar
chmod +x cpanel-patch-radar.sh
bash cpanel-patch-radar.sh
```

**Requirements:**
- Root access
- cPanel/WHM server (AlmaLinux 8/9, CloudLinux 8/9)
- Bash 4.0+
- `rpm` and `yum` (standard on all cPanel-supported distros)

---

## CLI Options

| Flag | Description |
|------|-------------|
| *(none)* | Audit only — no changes made |
| `--fix` | Apply targeted package updates (asks confirmation per fix) |
| `--backup` | Create backups before applying fixes |
| `--report` | Generate HTML report in `/var/log/cpanel-patch-radar/` |
| `--cve <ID>` | Audit a single CVE (e.g. `--cve CVE-2026-41940`) |
| `--quiet` | Suppress banner and info output |
| `--version` | Show version |
| `--help` | Show help |

---

## CVE Coverage

| CVE / Advisory | Severity | Package | Fix Date |
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

## How Fixes Work

This tool uses **targeted package updates only**:

```bash
yum update -y <vulnerable-package>
```

It does **not** run `upcp --force` or `upcp --tier=current`. A full cPanel update on a production server carries downtime risk — we never do that automatically.

Fix flow for each vulnerability:
1. Check current version
2. Confirm with operator before any change
3. Optional: backup config files
4. Run targeted `yum update`
5. Log result

---

## Output & Logs

**Terminal output:**
```
  ✔ PASS  [HIGH]      CVE-2026-9256
           ea-nginx Security Release — Installed: 1.31.1-1.cp1208

  ✘ FAIL  [CRITICAL]  CVE-2026-41940
           cPanel Authentication Bypass — cPanel 120.0.10 is vulnerable.

  ⚠ WARN  [INFO]      LITESPEED-AUTO-REMOVE
           LiteSpeed is installed. Nightly update may auto-remove it.
```

**Log file:** `/var/log/cpanel-patch-radar/audit_YYYYMMDD_HHMMSS.log`

**HTML report:** `/var/log/cpanel-patch-radar/report_YYYYMMDD_HHMMSS.html`
Dark-themed, professional layout — ready to attach to a ticket or email to a client.

---

## Disclaimer

This tool is intended for **authorized system administrators** auditing servers they own or manage. Running security tools against systems without permission is illegal. The author takes no responsibility for misuse.

Fixes are applied via standard `yum` package management. Always review changes in a staging environment before production. Taking backups (`--backup`) is strongly recommended.

---

## Contributing

Pull requests welcome. If you find a new cPanel CVE not covered here, open an issue with:
- CVE ID
- Affected package
- Fixed version
- Source (cPanel security advisories page)

---

## Author

**Danial Sobhani** — Linux Security Specialist  
Telegram: [@danial_hmt](https://t.me/danial_hmt)  
Website: [danialsobhani.ir](https://danialsobhani.ir)

---

<div align="center">
<sub>MIT License — Free to use, modify, and distribute.</sub>
</div>
