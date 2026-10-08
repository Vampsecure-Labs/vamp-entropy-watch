<!-- © VampSecure Studios — VampSecure Labs Security Research Division -->
<h1 align="center">vamp-entropy-watch</h1>
<p align="center">
  <strong>Real-time Shannon entropy monitor for early ransomware detection and encrypted file analysis</strong><br>
  <em>VampSecure Labs · Security Research Division</em>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/python-3.10%2B-blue?style=flat-square&logo=python&logoColor=white">
  <img src="https://img.shields.io/badge/platform-linux%20%7C%20macos-lightgrey?style=flat-square">
  <img src="https://img.shields.io/badge/license-research%20only-red?style=flat-square">
  <img src="https://img.shields.io/badge/VampSecure-Labs-8B0000?style=flat-square">
  <img src="https://github.com/Vampsecure-Labs/vamp-entropy-watch/actions/workflows/ci.yml/badge.svg" alt="CI"/>
</p>

---

## Overview

`vamp-entropy-watch` monitors directories for ransomware activity by computing the Shannon entropy of files as they are created or modified. Encrypted content approaches the theoretical maximum of 8 bits/byte and is statistically distinguishable from plaintext (~3–5 bits/byte) and even from legitimately compressed data (~7–7.5 bits/byte). When a file exceeds the configured entropy threshold, the tool raises an alert and optionally moves the file to a quarantine directory with read-only permissions to contain further damage.

It operates in two modes: a continuous `monitor` mode with a live Rich terminal table, and a one-shot `scan` mode for point-in-time audits and CI/CD pipeline integration.

## Features

- **Shannon entropy calculation** per file: H(X) = −Σ P(xᵢ) · log₂ P(xᵢ) over all 256 byte values; reads up to 1 MB per file for performance on large datasets
- **Four entropy levels**: ENCRYPTED (≥ threshold, default 7.0) / HIGH (≥ 88% of threshold) / MEDIUM (≥ 5.0) / SAFE (< 5.0)
- **Continuous `monitor` mode** with mtime/size change detection and configurable polling interval; displays a live-updating Rich table sorted by entropy descending
- **Automatic quarantine** — moves alert-triggering files to a configurable quarantine directory and sets them read-only (0o444) to prevent further modification; collision-safe naming with timestamp prefix
- **One-shot `scan` mode** — processes all files in the target directory once, prints the entropy table, and optionally exports JSON output sorted by entropy descending
- **Recursive directory support** via `--recursive` flag in both modes
- **Default extension exclusions** for already-compressed/binary formats (`.jpg`, `.zip`, `.gz`, `.exe`, `.dll`, etc.) that would generate spurious alerts
- **Configurable entropy threshold** — adjust to match the specific file corpus: `--threshold 7.5` for stricter detection, `--threshold 6.5` for broader coverage
- **JSON export** with per-file entropy, status label, size in bytes, and scan metadata
- **Unified VSL client report** (HTML/PDF) via `--report-html` / `--report-pdf` in both modes

## Requirements

```
pip install -r requirements.txt
```

| Package | Version |
|---------|---------|
| `rich`  | >= 13.7.0 |

Standard library: `argparse`, `json`, `math`, `os`, `shutil`, `sys`, `time`, `datetime`, `pathlib`.

## Installation


```bash
pip install vamp-entropy-watch
# o con Homebrew:
brew install vampsecure-labs/labs/vamp-entropy-watch
```

```bash
git clone https://github.com/belky-me/vamp-entropy-watch.git
cd vamp-entropy-watch
pip install -r requirements.txt
```

## Usage

```bash
python vamp_entropy_watch.py --help
```

Two subcommands are available: `monitor` and `scan`.

```
usage: vamp-entropy-watch {monitor,scan} ...

subcommands:
  monitor   Continuous directory surveillance
  scan      One-shot entropy audit
```

### Examples

**Continuously monitor the current directory with default threshold (7.0):**
```bash
python vamp_entropy_watch.py monitor
```

**Monitor a specific path, recursive, with quarantine enabled:**
```bash
python vamp_entropy_watch.py monitor -p /data/uploads -r --quarantine /data/quarantine
```

**Monitor without automatic quarantine (alert-only mode):**
```bash
python vamp_entropy_watch.py monitor -p /var/www --no-quarantine
```

**Monitor with a stricter threshold and 5-second polling interval:**
```bash
python vamp_entropy_watch.py monitor -p /home --threshold 7.5 --interval 5
```

**One-shot scan, recursive, export results to JSON:**
```bash
python vamp_entropy_watch.py scan -p /srv/data -r -o entropy_report.json
```

**One-shot scan with lowered threshold for broader suspicious-file coverage:**
```bash
python vamp_entropy_watch.py scan -p . --threshold 6.5
```

## Entropy Level Reference

| Label | Entropy Range | Typical Content |
|-------|--------------|----------------|
| ENCRYPTED | ≥ 7.0 (configurable) | Ransomware output, AES/ChaCha ciphertext |
| HIGH | ≥ ~6.2 | Dense binary, some archive formats |
| MEDIUM | ≥ 5.0 | Mixed binary/text, executables |
| SAFE | < 5.0 | Plaintext, source code, HTML |

## Output Formats

| Format | Flag | Description |
|--------|------|-------------|
| Console (Rich) | _(default)_ | Live table with per-file entropy, status, size, and detection time |
| JSON | `-o FILE` (scan mode) | Structured report with scan metadata and file list sorted by entropy |

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | No files exceeded the alert threshold |
| `1` | One or more files exceeded the alert threshold |

## Sample Output

```
$ python vamp_entropy_watch.py monitor -p /data/uploads -r --threshold 7.0

 vamp-entropy-watch v2.1 — VampSecure Labs
 Monitoring: /data/uploads (recursive)  |  Threshold: 7.0  |  Quarantine: /data/quarantine
 Polling interval: 10 s  |  Press Ctrl-C to stop

 File Entropy Monitor ────────────────────────────────────────────────────────────
 File                                    Entropy   Status      Size       Detected
 ─────────────────────────────────────────────────────────────────────────────────
 contracts/invoice_final.docx.enc        7.992     ENCRYPTED   248 KB     14:31:02
 contracts/report_2026.pdf.locked        7.988     ENCRYPTED   1.2 MB     14:31:02
 contracts/accounts.xlsx.crypt           7.974     ENCRYPTED   88 KB      14:31:05
 uploads/archive_backup.tar.gz           7.41      HIGH        34 MB      14:31:08
 uploads/firmware_update.bin             6.83      HIGH        5.6 MB     14:31:08
 uploads/user_manual.pdf                 4.72      MEDIUM      3.1 MB     14:31:08
 uploads/config.yaml                     2.91      SAFE        4 KB       14:31:08
 ─────────────────────────────────────────────────────────────────────────────────
 Alerts triggered: 3 ENCRYPTED files quarantined → /data/quarantine/
 [14:31:05] ALERT  contracts/accounts.xlsx.crypt  (7.974 bits/byte)  → quarantined
```

## Why vamp-entropy-watch vs. FSRM · Wazuh FIM · Tripwire

| Capability | vamp-entropy-watch | FSRM (Windows) | Wazuh FIM | Tripwire |
|---|---|---|---|---|
| Shannon entropy calculation per file | ✅ | ❌ | ❌ | ❌ |
| Cross-platform (Linux + macOS) | ✅ | ❌ Windows only | ✅ | ✅ |
| Automatic quarantine on alert | ✅ | ✅ | ❌ | ❌ |
| One-shot scan mode (CI/CD) | ✅ | ❌ | ❌ | ❌ |
| Zero agent — single Python file | ✅ | ❌ OS feature | ❌ requires agent | ❌ requires agent |
| Configurable entropy threshold | ✅ | ❌ | ❌ | ❌ |
| JSON export + VSL client report | ✅ | ❌ | ⚠️ SIEM output | ⚠️ enterprise only |
| Distinguishes encrypted vs. legitimately compressed | ✅ threshold + extension exclusions | ❌ | ❌ | ❌ |

- **Entropy as a first-class signal**: file-system change watchers detect that a file changed — not *what it became*. Entropy catches ransomware that renames and re-encrypts in place with no extension change.
- **Agentless, zero dependencies**: no SIEM, no agent to deploy, no kernel module. A single Python process with stdlib + `rich`; runs on any host in seconds.
- **Adjustable sensitivity**: `--threshold 7.5` avoids false positives from legitimate encryption (GPG, SSH keys); `--threshold 6.5` broadens coverage to staged exfiltration payloads before full encryption.
- **Containment by design**: automatic quarantine with read-only permissions (0o444) stops a ransomware process from modifying already-encrypted files and slows lateral encryption spread.

## Check Coverage

| Check ID | Description | Standard | Severity |
|---|---|---|---|
| ENT-001 | File entropy ≥ threshold (default 7.0) — consistent with AES/ChaCha ciphertext | MITRE ATT&CK T1486 | CRITICAL |
| ENT-002 | File entropy ≥ 88% of threshold — dense binary, possible staged payload | MITRE ATT&CK T1027 | HIGH |
| ENT-003 | File entropy ≥ 5.0 — mixed binary content, further analysis recommended | MITRE ATT&CK T1022 | MEDIUM |
| ENT-004 | Bulk encrypted files (≥5 ENCRYPTED within one polling interval) — mass-encryption pattern | MITRE ATT&CK T1486 | CRITICAL |
| ENT-005 | New file with ENCRYPTED entropy created in monitored directory | MITRE ATT&CK T1486 | CRITICAL |
| ENT-006 | Known plaintext type (.txt, .docx, .xlsx) now shows ENCRYPTED entropy | MITRE ATT&CK T1486 | CRITICAL |
| ENT-007 | File extension changed alongside high entropy (e.g. .docx → .docx.enc) | MITRE ATT&CK T1486 | HIGH |
| ENT-008 | Excluded extension with unexpected high entropy detected on explicit rescan | MITRE ATT&CK T1027 | MEDIUM |

## Part of VampSecure Labs Toolkit

This tool is part of the **VampSecure Labs Security Toolkit** — a collection of research-grade security tools for authorized penetration testing and red/blue team exercises.

- Full toolkit: [github.com/belky-me](https://github.com/belky-me)
- Orchestrator: [github.com/belky-me/vamp-orchestrator](https://github.com/belky-me/vamp-orchestrator)

---

© VampSecure Studios — VampSecure Labs Security Research Division  
For authorized security testing only.

---

## Versión
v2.1 — VampSecure Labs Security Research Division
