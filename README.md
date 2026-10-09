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

> 🇬🇧 [English](#english) · 🇪🇸 [Español](#español)

---

<a name="english"></a>
## 🇬🇧 English

`vamp-entropy-watch` monitors directories for ransomware activity by computing the Shannon entropy of files as they are created or modified. Encrypted content approaches the theoretical maximum of 8 bits/byte and is statistically distinguishable from plaintext (~3–5 bits/byte) and even from legitimately compressed data (~7–7.5 bits/byte). When a file exceeds the configured entropy threshold, the tool raises an alert and optionally moves the file to a quarantine directory with read-only permissions to contain further damage.

It operates in two modes: a continuous `monitor` mode with a live Rich terminal table, and a one-shot `scan` mode for point-in-time audits and CI/CD pipeline integration.

### Features

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

### Requirements

```
pip install -r requirements.txt
```

| Package | Version |
|---------|---------|
| `rich`  | >= 13.7.0 |

Standard library: `argparse`, `json`, `math`, `os`, `shutil`, `sys`, `time`, `datetime`, `pathlib`.

### Installation

```bash
pip install vamp-entropy-watch
# or with Homebrew:
brew install vampsecure-labs/labs/vamp-entropy-watch
```

```bash
git clone https://github.com/Vampsecure-Labs/vamp-entropy-watch.git
cd vamp-entropy-watch
pip install -r requirements.txt
```

### Usage

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

#### Examples

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

### Entropy Level Reference

| Label | Entropy Range | Typical Content |
|-------|--------------|----------------|
| ENCRYPTED | ≥ 7.0 (configurable) | Ransomware output, AES/ChaCha ciphertext |
| HIGH | ≥ ~6.2 | Dense binary, some archive formats |
| MEDIUM | ≥ 5.0 | Mixed binary/text, executables |
| SAFE | < 5.0 | Plaintext, source code, HTML |

### Output Formats

| Format | Flag | Description |
|--------|------|-------------|
| Console (Rich) | _(default)_ | Live table with per-file entropy, status, size, and detection time |
| JSON | `-o FILE` (scan mode) | Structured report with scan metadata and file list sorted by entropy |

### Exit Codes

| Code | Meaning |
|------|---------|
| `0` | No files exceeded the alert threshold |
| `1` | One or more files exceeded the alert threshold |

### Sample Output

```
$ python vamp_entropy_watch.py monitor -p /data/uploads -r --threshold 7.0

 vamp-entropy-watch v2.2 — VampSecure Labs
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

### Why vamp-entropy-watch vs. FSRM · Wazuh FIM · Tripwire

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

### Check Coverage

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

### Part of VampSecure Labs Toolkit

This tool is part of the **VampSecure Labs Security Toolkit** — a collection of research-grade security tools for authorized penetration testing and red/blue team exercises.

- Full toolkit: [github.com/Vampsecure-Labs](https://github.com/Vampsecure-Labs)
- Orchestrator: [github.com/Vampsecure-Labs/vamp-orchestrator](https://github.com/Vampsecure-Labs/vamp-orchestrator)

---

### Version History

| Version | Main changes |
|---------|-------------|
| v2.2 | Bilingual README (EN/ES) |
| v2.1 | Initial public release — monitor + scan modes, Shannon entropy, automatic quarantine |

---

© VampSecure Studios — VampSecure Labs Security Research Division  
For authorized security testing only.

---

<a name="español"></a>
## 🇪🇸 Español

`vamp-entropy-watch` monitoriza directorios en busca de actividad ransomware calculando la entropía Shannon de los ficheros a medida que se crean o modifican. El contenido cifrado se aproxima al máximo teórico de 8 bits/byte y es estadísticamente distinguible del texto plano (~3–5 bits/byte) e incluso de datos legítimamente comprimidos (~7–7.5 bits/byte). Cuando un fichero supera el umbral de entropía configurado, la herramienta lanza una alerta y opcionalmente mueve el fichero a un directorio de cuarentena con permisos de solo lectura para contener el daño.

Opera en dos modos: un modo `monitor` continuo con una tabla Rich en vivo, y un modo `scan` puntual para auditorías y pipelines CI/CD.

### Características

- **Cálculo de entropía Shannon** por fichero: H(X) = −Σ P(xᵢ) · log₂ P(xᵢ) sobre los 256 valores de byte; lee hasta 1 MB por fichero para rendimiento en conjuntos grandes
- **Cuatro niveles de entropía**: ENCRYPTED (≥ umbral, por defecto 7.0) / HIGH (≥ 88% del umbral) / MEDIUM (≥ 5.0) / SAFE (< 5.0)
- **Modo `monitor` continuo** con detección de cambios mtime/size e intervalo de sondeo configurable; muestra tabla Rich actualizada en vivo ordenada por entropía descendente
- **Cuarentena automática** — mueve los ficheros que disparan alertas a un directorio de cuarentena configurable y los pone en solo lectura (0o444) para prevenir modificaciones; nombre seguro ante colisiones con prefijo de timestamp
- **Modo `scan` puntual** — procesa todos los ficheros del directorio objetivo una vez, imprime la tabla de entropía y exporta opcionalmente JSON ordenado por entropía descendente
- **Soporte de directorios recursivo** via flag `--recursive` en ambos modos
- **Exclusiones de extensión por defecto** para formatos ya comprimidos/binarios (`.jpg`, `.zip`, `.gz`, `.exe`, `.dll`, etc.) que generarían falsas alertas
- **Umbral de entropía configurable** — ajústalo al corpus de ficheros específico: `--threshold 7.5` para detección más estricta, `--threshold 6.5` para mayor cobertura
- **Exportación JSON** con entropía por fichero, etiqueta de estado, tamaño en bytes y metadatos del escaneo
- **Informe unificado de cliente VSL** (HTML/PDF) via `--report-html` / `--report-pdf` en ambos modos

### Requisitos

```
pip install -r requirements.txt
```

| Paquete | Versión |
|---------|---------|
| `rich`  | >= 13.7.0 |

Biblioteca estándar: `argparse`, `json`, `math`, `os`, `shutil`, `sys`, `time`, `datetime`, `pathlib`.

### Instalación

```bash
pip install vamp-entropy-watch
# o con Homebrew:
brew install vampsecure-labs/labs/vamp-entropy-watch
```

```bash
git clone https://github.com/Vampsecure-Labs/vamp-entropy-watch.git
cd vamp-entropy-watch
pip install -r requirements.txt
```

### Uso

```bash
python vamp_entropy_watch.py --help
```

Hay dos subcomandos disponibles: `monitor` y `scan`.

```
uso: vamp-entropy-watch {monitor,scan} ...

subcomandos:
  monitor   Vigilancia continua de directorio
  scan      Auditoría de entropía puntual
```

#### Ejemplos

**Monitorizar el directorio actual con umbral por defecto (7.0):**
```bash
python vamp_entropy_watch.py monitor
```

**Monitorizar una ruta específica, recursivo, con cuarentena activada:**
```bash
python vamp_entropy_watch.py monitor -p /data/uploads -r --quarantine /data/quarantine
```

**Monitorizar sin cuarentena automática (solo alertas):**
```bash
python vamp_entropy_watch.py monitor -p /var/www --no-quarantine
```

**Monitorizar con umbral más estricto e intervalo de sondeo de 5 segundos:**
```bash
python vamp_entropy_watch.py monitor -p /home --threshold 7.5 --interval 5
```

**Escaneo puntual, recursivo, exportar resultados a JSON:**
```bash
python vamp_entropy_watch.py scan -p /srv/data -r -o entropy_report.json
```

**Escaneo puntual con umbral reducido para mayor cobertura de ficheros sospechosos:**
```bash
python vamp_entropy_watch.py scan -p . --threshold 6.5
```

### Referencia de niveles de entropía

| Etiqueta | Rango de entropía | Contenido típico |
|----------|-------------------|------------------|
| ENCRYPTED | ≥ 7.0 (configurable) | Salida de ransomware, texto cifrado AES/ChaCha |
| HIGH | ≥ ~6.2 | Binario denso, algunos formatos de archivo |
| MEDIUM | ≥ 5.0 | Binario/texto mezclado, ejecutables |
| SAFE | < 5.0 | Texto plano, código fuente, HTML |

### Formatos de salida

| Formato | Flag | Descripción |
|---------|------|-------------|
| Consola (Rich) | _(por defecto)_ | Tabla en vivo con entropía por fichero, estado, tamaño y hora de detección |
| JSON | `-o FICHERO` (modo scan) | Informe estructurado con metadatos y lista de ficheros ordenada por entropía |

### Exit codes

| Código | Significado |
|--------|-------------|
| `0` | Ningún fichero superó el umbral de alerta |
| `1` | Uno o más ficheros superaron el umbral de alerta |

### Por qué vamp-entropy-watch frente a FSRM · Wazuh FIM · Tripwire

| Capacidad | vamp-entropy-watch | FSRM (Windows) | Wazuh FIM | Tripwire |
|---|---|---|---|---|
| Cálculo de entropía Shannon por fichero | ✅ | ❌ | ❌ | ❌ |
| Multiplataforma (Linux + macOS) | ✅ | ❌ solo Windows | ✅ | ✅ |
| Cuarentena automática ante alerta | ✅ | ✅ | ❌ | ❌ |
| Modo scan puntual (CI/CD) | ✅ | ❌ | ❌ | ❌ |
| Sin agente — fichero Python único | ✅ | ❌ función del SO | ❌ requiere agente | ❌ requiere agente |
| Umbral de entropía configurable | ✅ | ❌ | ❌ | ❌ |
| Exportación JSON + informe de cliente VSL | ✅ | ❌ | ⚠️ salida SIEM | ⚠️ solo enterprise |
| Distingue cifrado de comprimido legítimo | ✅ umbral + exclusiones de extensión | ❌ | ❌ | ❌ |

- **Entropía como señal de primer orden**: los vigilantes de cambios en el sistema de ficheros detectan que un fichero cambió — no *en qué se convirtió*. La entropía atrapa ransomware que renombra y re-cifra en sitio sin cambiar la extensión.
- **Sin agente, cero dependencias**: no necesita SIEM, agente a desplegar ni módulo de kernel. Un único proceso Python con stdlib + `rich`; funciona en cualquier host en segundos.
- **Sensibilidad ajustable**: `--threshold 7.5` evita falsos positivos por cifrado legítimo (GPG, claves SSH); `--threshold 6.5` amplía la cobertura a payloads de exfiltración antes del cifrado completo.
- **Contención por diseño**: la cuarentena automática con permisos de solo lectura (0o444) impide que un proceso ransomware modifique ficheros ya cifrados y frena la propagación lateral.

### Cobertura de checks

| Check ID | Descripción | Estándar | Severidad |
|---|---|---|---|
| ENT-001 | Entropía de fichero ≥ umbral (por defecto 7.0) — consistente con texto cifrado AES/ChaCha | MITRE ATT&CK T1486 | CRITICAL |
| ENT-002 | Entropía de fichero ≥ 88% del umbral — binario denso, posible payload en espera | MITRE ATT&CK T1027 | HIGH |
| ENT-003 | Entropía de fichero ≥ 5.0 — contenido binario mixto, se recomienda análisis adicional | MITRE ATT&CK T1022 | MEDIUM |
| ENT-004 | Ficheros cifrados en masa (≥5 ENCRYPTED en un intervalo de sondeo) — patrón de cifrado masivo | MITRE ATT&CK T1486 | CRITICAL |
| ENT-005 | Nuevo fichero con entropía ENCRYPTED creado en el directorio monitorizado | MITRE ATT&CK T1486 | CRITICAL |
| ENT-006 | Tipo de texto plano conocido (.txt, .docx, .xlsx) muestra ahora entropía ENCRYPTED | MITRE ATT&CK T1486 | CRITICAL |
| ENT-007 | Extensión de fichero cambiada junto con entropía alta (p. ej. .docx → .docx.enc) | MITRE ATT&CK T1486 | HIGH |
| ENT-008 | Extensión excluida con entropía alta inesperada detectada en rescaneo explícito | MITRE ATT&CK T1027 | MEDIUM |

### Parte del toolkit VampSecure Labs

Esta herramienta forma parte del **toolkit de seguridad VampSecure Labs** — una colección de herramientas de seguridad de grado investigación para pruebas de penetración autorizadas y ejercicios red/blue team.

---

### Historial de versiones

| Versión | Cambios principales |
|---------|---------------------|
| v2.2 | README bilingüe (EN/ES) |
| v2.1 | Lanzamiento público inicial — modos monitor + scan, entropía Shannon, cuarentena automática |

---

© VampSecure Studios — VampSecure Labs Security Research Division  
Uso exclusivo en pruebas de seguridad autorizadas.
