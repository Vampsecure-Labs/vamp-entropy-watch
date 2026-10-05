#!/usr/bin/env python3
# © VampSecure Studios — VampSecure Labs Security Research Division
"""
vamp_entropy_watch.py — Monitor de Entropía para Detección de Ransomware
========================================================================
VampSecure Labs · VampSecure Studios
Para Uso Exclusivo en Pruebas de Penetración Autorizadas — v2.0

DESCRIPCIÓN GENERAL
-------------------
Monitor de entropía de Shannon para la detección temprana de actividad
ransomware y cifrado malicioso de ficheros. Analiza continuamente un
directorio objetivo calculando la entropía de los ficheros nuevos o
modificados: un fichero cifrado exhibe una entropía próxima al máximo
teórico (~8 bits/byte), lo que lo diferencia de texto plano (~3-5 bits/byte)
o datos comprimidos legítimos.

Cuando se detecta un fichero con entropía superior al umbral configurado
(default: H ≥ 7.0 bits/byte), la herramienta genera una alerta crítica y,
opcionalmente, mueve el fichero a una carpeta de cuarentena para contener
el daño. El modo scan permite auditar un estado de directorio puntualmente,
sin bucle continuo, exportando los resultados a JSON.

ARQUITECTURA DE EJECUCIÓN (2 modos)
------------------------------------
  Modo monitor (vigilancia continua)
    Fase 1 — Línea base: calcula entropía de todos los ficheros existentes
             en el directorio (y subdirectorios si --recursive) y establece
             el estado inicial. Filtros: DEFAULT_IGNORE_EXTS + patrones glob.
    Fase 2 — Bucle de detección: vigila cambios (ficheros nuevos o modificados
             por mtime/tamaño). Calcula H(X) para cada cambio detectado.
             Alerta si H ≥ umbral. Cuarentena automática si --quarantine.
    Salida: Rich Live table con entropía y estado por fichero en tiempo real.

  Modo scan (auditoría puntual)
    Escaneo único del directorio con salida Rich + exportación JSON opcional.
    Útil para verificaciones post-incidente o integraciones en pipelines CI/CD.

MODELO DE ENTROPÍA
------------------
  H(X) = -Σ P(xᵢ) · log₂ P(xᵢ)   para cada byte posible xᵢ ∈ {0…255}
  Umbral por defecto: 7.0 bits/byte
  Niveles: CIFRADO (≥7.0) · SOSPECHOSO (≥6.2) · ELEVADO (≥5.0) · NORMAL (<5.0)

ARGUMENTOS CLAVE (v2.1)
-----------------------
  --threshold FLOAT  Umbral de entropía Shannon (0-8, default: 7.0).
                     Valores >4.5 son sospechosos; >7.0 indican posible cifrado.
  --whitelist FILE   Fichero de texto con paths/nombres a ignorar (uno por línea).
                     Las líneas terminadas en * actúan como prefijos.
                     Si el fichero no existe, emite warning y continúa sin whitelist.

DEPENDENCIAS
------------
  rich     >= 13.7.0  — Salida de consola con formato enriquecido y tablas

AUTORÍA
-------
  © VampSecure Studios — VampSecure Labs Security Research Division
  Todos los derechos reservados. Uso exclusivo en entornos autorizados.
"""

from __future__ import annotations

import argparse
import json
import math
import os
import shutil
import sys
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.table import Table

# ────────────────────────────────────────────────────────────────────────────
# Constantes
# ────────────────────────────────────────────────────────────────────────────

VERSION = "2.2"
TOOL_NAME = "vamp-entropy-watch"

BANNER = r"""
__   ___   __  __ ___  ___ ___ ___ _   _ ___ ___ _      _   ___ ___
\ \ / /_\ |  \/  | _ \/ __| __/ __| | | | _ \ __| |    /_\ | _ ) __|
 \ V / _ \| |\/| |  _/\__ \ _| (__| |_| |   / _|| |__ / _ \| _ \__ \
  \_/_/ \_\_|  |_|_|  |___/___\___|\___/|_|_\___|____/_/ \_\___/___/
  by Antonio Hernandez "Belky" — VampSecure Studios
  vamp-entropy-watch v2.2 · Ransomware Detection via Shannon Entropy
  ────────────────────────────────────────────────────────────────────────
  USO EXCLUSIVO EN AUDITORÍAS AUTORIZADAS · El uso no autorizado es ilegal
"""

# Extensiones que se ignoran por defecto (ya cifradas o binarios)
DEFAULT_IGNORE_EXTS: set[str] = {
    ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".mp3", ".mp4", ".avi",
    ".zip", ".gz", ".7z", ".bz2", ".xz", ".rar", ".tar", ".apk",
    ".exe", ".dll", ".so", ".dylib", ".bin", ".iso", ".dmg",
}

# ────────────────────────────────────────────────────────────────────────────
# Lista embebida de extensiones de ransomware conocidas  (v2.2)
# ────────────────────────────────────────────────────────────────────────────
# Fuente combinada: ID-Ransomware, MalwareHunterTeam, Bleeping Computer,
# Coveware Q3 2026.  Se puede ampliar con --ransomware-feeds-url o con
# un fichero local ~/.config/vamp-entropy-watch/extensions.json
# ────────────────────────────────────────────────────────────────────────────

RANSOMWARE_EXTENSIONS_EMBEBIDAS: set[str] = {
    # WannaCry / WannaCrypt
    ".wnry", ".wcry", ".wncry", ".wncryt",
    # Locky y variantes
    ".locky", ".zepto", ".odin", ".shit", ".thor", ".aesir", ".zzzzz",
    ".osiris", ".loli",
    # Cerber
    ".cerber", ".cerber2", ".cerber3",
    # CryptoWall / CryptoLocker
    ".cryptowall", ".locked", ".encrypted", ".enc", ".crypted", ".crypt",
    ".cry", ".crypto",
    # Dharma y familia CrySis
    ".dharma", ".cezar", ".cesar", ".arena", ".cobra", ".java", ".arrow",
    ".bip", ".monro", ".deal",
    # Extensiones cortas genéricas muy usadas
    ".aaa", ".abc", ".xyz", ".micro", ".ecc", ".ezz", ".exx", ".zzz",
    ".vvv", ".xxx", ".ttt", ".ccc", ".kkk",
    # MedusaLocker / variantes
    ".bkp", ".btc", ".cf",
    # GlobeImposter / Globe
    ".globe", ".purge",
    # Sage
    ".sage",
    # Spora
    ".spora",
    # Petya / NotPetya
    ".petya",
    # Extensiones de ofuscación/cifrado diversas
    ".funk", ".darkness", ".wallet", ".mp3",
    # Variantes con nombres de fichero completos como extensión
    ".chifrator", ".crjoker",
    # Extensiones utilizadas en familias diversas
    ".ctb2", ".ctbl", ".decimnineteen", ".encode", ".fucked",
    ".good", ".helpmeencrypt", ".herbst", ".keybtc", ".kimcilware",
    ".kraken", ".losers", ".magic", ".nochance", ".nuclear55", ".nuke",
    ".nymaim", ".odcodc", ".old", ".omg", ".popup", ".r5a", ".raid10",
    ".rdm", ".restoredfiles", ".rmd", ".rsa", ".ruby", ".serpent",
    ".silent", ".snlck", ".surprise", ".tgz", ".toxcrypt", ".ultra",
    ".v8", ".vaultfile", ".vault", ".wflx", ".wlu", ".x1881", ".xort",
    ".ykcol", ".zcrypt", ".zorro",
    # Extensiones adicionales documentadas (2024-2026)
    ".blackout", ".ryuk", ".conti", ".revil", ".sodinokibi", ".avaddon",
    ".darkside", ".blackcat", ".alphv", ".lockbit", ".play", ".clop",
    ".hive", ".blackbasta", ".medusa", ".akira", ".8base",
    ".encrypt", ".enc1", ".enc2", ".locked1", ".crypted1", ".scrambled",
    ".payfordecrypt", ".readinstructions", ".helpyourdecrypt",
    # Familia Maze / Egregor
    ".maze", ".egregor",
    # Stop/DJVU
    ".djvu", ".stop",
    # MegaCortex
    ".megac0rtex",
}

# Ruta del fichero de extensiones personalizadas (actualizable con --update-ransomware-list)
_RANSOMWARE_EXT_CONFIG_PATH = Path.home() / ".config" / "vamp-entropy-watch" / "extensions.json"


def cargar_extensiones_ransomware(feeds_extra_path: Path | None = None) -> set[str]:
    """
    Carga la lista efectiva de extensiones ransomware.

    Combina la lista embebida RANSOMWARE_EXTENSIONS_EMBEBIDAS con:
      1. El fichero de configuración local (~/.config/vamp-entropy-watch/extensions.json)
         si existe (resultado de --update-ransomware-list previo).
      2. Un fichero adicional pasado como feeds_extra_path (raramente necesario).

    Retorna un set de extensiones en minúsculas con punto inicial.
    """
    extensiones = set(RANSOMWARE_EXTENSIONS_EMBEBIDAS)

    # Cargar desde fichero de configuración local (si existe)
    if _RANSOMWARE_EXT_CONFIG_PATH.exists():
        try:
            datos = _json.loads(_RANSOMWARE_EXT_CONFIG_PATH.read_text(encoding="utf-8"))
            if isinstance(datos, list):
                for ext in datos:
                    ext = str(ext).strip().lower()
                    if not ext.startswith("."):
                        ext = "." + ext
                    extensiones.add(ext)
        except (OSError, _json.JSONDecodeError):
            pass

    # Cargar desde fichero extra si se proporcionó
    if feeds_extra_path and feeds_extra_path.exists():
        try:
            datos = _json.loads(feeds_extra_path.read_text(encoding="utf-8"))
            if isinstance(datos, list):
                for ext in datos:
                    ext = str(ext).strip().lower()
                    if not ext.startswith("."):
                        ext = "." + ext
                    extensiones.add(ext)
        except (OSError, _json.JSONDecodeError):
            pass

    return extensiones


def actualizar_lista_ransomware(feed_url: str) -> bool:
    """
    Descarga un feed JSON de extensiones ransomware y lo guarda en el
    fichero de configuración local para uso futuro.

    El feed debe ser una URL que devuelve una lista JSON de strings (extensiones).
    Ejemplo: ["locked", ".encrypted", ".crypt", ...]

    Parámetros
    ----------
    feed_url : URL del feed JSON de extensiones ransomware

    Retorna True si la actualización fue exitosa, False en caso de error.
    """
    import urllib.request as _ureq

    console.print(f"[cyan]  Descargando feed de extensiones ransomware: {feed_url}[/]")

    try:
        req = _ureq.Request(
            feed_url,
            headers={"User-Agent": f"vamp-entropy-watch/{VERSION}"},
        )
        with _ureq.urlopen(req, timeout=15) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
    except Exception as exc:
        console.print(f"[red]  Error descargando feed: {exc}[/]")
        return False

    try:
        datos = _json.loads(raw)
    except _json.JSONDecodeError as exc:
        console.print(f"[red]  Feed no es JSON válido: {exc}[/]")
        return False

    if not isinstance(datos, list):
        console.print("[red]  El feed debe ser una lista JSON de strings.[/]")
        return False

    # Normalizar extensiones: minúsculas con punto inicial
    normalizadas = []
    for ext in datos:
        ext = str(ext).strip().lower()
        if not ext.startswith("."):
            ext = "." + ext
        normalizadas.append(ext)

    if not normalizadas:
        console.print("[yellow]  Feed descargado pero vacío.[/]")
        return False

    # Guardar en la ruta de configuración
    _RANSOMWARE_EXT_CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    try:
        _RANSOMWARE_EXT_CONFIG_PATH.write_text(
            _json.dumps(normalizadas, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
    except OSError as exc:
        console.print(f"[red]  No se pudo guardar el feed: {exc}[/]")
        return False

    console.print(
        f"[green]  ✔ Feed actualizado: {len(normalizadas)} extensiones guardadas en "
        f"{_RANSOMWARE_EXT_CONFIG_PATH}[/]"
    )
    return True


def verificar_extension_ransomware(file_path: Path, extensiones: set[str]) -> bool:
    """
    Comprueba si la extensión del fichero es una extensión ransomware conocida.

    Compara tanto la extensión simple (fichero.locky → .locky) como la
    extensión doble/compuesta (fichero.pdf.wnry → .wnry).

    Retorna True si la extensión coincide con alguna de las extensiones ransomware.
    """
    nombre = file_path.name.lower()
    # Extensión principal (último punto)
    ext_principal = file_path.suffix.lower()
    if ext_principal in extensiones:
        return True
    # Buscar extensiones compuestas: fichero.pdf.locky → buscar .locky en el nombre
    partes = nombre.split(".")
    if len(partes) >= 2:
        # Probar el último segmento y los últimos dos (para extensiones dobles)
        for n in (1, 2):
            ext_compuesta = "." + ".".join(partes[-n:])
            if ext_compuesta in extensiones:
                return True
    return False


# ────────────────────────────────────────────────────────────────────────────
# Módulo json — importar explícitamente para uso en funciones anteriores
# ────────────────────────────────────────────────────────────────────────────
import json as _json


# Colores por rango de entropía
def _entropy_style(h: float, threshold: float) -> str:
    """Devuelve el estilo Rich según el nivel de entropía."""
    if h >= threshold:
        return "bold red"
    if h >= threshold * 0.88:
        return "orange3"
    if h >= 5.0:
        return "yellow"
    return "green"


def _entropy_label(h: float, threshold: float) -> str:
    """Etiqueta de estado según el nivel de entropía."""
    if h >= threshold:
        return "⚠ ALERTA"
    if h >= threshold * 0.88:
        return "ALTO"
    if h >= 5.0:
        return "MEDIO"
    return "SEGURO"


console = Console()


# ────────────────────────────────────────────────────────────────────────────
# Cálculo de entropía
# ────────────────────────────────────────────────────────────────────────────

def calculate_entropy(file_path: Path, max_bytes: int = 1_048_576) -> float | None:
    """
    Calcula la entropía de Shannon de un fichero (en bits por byte, rango 0-8).

    Lee hasta max_bytes para mantener rendimiento en ficheros grandes.
    Devuelve None si el fichero no es accesible o está vacío.
    """
    try:
        data = file_path.read_bytes()[:max_bytes]
    except (OSError, PermissionError):
        return None

    if not data:
        return 0.0

    counts = [0] * 256
    for byte in data:
        counts[byte] += 1

    total = len(data)
    entropy = 0.0
    for count in counts:
        if count:
            p = count / total
            entropy -= p * math.log2(p)

    return round(entropy, 4)


# ────────────────────────────────────────────────────────────────────────────
# Estado del monitor
# ────────────────────────────────────────────────────────────────────────────

@dataclass
class FileState:
    """Estado de un fichero monitoreado."""
    path: str
    name: str
    entropy: float
    status: str
    quarantined: bool = False
    detected_at: str = ""
    size_bytes: int = 0


class WatchState:
    """Estado global del monitor: tabla de ficheros y estadísticas."""

    def __init__(self, threshold: float):
        self.threshold = threshold
        self.files: dict[str, FileState] = {}
        self.alerts: list[FileState] = []
        self.scanned = 0
        self.quarantined = 0

    def update(self, path: Path, entropy: float, quarantined: bool = False) -> bool:
        """
        Actualiza el estado de un fichero.
        Devuelve True si se trata de una nueva alerta.
        """
        key = str(path)
        status = _entropy_label(entropy, self.threshold)
        is_alert = entropy >= self.threshold
        state = FileState(
            path=key,
            name=path.name,
            entropy=entropy,
            status=status,
            quarantined=quarantined,
            detected_at=datetime.now().strftime("%H:%M:%S"),
            size_bytes=path.stat().st_size if path.exists() else 0,
        )
        new_alert = is_alert and key not in self.files
        self.files[key] = state
        self.scanned += 1
        if is_alert:
            self.alerts.append(state)
        if quarantined:
            self.quarantined += 1
        return new_alert

    def build_table(self) -> Table:
        """Construye la tabla Rich de ficheros monitoreados."""
        t = Table(
            title=f"[bold cyan]Entropy Watch v{VERSION} — Directorio vigilado[/]",
            border_style="cyan",
            show_lines=False,
        )
        t.add_column("Fichero", style="white", width=30)
        t.add_column("Entropía", justify="right", width=10)
        t.add_column("Estado", width=12)
        t.add_column("Tamaño", justify="right", width=10)
        t.add_column("Hora", style="dim", width=10)

        # Mostrar alertas primero, luego por entropía desc
        sorted_files = sorted(
            self.files.values(),
            key=lambda f: (-f.entropy, f.name),
        )
        for s in sorted_files[-30:]:  # límite visual a 30
            style = _entropy_style(s.entropy, self.threshold)
            label = "[bold red]CUARENTENA[/]" if s.quarantined else f"[{style}]{s.status}[/]"
            size_str = f"{s.size_bytes:,}" if s.size_bytes else "—"
            t.add_row(
                s.name[:30],
                f"[{style}]{s.entropy:.4f}[/]",
                label,
                size_str,
                s.detected_at,
            )
        return t

    def build_stats(self) -> Panel:
        """Panel de estadísticas en tiempo real."""
        content = (
            f"Escaneados: [cyan]{self.scanned}[/]  |  "
            f"Alertas: [red]{len(self.alerts)}[/]  |  "
            f"En cuarentena: [yellow]{self.quarantined}[/]  |  "
            f"Umbral: [bold]{self.threshold}[/]  |  "
            f"[dim]{datetime.now().strftime('%H:%M:%S')}[/]"
        )
        return Panel(content, title="[bold cyan]Estado[/]", border_style="cyan")


# ────────────────────────────────────────────────────────────────────────────
# Cuarentena
# ────────────────────────────────────────────────────────────────────────────

def quarantine_file(file_path: Path, quarantine_dir: Path) -> bool:
    """
    Mueve un fichero sospechoso al directorio de cuarentena y lo marca
    como solo-lectura para impedir modificaciones posteriores.

    Devuelve True si el movimiento se realizó con éxito.
    """
    try:
        quarantine_dir.mkdir(parents=True, exist_ok=True)
        dest = quarantine_dir / file_path.name
        # Evitar colisión de nombres
        if dest.exists():
            ts = datetime.now().strftime("%Y%m%d_%H%M%S_")
            dest = quarantine_dir / (ts + file_path.name)
        shutil.move(str(file_path), str(dest))
        os.chmod(dest, 0o444)
        return True
    except Exception:
        return False


# ────────────────────────────────────────────────────────────────────────────
# Modos de operación
# ────────────────────────────────────────────────────────────────────────────

def _collect_files(
    target: Path,
    recursive: bool,
    ignore_exts: set[str],
) -> list[Path]:
    """
    Recolecta todos los ficheros a monitorear según la configuración.
    Excluye extensiones ignoradas y el propio directorio de cuarentena.
    """
    if recursive:
        files = [
            f for f in target.rglob("*")
            if f.is_file() and f.suffix.lower() not in ignore_exts
            and "quarantine" not in str(f)
        ]
    else:
        files = [
            f for f in target.iterdir()
            if f.is_file() and f.suffix.lower() not in ignore_exts
            and "quarantine" not in str(f)
        ]
    return files


def load_whitelist(fichero: str | None) -> list[str]:
    """
    Carga el fichero de whitelist: una entrada por línea.
    Las líneas en blanco o que comiencen por '#' se ignoran.
    Si el fichero no existe emite un warning y devuelve lista vacía.

    Parámetros
    ----------
    fichero : ruta al fichero de whitelist o None

    Retorna
    -------
    List[str] con los patrones cargados (entradas exactas o prefijos con *)
    """
    if not fichero:
        return []
    p = Path(fichero)
    if not p.exists():
        console.print(
            f"[yellow]⚠  Whitelist no encontrada: {fichero}. Continuando sin whitelist.[/]"
        )
        return []
    try:
        lineas = [
            l.strip()
            for l in p.read_text(encoding="utf-8", errors="replace").splitlines()
            if l.strip() and not l.strip().startswith("#")
        ]
        console.print(f"[dim]Whitelist cargada: {len(lineas)} entradas ({fichero})[/]")
        return lineas
    except Exception as exc:
        console.print(
            f"[yellow]⚠  Error leyendo whitelist {fichero}: {exc}. Continuando sin whitelist.[/]"
        )
        return []


def _is_whitelisted(file_path: Path, whitelist: list[str]) -> bool:
    """
    Comprueba si un fichero coincide con alguna entrada del whitelist.

    Reglas de coincidencia:
    - Coincidencia exacta: la entrada iguala la ruta absoluta o el nombre del fichero.
    - Prefijo: si la entrada termina en '*', se comprueba que la ruta o el nombre
      empiece por el prefijo (sin el '*').

    Parámetros
    ----------
    file_path : Path del fichero a comprobar
    whitelist : lista de patrones cargada con load_whitelist()

    Retorna
    -------
    True si el fichero debe ignorarse, False en caso contrario.
    """
    if not whitelist:
        return False
    path_str = str(file_path)
    name_str = file_path.name
    for entry in whitelist:
        if entry.endswith("*"):
            prefix = entry[:-1]
            if path_str.startswith(prefix) or name_str.startswith(prefix):
                return True
        else:
            if path_str == entry or name_str == entry:
                return True
    return False


def mode_monitor(
    target: Path,
    threshold: float,
    quarantine_dir: Path | None,
    recursive: bool,
    ignore_exts: set[str],
    interval: float,
    whitelist: list[str] | None = None,
) -> None:
    """
    Modo vigilancia continua. Bucle infinito que detecta ficheros nuevos
    o modificados y calcula su entropía en cada iteración.
    """
    if whitelist is None:
        whitelist = []
    state = WatchState(threshold)
    known_mtimes: dict[str, float] = {}

    console.print(Panel(
        f"Directorio: [bold]{target.resolve()}[/]\n"
        f"Umbral:     [bold yellow]{threshold}[/]\n"
        f"Recursivo:  {'Sí' if recursive else 'No'}\n"
        f"Cuarentena: {str(quarantine_dir) if quarantine_dir else 'Desactivada'}\n"
        f"Intervalo:  {interval}s",
        title=f"[bold cyan]Entropy Watch v{VERSION}[/]",
        border_style="cyan",
    ))

    with Live(state.build_table(), console=console, refresh_per_second=2) as live:
        try:
            while True:
                files = _collect_files(target, recursive, ignore_exts)
                for f in files:
                    try:
                        mtime = f.stat().st_mtime
                    except FileNotFoundError:
                        continue

                    key = str(f)
                    if key not in known_mtimes or known_mtimes[key] != mtime:
                        known_mtimes[key] = mtime
                        h = calculate_entropy(f)
                        if h is None:
                            continue

                        # Ignorar ficheros de alta entropía que están en la whitelist
                        if h >= threshold and _is_whitelisted(f, whitelist):
                            continue

                        do_quarantine = False
                        if h >= threshold and quarantine_dir:
                            do_quarantine = quarantine_file(f, quarantine_dir)

                        state.update(f, h, quarantined=do_quarantine)

                live.update(state.build_table())
                time.sleep(interval)
        except KeyboardInterrupt:
            pass

    console.print(state.build_stats())
    console.print("\n[bold cyan]Monitor detenido.[/]")
    return state


def mode_scan(
    target: Path,
    threshold: float,
    recursive: bool,
    ignore_exts: set[str],
    output_json: str | None,
    whitelist: list[str] | None = None,
    extensiones_ransomware: set[str] | None = None,
) -> None:
    """
    Modo escaneo único. Procesa todos los ficheros y genera un informe.
    No realiza acciones de cuarentena (solo análisis).

    Si extensiones_ransomware no es None, los ficheros de alta entropía cuya
    extensión coincide con la lista reciben severidad CRITICAL y el hallazgo
    adicional RANSOMWARE_EXTENSION_MATCH.
    """
    if whitelist is None:
        whitelist = []
    if extensiones_ransomware is None:
        extensiones_ransomware = set()

    files = _collect_files(target, recursive, ignore_exts)
    console.print(f"Escaneando [cyan]{len(files)}[/] ficheros...\n")

    state = WatchState(threshold)
    results = []

    with console.status("[cyan]Calculando entropía...[/]", spinner="dots"):
        for f in files:
            h = calculate_entropy(f)
            if h is None:
                continue
            # Ignorar ficheros de alta entropía que están en la whitelist
            if h >= threshold and _is_whitelisted(f, whitelist):
                continue

            # Verificar si la extensión coincide con extensiones de ransomware conocidas
            es_ransomware = (
                h >= threshold and
                extensiones_ransomware and
                verificar_extension_ransomware(f, extensiones_ransomware)
            )

            state.update(f, h)
            entrada = {
                "path": str(f),
                "name": f.name,
                "entropy": h,
                "status": _entropy_label(h, threshold),
                "size_bytes": f.stat().st_size if f.exists() else 0,
            }

            # Escalar a CRITICAL y añadir hallazgo RANSOMWARE_EXTENSION_MATCH
            if es_ransomware:
                entrada["ransomware_extension_match"] = True
                entrada["status"] = "⚠ RANSOMWARE"
                console.print(
                    f"  [bold red]RANSOMWARE_EXTENSION_MATCH[/]: {f.name} "
                    f"(entropía={h:.3f}, ext={f.suffix})"
                )

            results.append(entrada)

    console.print(state.build_table())
    console.print(state.build_stats())

    # Resumen de coincidencias ransomware
    n_ransomware = sum(1 for r in results if r.get("ransomware_extension_match"))
    if n_ransomware:
        console.print(
            f"\n[bold red]⚠ {n_ransomware} fichero(s) con extensión de ransomware conocida "
            f"(RANSOMWARE_EXTENSION_MATCH)[/]"
        )

    if output_json:
        payload = {
            "tool": TOOL_NAME,
            "version": VERSION,
            "scan_time": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
            "target": str(target.resolve()),
            "threshold": threshold,
            "total_scanned": len(results),
            "alerts": sum(1 for r in results if r["entropy"] >= threshold),
            "ransomware_matches": n_ransomware,
            "files": sorted(results, key=lambda r: -r["entropy"]),
        }
        Path(output_json).write_text(json.dumps(payload, indent=2), encoding="utf-8")
        console.print(f"\n[green]✔ JSON guardado en {output_json}[/]")

    return results


# ────────────────────────────────────────────────────────────────────────────
# CLI
# ────────────────────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    """Construye el parser de argumentos con subcomandos monitor / scan."""
    p = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description=f"VampSecure Labs Entropy Watch v{VERSION} — Detector de ransomware por entropía",
    )
    subs = p.add_subparsers(dest="mode", metavar="modo")
    subs.required = True

    # Subcomando monitor
    mon = subs.add_parser("monitor", help="Vigilancia continua de un directorio")
    mon.add_argument("-p", "--path", default=".", metavar="DIR",
                     help="Directorio a vigilar (default: .)")
    mon.add_argument("--threshold", type=float, default=7.0, metavar="FLOAT",
                     help="Umbral de entropía Shannon (0-8, default: 7.0). "
                          "Valores >4.5 son sospechosos; >7.0 indican posible cifrado.")
    mon.add_argument("--whitelist", metavar="FILE", default=None,
                     help="Fichero con paths/nombres a ignorar aunque superen el umbral "
                          "(uno por línea; líneas con * actúan como prefijo). "
                          "Si el fichero no existe se emite warning y se continúa.")
    mon.add_argument("--quarantine", metavar="DIR",
                     help="Directorio de cuarentena (default: <path>/quarantine)")
    mon.add_argument("--no-quarantine", action="store_true",
                     help="Desactivar cuarentena automática")
    mon.add_argument("--recursive", "-r", action="store_true",
                     help="Vigilar subdirectorios recursivamente")
    mon.add_argument("--interval", type=float, default=2.0, metavar="SEG",
                     help="Intervalo de polling en segundos (default: 2.0)")

    # Subcomando scan
    scn = subs.add_parser("scan", help="Escaneo único sin bucle")
    scn.add_argument("-p", "--path", default=".", metavar="DIR",
                     help="Directorio a escanear (default: .)")
    scn.add_argument("--threshold", type=float, default=7.0, metavar="FLOAT",
                     help="Umbral de entropía Shannon (0-8, default: 7.0). "
                          "Valores >4.5 son sospechosos; >7.0 indican posible cifrado.")
    scn.add_argument("--whitelist", metavar="FILE", default=None,
                     help="Fichero con paths/nombres a ignorar aunque superen el umbral "
                          "(uno por línea; líneas con * actúan como prefijo). "
                          "Si el fichero no existe se emite warning y se continúa.")
    scn.add_argument("--recursive", "-r", action="store_true",
                     help="Escanear subdirectorios recursivamente")
    scn.add_argument("-o", "--output", metavar="FILE",
                     help="Guardar resultado en JSON")

    # Correlación con extensiones ransomware (v2.2) — disponible en ambos modos
    for sub in (mon, scn):
        sub.add_argument(
            "--ransomware-feeds-url",
            metavar="URL",
            default=None,
            dest="ransomware_feeds_url",
            help=(
                "URL de feed JSON externo con extensiones ransomware (lista de strings). "
                "Si se especifica, amplía la lista embebida para este escaneo."
            ),
        )
        sub.add_argument(
            "--update-ransomware-list",
            action="store_true",
            dest="update_ransomware_list",
            help=(
                "Descargar el feed de --ransomware-feeds-url y guardarlo en "
                "~/.config/vamp-entropy-watch/extensions.json para uso futuro. "
                "Requiere --ransomware-feeds-url."
            ),
        )
        sub.add_argument(
            "--no-ransomware-check",
            action="store_true",
            dest="no_ransomware_check",
            help="Deshabilitar la correlación de extensiones ransomware conocidas.",
        )

    # Argumentos de informe unificado VSL (--client, --engagement, --auditor,
    # --report-scope, --report-html, --report-pdf) — disponibles en ambos modos
    from vampsec_report import add_report_args
    add_report_args(mon)
    add_report_args(scn)

    return p


# =============================================================================
# CONVERSOR A FORMATO DE INFORME UNIFICADO VSL
# =============================================================================

def _findings_vsl(items: list, threshold: float, target: str) -> list:
    """
    Convierte ficheros de alta entropía al formato Finding unificado de VampSecure Labs.

    Acepta tanto la lista de dicts de mode_scan como la lista de FileState de monitor.
    Solo se incluyen ficheros cuya entropía supera el umbral configurado.

    Parámetros
    ----------
    items     : list  — Lista de dicts (scan) o FileState (monitor) con entropy
    threshold : float — Umbral de entropía configurado en la sesión
    target    : str   — Directorio raíz analizado

    Retorna
    -------
    List[Finding]  — Lista de hallazgos en formato VSL con prefijo ENT-NNN
    """
    from vampsec_report import Finding as VSLFinding

    hallazgos: list = []
    n = 0

    # Normalizar a dicts con claves homogéneas
    normalized = []
    for item in items:
        if isinstance(item, dict):
            normalized.append(item)
        else:
            # FileState dataclass → dict equivalente
            normalized.append({
                "path": item.path,
                "name": item.name,
                "entropy": item.entropy,
                "status": item.status,
                "size_bytes": item.size_bytes,
                "quarantined": item.quarantined,
                "detected_at": item.detected_at,
            })

    # Solo alertas reales (por encima del umbral)
    alertas = [r for r in normalized if r.get("entropy", 0) >= threshold]

    for r in sorted(alertas, key=lambda x: -x.get("entropy", 0)):
        n += 1
        ent = r.get("entropy", 0.0)

        # Severidad según nivel de entropía por encima del umbral
        if ent >= 7.8:
            severidad = "CRITICAL"
        elif ent >= 7.4:
            severidad = "HIGH"
        else:
            severidad = "MEDIUM"

        # Ruta relativa
        try:
            ruta_rel = str(Path(r["path"]).relative_to(target))
        except ValueError:
            ruta_rel = r["path"]

        partes_evidencia = [
            f"Entropía: {ent:.4f} bits/símbolo (umbral: {threshold})",
            f"Fichero: {ruta_rel}",
        ]
        if r.get("size_bytes"):
            partes_evidencia.append(f"Tamaño: {r['size_bytes'] / 1024:.1f} KB")
        if r.get("quarantined"):
            partes_evidencia.append("CUARENTENA ACTIVA")
        if r.get("detected_at"):
            partes_evidencia.append(f"Detectado: {r['detected_at']}")

        hallazgos.append(VSLFinding(
            id          = f"ENT-{n:03d}",
            title       = f"Fichero de alta entropía: {r.get('name', ruta_rel)}",
            severity    = severidad,
            description = (
                f"El fichero '{ruta_rel}' presenta una entropía de {ent:.4f} bits/símbolo, "
                f"superior al umbral configurado de {threshold}. "
                "Una entropía elevada puede indicar cifrado no autorizado (ransomware), "
                "datos comprimidos no declarados, o contenido ofuscado."
            ),
            evidence    = " | ".join(partes_evidencia),
            affected    = ruta_rel,
            remediation = (
                "Verificar que el cifrado del fichero es legítimo y autorizado. "
                "Si el fichero ha sido cifrado por ransomware, restaurar desde backup, "
                "aislar el sistema y analizar el vector de entrada. "
                "Activar monitorización de integridad de ficheros (FIM) para detectar cambios futuros."
            ),
            tags        = ["entropy", "ransomware-detection", severidad.lower()],
        ))

    return hallazgos


def main() -> None:
    """Punto de entrada principal."""
    console.print(BANNER.format(version=VERSION), style="bold cyan")

    parser = build_parser()
    args = parser.parse_args()

    target = Path(args.path).resolve()
    if not target.exists():
        console.print(f"[red]ERROR: Directorio no existe: {target}[/]")
        sys.exit(1)
    if not target.is_dir():
        console.print(f"[red]ERROR: No es un directorio: {target}[/]")
        sys.exit(1)

    # Cargar whitelist (común a ambos modos)
    wl = load_whitelist(getattr(args, "whitelist", None))

    # ── Gestión de extensiones ransomware  (v2.2) ────────────────────────────
    _feeds_url             = getattr(args, "ransomware_feeds_url", None)
    _actualizar_lista      = getattr(args, "update_ransomware_list", False)
    _sin_check_ransomware  = getattr(args, "no_ransomware_check", False)

    # Si se pide actualizar la lista, descargar y guardar, luego salir
    if _actualizar_lista:
        if not _feeds_url:
            console.print(
                "[red]  --update-ransomware-list requiere --ransomware-feeds-url[/]"
            )
            sys.exit(1)
        exito = actualizar_lista_ransomware(_feeds_url)
        sys.exit(0 if exito else 1)

    # Cargar extensiones efectivas (embebidas + fichero local + feed extra si hay URL)
    _feeds_extra_path: Path | None = None
    if _feeds_url and not _sin_check_ransomware:
        # Descargar feed temporalmente para este escaneo (no guardar en disco)
        import urllib.request as _ureq
        try:
            req = _ureq.Request(
                _feeds_url,
                headers={"User-Agent": f"vamp-entropy-watch/{VERSION}"},
            )
            with _ureq.urlopen(req, timeout=15) as _resp:
                _raw = _resp.read().decode("utf-8", errors="replace")
            import json as _json_tmp
            _datos_feed = _json_tmp.loads(_raw)
            if isinstance(_datos_feed, list):
                import tempfile as _tmp
                _tf = _tmp.NamedTemporaryFile(
                    mode="w", suffix=".json", delete=False, encoding="utf-8"
                )
                _json_tmp.dump(_datos_feed, _tf)
                _tf.close()
                _feeds_extra_path = Path(_tf.name)
                console.print(
                    f"[dim]  Feed ransomware descargado: {len(_datos_feed)} extensiones[/]"
                )
        except Exception as exc:
            console.print(f"[yellow]  Aviso: no se pudo descargar el feed ransomware: {exc}[/]")

    # Cargar extensiones efectivas
    _extensiones_ransomware: set[str] | None = None
    if not _sin_check_ransomware:
        _extensiones_ransomware = cargar_extensiones_ransomware(_feeds_extra_path)
        console.print(
            f"[dim]  Extensiones ransomware cargadas: {len(_extensiones_ransomware)}[/]"
        )

    if args.mode == "monitor":
        if getattr(args, "no_quarantine", False):
            q_dir = None
        elif getattr(args, "quarantine", None):
            q_dir = Path(args.quarantine)
        else:
            q_dir = target / "quarantine"

        state = mode_monitor(
            target=target,
            threshold=args.threshold,
            quarantine_dir=q_dir,
            recursive=args.recursive,
            ignore_exts=DEFAULT_IGNORE_EXTS,
            interval=args.interval,
            whitelist=wl,
        )

        # ── Informe unificado VSL (cliente) ───────────────────────────────────
        if getattr(args, "report_html", None) or getattr(args, "report_pdf", None):
            from vampsec_report import VampSecReport, meta_from_args
            meta   = meta_from_args(args, tool="vamp-entropy-watch", version=VERSION)
            report = VampSecReport(
                meta=meta,
                findings=_findings_vsl(state.alerts, args.threshold, str(target)),
            )
            if args.report_html:
                report.to_html_client(args.report_html)
                console.print(f"[bold green]✔ Informe cliente HTML guardado: {args.report_html}[/]")
            if args.report_pdf:
                report.to_pdf(args.report_pdf)
                console.print(f"[bold green]✔ Informe cliente PDF guardado: {args.report_pdf}[/]")

    elif args.mode == "scan":
        results = mode_scan(
            target=target,
            threshold=args.threshold,
            recursive=args.recursive,
            ignore_exts=DEFAULT_IGNORE_EXTS,
            output_json=getattr(args, "output", None),
            whitelist=wl,
            extensiones_ransomware=_extensiones_ransomware,
        )

        # ── Informe unificado VSL (cliente) ───────────────────────────────────
        if getattr(args, "report_html", None) or getattr(args, "report_pdf", None):
            from vampsec_report import VampSecReport, meta_from_args
            meta   = meta_from_args(args, tool="vamp-entropy-watch", version=VERSION)
            report = VampSecReport(
                meta=meta,
                findings=_findings_vsl(results or [], args.threshold, str(target)),
            )
            if args.report_html:
                report.to_html_client(args.report_html)
                console.print(f"[bold green]✔ Informe cliente HTML guardado: {args.report_html}[/]")
            if args.report_pdf:
                report.to_pdf(args.report_pdf)
                console.print(f"[bold green]✔ Informe cliente PDF guardado: {args.report_pdf}[/]")


if __name__ == "__main__":
    main()
