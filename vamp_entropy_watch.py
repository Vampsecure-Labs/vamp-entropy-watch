#!/usr/bin/env python3
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
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Set

from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

# ────────────────────────────────────────────────────────────────────────────
# Constantes
# ────────────────────────────────────────────────────────────────────────────

VERSION = "2.0"
TOOL_NAME = "vamp-entropy-watch"

BANNER = r"""
  ____   ____    _    __  __ ____  _____ ____ _   _ ____  _____   _        _    ____ ____
 \ \ / / _  |  / \  |  \/  |  _ \/ ____/ ___| | | |  _ \| ____| | |      / \  | __ ) ___|
  \ V / (_| | / _ \ | |\/| | |_) \___ \| |___| | | | |_) |  _|   | |     / _ \ |  _ \___ \
   | |  \__, |/ ___ \| |  | |  __/ ___) |___  | |_| |  _ <| |___  | |___ / ___ \| |_) |__) |
   |_|     /_/_/   \_|_|  |_|_|   |____/\____|\___/|_| \_|_____| |_____/_/   \_|____/____/
     by VampSecure Studios · vamp-entropy-watch v2.0 · Ransomware Detection via Shannon Entropy
     ─────────────────────────────────────────────────────────────────────────────────────────
     USO EXCLUSIVO EN AUDITORÍAS AUTORIZADAS · El uso no autorizado es ilegal
"""

# Extensiones que se ignoran por defecto (ya cifradas o binarios)
DEFAULT_IGNORE_EXTS: Set[str] = {
    ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".mp3", ".mp4", ".avi",
    ".zip", ".gz", ".7z", ".bz2", ".xz", ".rar", ".tar", ".apk",
    ".exe", ".dll", ".so", ".dylib", ".bin", ".iso", ".dmg",
}

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

def calculate_entropy(file_path: Path, max_bytes: int = 1_048_576) -> Optional[float]:
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
        self.files: Dict[str, FileState] = {}
        self.alerts: List[FileState] = []
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
    ignore_exts: Set[str],
) -> List[Path]:
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


def mode_monitor(
    target: Path,
    threshold: float,
    quarantine_dir: Optional[Path],
    recursive: bool,
    ignore_exts: Set[str],
    interval: float,
) -> None:
    """
    Modo vigilancia continua. Bucle infinito que detecta ficheros nuevos
    o modificados y calcula su entropía en cada iteración.
    """
    state = WatchState(threshold)
    known_mtimes: Dict[str, float] = {}

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


def mode_scan(
    target: Path,
    threshold: float,
    recursive: bool,
    ignore_exts: Set[str],
    output_json: Optional[str],
) -> None:
    """
    Modo escaneo único. Procesa todos los ficheros y genera un informe.
    No realiza acciones de cuarentena (solo análisis).
    """
    files = _collect_files(target, recursive, ignore_exts)
    console.print(f"Escaneando [cyan]{len(files)}[/] ficheros...\n")

    state = WatchState(threshold)
    results = []

    with console.status("[cyan]Calculando entropía...[/]", spinner="dots"):
        for f in files:
            h = calculate_entropy(f)
            if h is None:
                continue
            state.update(f, h)
            results.append({
                "path": str(f),
                "name": f.name,
                "entropy": h,
                "status": _entropy_label(h, threshold),
                "size_bytes": f.stat().st_size if f.exists() else 0,
            })

    console.print(state.build_table())
    console.print(state.build_stats())

    if output_json:
        payload = {
            "tool": TOOL_NAME,
            "version": VERSION,
            "scan_time": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
            "target": str(target.resolve()),
            "threshold": threshold,
            "total_scanned": len(results),
            "alerts": sum(1 for r in results if r["entropy"] >= threshold),
            "files": sorted(results, key=lambda r: -r["entropy"]),
        }
        Path(output_json).write_text(json.dumps(payload, indent=2), encoding="utf-8")
        console.print(f"\n[green]✔ JSON guardado en {output_json}[/]")


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
                     help="Umbral de entropía para alerta (default: 7.0)")
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
                     help="Umbral de entropía (default: 7.0)")
    scn.add_argument("--recursive", "-r", action="store_true",
                     help="Escanear subdirectorios recursivamente")
    scn.add_argument("-o", "--output", metavar="FILE",
                     help="Guardar resultado en JSON")

    return p


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

    if args.mode == "monitor":
        if getattr(args, "no_quarantine", False):
            q_dir = None
        elif getattr(args, "quarantine", None):
            q_dir = Path(args.quarantine)
        else:
            q_dir = target / "quarantine"

        mode_monitor(
            target=target,
            threshold=args.threshold,
            quarantine_dir=q_dir,
            recursive=args.recursive,
            ignore_exts=DEFAULT_IGNORE_EXTS,
            interval=args.interval,
        )

    elif args.mode == "scan":
        mode_scan(
            target=target,
            threshold=args.threshold,
            recursive=args.recursive,
            ignore_exts=DEFAULT_IGNORE_EXTS,
            output_json=getattr(args, "output", None),
        )


if __name__ == "__main__":
    main()
