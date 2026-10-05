# © VampSecure Studios — VampSecure Labs Security Research Division
"""
test_integration.py — Tests de integración para vamp-entropy-watch.

Pruebas de extremo a extremo sobre directorios reales: se crean en tmp_path,
se ejecuta mode_scan y se comprueban los resultados completos.
Mínimo 5 tests de integración.
"""

import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from vamp_entropy_watch import (
    DEFAULT_IGNORE_EXTS,
    RANSOMWARE_EXTENSIONS_EMBEBIDAS,
    mode_scan,
)

# ─────────────────────────────────────────────────────────────────────────────
# 1. Integración: mode_scan detecta fichero de alta entropía
# ─────────────────────────────────────────────────────────────────────────────

def test_integracion_scan_detecta_fichero_cifrado(directorio_con_ficheros):
    """
    mode_scan sobre un directorio con un .bin aleatorio debe generar
    al menos un resultado con entropía > umbral y status '⚠ ALERTA'.
    """
    resultados = mode_scan(
        target=directorio_con_ficheros,
        threshold=7.0,
        recursive=False,
        ignore_exts=DEFAULT_IGNORE_EXTS,
        output_json=None,
        whitelist=[],
    )

    assert resultados is not None
    # Debe haber al menos un fichero con status ALERTA (cifrado.bin es random)
    alertas = [r for r in resultados if r["entropy"] >= 7.0]
    assert len(alertas) >= 1, (
        "Se esperaba al menos un fichero con entropía >= 7.0 "
        f"(random). Resultados: {[r['name'] for r in resultados]}"
    )


# ─────────────────────────────────────────────────────────────────────────────
# 2. Integración: DEFAULT_IGNORE_EXTS excluye .jpg del escaneo
# ─────────────────────────────────────────────────────────────────────────────

def test_integracion_scan_excluye_jpg(directorio_con_ficheros):
    """
    mode_scan no debe devolver resultados de imagen.jpg (está en DEFAULT_IGNORE_EXTS).
    """
    resultados = mode_scan(
        target=directorio_con_ficheros,
        threshold=7.0,
        recursive=False,
        ignore_exts=DEFAULT_IGNORE_EXTS,
        output_json=None,
        whitelist=[],
    )

    nombres = [r["name"] for r in resultados]
    assert "imagen.jpg" not in nombres, (
        "imagen.jpg no debería estar en los resultados (está en DEFAULT_IGNORE_EXTS)"
    )


# ─────────────────────────────────────────────────────────────────────────────
# 3. Integración: mode_scan exporta JSON correcto
# ─────────────────────────────────────────────────────────────────────────────

def test_integracion_scan_exporta_json(directorio_con_ficheros, tmp_path):
    """
    Con output_json, mode_scan escribe un JSON bien formado con las claves
    obligatorias: tool, version, threshold, total_scanned, alerts, files.
    """
    salida = tmp_path / "resultado.json"

    mode_scan(
        target=directorio_con_ficheros,
        threshold=7.0,
        recursive=False,
        ignore_exts=DEFAULT_IGNORE_EXTS,
        output_json=str(salida),
        whitelist=[],
    )

    assert salida.exists(), "El fichero JSON de salida no fue creado"
    with open(str(salida), encoding="utf-8") as f:
        datos = json.load(f)

    # Claves obligatorias
    assert "tool" in datos
    assert "version" in datos
    assert "threshold" in datos
    assert "total_scanned" in datos
    assert "alerts" in datos
    assert "files" in datos
    # Los ficheros deben estar ordenados por entropía descendente
    entropias = [r["entropy"] for r in datos["files"]]
    assert entropias == sorted(entropias, reverse=True)


# ─────────────────────────────────────────────────────────────────────────────
# 4. Integración: whitelist excluye fichero del análisis
# ─────────────────────────────────────────────────────────────────────────────

def test_integracion_scan_whitelist_excluye_fichero(tmp_path):
    """
    Un fichero de alta entropía incluido en la whitelist no debe aparecer
    en los resultados con status ALERTA.
    """
    # Fichero de alta entropía que pondremos en whitelist
    fichero_wl = tmp_path / "autorizado.bin"
    fichero_wl.write_bytes(os.urandom(1024))

    # Otro fichero normal
    (tmp_path / "normal.txt").write_bytes(b"texto plano normal " * 100)

    whitelist = [str(fichero_wl)]

    resultados = mode_scan(
        target=tmp_path,
        threshold=7.0,
        recursive=False,
        ignore_exts=DEFAULT_IGNORE_EXTS,
        output_json=None,
        whitelist=whitelist,
    )

    # autorizado.bin no debe estar en las alertas (está en whitelist)
    nombres_alertas = [
        r["name"] for r in resultados if r.get("entropy", 0) >= 7.0
    ]
    assert "autorizado.bin" not in nombres_alertas, (
        "El fichero en whitelist no debe aparecer como alerta"
    )


# ─────────────────────────────────────────────────────────────────────────────
# 5. Integración: detección de extensión ransomware
# ─────────────────────────────────────────────────────────────────────────────

def test_integracion_scan_detecta_extension_ransomware(directorio_con_ransomware):
    """
    Un fichero .locky con alta entropía en el directorio debe recibir el
    campo ransomware_extension_match=True en el resultado.
    """
    resultados = mode_scan(
        target=directorio_con_ransomware,
        threshold=7.0,
        recursive=False,
        ignore_exts=DEFAULT_IGNORE_EXTS,
        output_json=None,
        whitelist=[],
        extensiones_ransomware=RANSOMWARE_EXTENSIONS_EMBEBIDAS,
    )

    # El fichero .locky (con datos random) debe tener ransomware_extension_match
    ransomware_hits = [r for r in resultados if r.get("ransomware_extension_match")]
    assert len(ransomware_hits) >= 1, (
        "Se esperaba al menos un hallazgo RANSOMWARE_EXTENSION_MATCH "
        f"para documento.pdf.locky. Resultados: {[r['name'] for r in resultados]}"
    )
    assert ransomware_hits[0]["name"].endswith(".locky")


# ─────────────────────────────────────────────────────────────────────────────
# 6. Integración: directorio vacío → 0 resultados
# ─────────────────────────────────────────────────────────────────────────────

def test_integracion_scan_directorio_vacio(tmp_path):
    """
    mode_scan sobre un directorio vacío no debe lanzar error y debe
    devolver una lista vacía.
    """
    resultados = mode_scan(
        target=tmp_path,
        threshold=7.0,
        recursive=False,
        ignore_exts=DEFAULT_IGNORE_EXTS,
        output_json=None,
        whitelist=[],
    )

    assert resultados is not None
    assert len(resultados) == 0


# ─────────────────────────────────────────────────────────────────────────────
# 7. Integración: modo recursivo incluye subdirectorios
# ─────────────────────────────────────────────────────────────────────────────

def test_integracion_scan_recursivo(tmp_path):
    """
    Con recursive=True, mode_scan debe incluir ficheros en subdirectorios.
    """
    subdir = tmp_path / "subdir"
    subdir.mkdir()
    (subdir / "cifrado_sub.enc").write_bytes(os.urandom(512))
    (tmp_path / "raiz.txt").write_bytes(b"texto " * 100)

    resultados_no_recursivo = mode_scan(
        target=tmp_path,
        threshold=7.0,
        recursive=False,
        ignore_exts=DEFAULT_IGNORE_EXTS,
        output_json=None,
        whitelist=[],
    )

    resultados_recursivo = mode_scan(
        target=tmp_path,
        threshold=7.0,
        recursive=True,
        ignore_exts=DEFAULT_IGNORE_EXTS,
        output_json=None,
        whitelist=[],
    )

    nombres_no_rec = [r["name"] for r in resultados_no_recursivo]
    nombres_rec = [r["name"] for r in resultados_recursivo]

    assert "cifrado_sub.enc" not in nombres_no_rec, (
        "Sin recursivo no debe incluir ficheros del subdirectorio"
    )
    assert "cifrado_sub.enc" in nombres_rec, (
        "Con recursivo debe incluir ficheros del subdirectorio"
    )
