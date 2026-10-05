# © VampSecure Studios — VampSecure Labs Security Research Division
"""
conftest.py — Fixtures compartidas para los tests de vamp-entropy-watch.

Proporciona ficheros de prueba de alta y baja entropía, la función helper
entropia_shannon, y configuraciones para test_unit.py y test_integration.py.
"""

import os
import math
import pytest
from pathlib import Path


# ── Helper de entropía de Shannon (referencia independiente) ─────────────────

def entropia_shannon(data: bytes) -> float:
    """
    Calcula la entropía de Shannon de una secuencia de bytes.
    H(X) = -Σ P(xᵢ) · log₂ P(xᵢ)
    Rango [0, 8] bits/byte.
    """
    if not data:
        return 0.0
    counts = [0] * 256
    for byte in data:
        counts[byte] += 1
    total = len(data)
    entropia = 0.0
    for count in counts:
        if count:
            p = count / total
            entropia -= p * math.log2(p)
    return entropia


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture
def fichero_alta_entropia(tmp_path):
    """
    Crea un fichero de 1024 bytes con datos aleatorios (entropía ~7.9-8.0).
    Simula un fichero cifrado por ransomware.
    """
    ruta = tmp_path / "cifrado.bin"
    ruta.write_bytes(os.urandom(1024))
    return ruta


@pytest.fixture
def fichero_baja_entropia(tmp_path):
    """
    Crea un fichero de texto con contenido repetitivo (entropía <3.0).
    Simula un fichero de texto plano legítimo.
    """
    ruta = tmp_path / "texto.txt"
    # Texto muy repetitivo → entropía baja
    contenido = ("aaaa bbbb cccc dddd \n" * 200).encode("utf-8")
    ruta.write_bytes(contenido)
    return ruta


@pytest.fixture
def fichero_vacio(tmp_path):
    """Fichero completamente vacío — debe devolver 0.0."""
    ruta = tmp_path / "vacio.bin"
    ruta.write_bytes(b"")
    return ruta


@pytest.fixture
def fichero_uniforme(tmp_path):
    """
    Fichero con todos los bytes distintos y uniformemente distribuidos
    (distribución uniforme exacta → entropía máxima = 8.0).
    """
    ruta = tmp_path / "uniforme.bin"
    # 256 bytes, uno por cada valor posible → distribución completamente uniforme
    datos = bytes(range(256))
    ruta.write_bytes(datos)
    return ruta


@pytest.fixture
def directorio_con_ficheros(tmp_path):
    """
    Directorio con varios ficheros de distinto tipo de entropía:
    - cifrado.bin  → alta entropía (random)
    - texto.txt    → baja entropía
    - codigo.py    → entropía media
    - imagen.jpg   → excluido por DEFAULT_IGNORE_EXTS
    """
    (tmp_path / "cifrado.enc").write_bytes(os.urandom(2048))
    (tmp_path / "texto.txt").write_bytes(b"hola mundo " * 500)
    (tmp_path / "codigo.py").write_bytes(
        b"import os\nimport sys\ndef main():\n    pass\n" * 50
    )
    # Este fichero debe ser ignorado por DEFAULT_IGNORE_EXTS
    (tmp_path / "imagen.jpg").write_bytes(os.urandom(512))
    return tmp_path


@pytest.fixture
def directorio_con_ransomware(tmp_path):
    """
    Directorio con un fichero con extensión ransomware conocida y alta entropía.
    """
    # Fichero .locky con datos aleatorios
    (tmp_path / "documento.pdf.locky").write_bytes(os.urandom(1024))
    # Fichero .txt normal
    (tmp_path / "readme.txt").write_bytes(b"instrucciones de descifrado")
    return tmp_path
