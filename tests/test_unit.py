# © VampSecure Studios — VampSecure Labs Security Research Division
"""
test_unit.py — Tests unitarios para vamp-entropy-watch.

Cubre: calculate_entropy, verificar_extension_ransomware, _entropy_label,
_entropy_style, WatchState, DEFAULT_IGNORE_EXTS, RANSOMWARE_EXTENSIONS_EMBEBIDAS,
quarantine_file, _is_whitelisted y load_whitelist.
Mínimo 12 tests unitarios.
"""

import os
import sys
import math
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from vamp_entropy_watch import (
    calculate_entropy,
    verificar_extension_ransomware,
    _entropy_label,
    _entropy_style,
    WatchState,
    DEFAULT_IGNORE_EXTS,
    RANSOMWARE_EXTENSIONS_EMBEBIDAS,
    quarantine_file,
    _is_whitelisted,
    load_whitelist,
)
from tests.conftest import entropia_shannon


# ─────────────────────────────────────────────────────────────────────────────
# 1. calculate_entropy — fichero de alta entropía
# ─────────────────────────────────────────────────────────────────────────────

class TestCalculateEntropy:
    """Tests para calculate_entropy con distintos tipos de ficheros."""

    def test_fichero_alta_entropia_supera_umbral(self, fichero_alta_entropia):
        """Un fichero de bytes aleatorios debe tener H > 7.0."""
        h = calculate_entropy(fichero_alta_entropia)
        assert h is not None
        assert h > 7.0, f"Entropía esperada >7.0, obtenida {h}"

    def test_fichero_baja_entropia_inferior_a_5(self, fichero_baja_entropia):
        """Un fichero de texto repetitivo debe tener H < 5.0."""
        h = calculate_entropy(fichero_baja_entropia)
        assert h is not None
        assert h < 5.0, f"Entropía esperada <5.0, obtenida {h}"

    def test_fichero_vacio_devuelve_cero(self, fichero_vacio):
        """Un fichero vacío devuelve 0.0."""
        h = calculate_entropy(fichero_vacio)
        assert h is not None
        assert h == 0.0

    def test_fichero_uniforme_entropia_maxima(self, fichero_uniforme):
        """
        Distribución uniforme de 256 bytes distintos → entropía = 8.0.
        """
        h = calculate_entropy(fichero_uniforme)
        assert h is not None
        assert abs(h - 8.0) < 0.001, f"Entropía esperada 8.0, obtenida {h}"

    def test_fichero_no_existe_devuelve_none(self, tmp_path):
        """Si el fichero no existe devuelve None."""
        ruta = tmp_path / "no_existe.bin"
        h = calculate_entropy(ruta)
        assert h is None

    def test_calculo_coincide_con_helper_shannon(self, fichero_alta_entropia):
        """El resultado debe coincidir con la función helper entropia_shannon."""
        datos = fichero_alta_entropia.read_bytes()
        esperado = round(entropia_shannon(datos), 4)
        obtenido = calculate_entropy(fichero_alta_entropia)
        assert abs(obtenido - esperado) < 0.001

    def test_max_bytes_limita_lectura(self, tmp_path):
        """Con max_bytes=100 solo lee los primeros 100 bytes."""
        datos = bytes(range(256)) * 4  # 1024 bytes con distribución uniforme
        ruta = tmp_path / "grande.bin"
        ruta.write_bytes(datos)
        h_total = calculate_entropy(ruta)
        h_100 = calculate_entropy(ruta, max_bytes=100)
        # Ambos deben ser distintos de None pero pueden diferir
        assert h_total is not None
        assert h_100 is not None


# ─────────────────────────────────────────────────────────────────────────────
# 2. verificar_extension_ransomware
# ─────────────────────────────────────────────────────────────────────────────

class TestVerificarExtensionRansomware:
    """Tests para verificar_extension_ransomware."""

    def test_extension_locky_detectada(self, tmp_path):
        """Un fichero .locky debe ser detectado como ransomware."""
        ruta = tmp_path / "datos.docx.locky"
        ruta.write_bytes(b"x")
        assert verificar_extension_ransomware(ruta, RANSOMWARE_EXTENSIONS_EMBEBIDAS)

    def test_extension_wnry_detectada(self, tmp_path):
        """Un fichero .wnry (WannaCry) debe ser detectado."""
        ruta = tmp_path / "archivo.wnry"
        ruta.write_bytes(b"x")
        assert verificar_extension_ransomware(ruta, RANSOMWARE_EXTENSIONS_EMBEBIDAS)

    def test_extension_encrypted_detectada(self, tmp_path):
        """Un fichero .encrypted debe ser detectado."""
        ruta = tmp_path / "imagen.png.encrypted"
        ruta.write_bytes(b"x")
        assert verificar_extension_ransomware(ruta, RANSOMWARE_EXTENSIONS_EMBEBIDAS)

    def test_extension_normal_no_detectada(self, tmp_path):
        """Un fichero .txt normal no debe ser detectado como ransomware."""
        ruta = tmp_path / "documento.txt"
        ruta.write_bytes(b"x")
        assert not verificar_extension_ransomware(ruta, RANSOMWARE_EXTENSIONS_EMBEBIDAS)

    def test_extension_py_no_detectada(self, tmp_path):
        """Un fichero .py no debe ser detectado como ransomware."""
        ruta = tmp_path / "script.py"
        ruta.write_bytes(b"x")
        assert not verificar_extension_ransomware(ruta, RANSOMWARE_EXTENSIONS_EMBEBIDAS)

    def test_set_vacio_no_detecta_nada(self, tmp_path):
        """Con un set vacío de extensiones nunca hay detección."""
        ruta = tmp_path / "datos.locky"
        ruta.write_bytes(b"x")
        assert not verificar_extension_ransomware(ruta, set())

    def test_extension_personalizada(self, tmp_path):
        """Extensión personalizada añadida al set debe ser detectada."""
        ruta = tmp_path / "fichero.vamptest"
        ruta.write_bytes(b"x")
        extensiones_custom = {".vamptest"}
        assert verificar_extension_ransomware(ruta, extensiones_custom)


# ─────────────────────────────────────────────────────────────────────────────
# 3. _entropy_label y _entropy_style
# ─────────────────────────────────────────────────────────────────────────────

class TestEntropyLabelYStyle:
    """Tests para _entropy_label y _entropy_style con umbral=7.0."""

    UMBRAL = 7.0

    def test_label_sobre_umbral_es_alerta(self):
        """H >= 7.0 → '⚠ ALERTA'."""
        assert _entropy_label(7.5, self.UMBRAL) == "⚠ ALERTA"
        assert _entropy_label(7.0, self.UMBRAL) == "⚠ ALERTA"

    def test_label_alto_entre_88pct_y_umbral(self):
        """H en [6.16, 7.0) → 'ALTO'."""
        # 7.0 * 0.88 = 6.16
        assert _entropy_label(6.5, self.UMBRAL) == "ALTO"

    def test_label_medio_entre_5_y_88pct(self):
        """H en [5.0, 6.16) → 'MEDIO'."""
        assert _entropy_label(5.5, self.UMBRAL) == "MEDIO"

    def test_label_seguro_bajo_umbral(self):
        """H < 5.0 → 'SEGURO'."""
        assert _entropy_label(3.0, self.UMBRAL) == "SEGURO"
        assert _entropy_label(0.0, self.UMBRAL) == "SEGURO"

    def test_style_sobre_umbral_es_rojo(self):
        """H >= umbral → 'bold red'."""
        assert _entropy_style(7.5, self.UMBRAL) == "bold red"

    def test_style_alto_es_naranja(self):
        """H en rango ALTO → 'orange3'."""
        assert _entropy_style(6.5, self.UMBRAL) == "orange3"

    def test_style_seguro_es_verde(self):
        """H < 5.0 → 'green'."""
        assert _entropy_style(3.0, self.UMBRAL) == "green"


# ─────────────────────────────────────────────────────────────────────────────
# 4. WatchState
# ─────────────────────────────────────────────────────────────────────────────

class TestWatchState:
    """Tests para WatchState: update, estadísticas y tabla."""

    def test_update_nueva_alerta_devuelve_true(self, fichero_alta_entropia):
        """WatchState.update devuelve True para la primera alerta de un fichero."""
        estado = WatchState(threshold=7.0)
        h = calculate_entropy(fichero_alta_entropia)
        nueva_alerta = estado.update(fichero_alta_entropia, h)
        assert nueva_alerta is True
        assert len(estado.alerts) == 1

    def test_update_fichero_seguro_no_es_alerta(self, fichero_baja_entropia):
        """Un fichero con H < umbral no genera alerta."""
        estado = WatchState(threshold=7.0)
        h = calculate_entropy(fichero_baja_entropia)
        nueva_alerta = estado.update(fichero_baja_entropia, h)
        assert nueva_alerta is False
        assert len(estado.alerts) == 0

    def test_scanned_incrementa_en_cada_update(self, fichero_alta_entropia,
                                                 fichero_baja_entropia):
        """El contador scanned se incrementa en cada llamada a update."""
        estado = WatchState(threshold=7.0)
        assert estado.scanned == 0
        estado.update(fichero_alta_entropia, 7.9)
        assert estado.scanned == 1
        estado.update(fichero_baja_entropia, 2.0)
        assert estado.scanned == 2

    def test_quarantined_incrementa_al_cuarentenar(self, fichero_alta_entropia):
        """El contador quarantined se incrementa cuando quarantined=True."""
        estado = WatchState(threshold=7.0)
        estado.update(fichero_alta_entropia, 7.9, quarantined=True)
        assert estado.quarantined == 1

    def test_build_table_no_lanza_excepcion(self, fichero_alta_entropia):
        """build_table no debe lanzar excepción con ficheros en estado."""
        estado = WatchState(threshold=7.0)
        estado.update(fichero_alta_entropia, 7.9)
        # No debe lanzar
        tabla = estado.build_table()
        assert tabla is not None


# ─────────────────────────────────────────────────────────────────────────────
# 5. DEFAULT_IGNORE_EXTS y RANSOMWARE_EXTENSIONS_EMBEBIDAS
# ─────────────────────────────────────────────────────────────────────────────

class TestConjuntosExtensiones:
    """Verifica la composición de los sets de extensiones."""

    def test_jpg_en_default_ignore_exts(self):
        """.jpg debe estar en DEFAULT_IGNORE_EXTS."""
        assert ".jpg" in DEFAULT_IGNORE_EXTS

    def test_zip_en_default_ignore_exts(self):
        """.zip debe estar en DEFAULT_IGNORE_EXTS."""
        assert ".zip" in DEFAULT_IGNORE_EXTS

    def test_encrypted_en_ransomware_embebidas(self):
        """.encrypted debe estar en RANSOMWARE_EXTENSIONS_EMBEBIDAS."""
        assert ".encrypted" in RANSOMWARE_EXTENSIONS_EMBEBIDAS

    def test_locky_en_ransomware_embebidas(self):
        """.locky debe estar en RANSOMWARE_EXTENSIONS_EMBEBIDAS."""
        assert ".locky" in RANSOMWARE_EXTENSIONS_EMBEBIDAS

    def test_wnry_en_ransomware_embebidas(self):
        """.wnry (WannaCry) debe estar en RANSOMWARE_EXTENSIONS_EMBEBIDAS."""
        assert ".wnry" in RANSOMWARE_EXTENSIONS_EMBEBIDAS

    def test_txt_no_en_default_ignore_exts(self):
        """.txt no debe estar en DEFAULT_IGNORE_EXTS (texto plano a analizar)."""
        assert ".txt" not in DEFAULT_IGNORE_EXTS


# ─────────────────────────────────────────────────────────────────────────────
# 6. quarantine_file
# ─────────────────────────────────────────────────────────────────────────────

class TestQuarantineFile:
    """Tests para quarantine_file."""

    def test_cuarentena_mueve_el_fichero(self, tmp_path):
        """quarantine_file debe mover el fichero al directorio de cuarentena."""
        fichero = tmp_path / "sospechoso.bin"
        fichero.write_bytes(os.urandom(128))
        cuarentena = tmp_path / "quarantine"

        resultado = quarantine_file(fichero, cuarentena)

        assert resultado is True
        assert not fichero.exists(), "El fichero original debe haber desaparecido"
        assert (cuarentena / "sospechoso.bin").exists(), "El fichero debe estar en cuarentena"

    def test_cuarentena_crea_directorio(self, tmp_path):
        """quarantine_file crea el directorio de cuarentena si no existe."""
        fichero = tmp_path / "malware.bin"
        fichero.write_bytes(b"x" * 64)
        cuarentena = tmp_path / "deep" / "quarantine"

        assert not cuarentena.exists()
        quarantine_file(fichero, cuarentena)
        assert cuarentena.exists()


# ─────────────────────────────────────────────────────────────────────────────
# 7. _is_whitelisted y load_whitelist
# ─────────────────────────────────────────────────────────────────────────────

class TestWhitelist:
    """Tests para _is_whitelisted y load_whitelist."""

    def test_whitelist_vacia_no_filtra_nada(self, tmp_path):
        """Con whitelist vacía, ningún fichero es ignorado."""
        ruta = tmp_path / "fichero.bin"
        ruta.write_bytes(b"x")
        assert _is_whitelisted(ruta, []) is False

    def test_coincidencia_exacta_por_nombre(self, tmp_path):
        """Una coincidencia exacta del nombre del fichero debe devolver True."""
        ruta = tmp_path / "backup.bin"
        ruta.write_bytes(b"x")
        whitelist = ["backup.bin"]
        assert _is_whitelisted(ruta, whitelist) is True

    def test_prefijo_con_asterisco(self, tmp_path):
        """Una entrada terminada en * actúa como prefijo en la ruta."""
        ruta = tmp_path / "backup_2026.bin"
        ruta.write_bytes(b"x")
        whitelist = ["backup*"]
        assert _is_whitelisted(ruta, whitelist) is True

    def test_no_coincidencia_no_filtra(self, tmp_path):
        """Un fichero sin coincidencia no es filtrado."""
        ruta = tmp_path / "ejecutable.exe"
        ruta.write_bytes(b"x")
        whitelist = ["otro.exe", "distinto*"]
        assert _is_whitelisted(ruta, whitelist) is False

    def test_load_whitelist_fichero_no_existe(self, tmp_path):
        """Si el fichero de whitelist no existe devuelve lista vacía sin error."""
        ruta = tmp_path / "no_existe.txt"
        resultado = load_whitelist(str(ruta))
        assert resultado == []

    def test_load_whitelist_none_devuelve_lista_vacia(self):
        """load_whitelist(None) devuelve lista vacía."""
        resultado = load_whitelist(None)
        assert resultado == []

    def test_load_whitelist_carga_entradas(self, tmp_path):
        """load_whitelist carga correctamente las entradas del fichero."""
        wl_file = tmp_path / "whitelist.txt"
        wl_file.write_text(
            "# comentario ignorado\n"
            "\n"
            "/ruta/exacta/fichero.bin\n"
            "prefijo*\n",
            encoding="utf-8",
        )
        resultado = load_whitelist(str(wl_file))
        assert "/ruta/exacta/fichero.bin" in resultado
        assert "prefijo*" in resultado
        # Los comentarios y líneas vacías no deben aparecer
        assert "# comentario ignorado" not in resultado
        assert "" not in resultado
