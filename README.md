# vamp-entropy-watch

**VampSecure Labs — Security Research Division**  
Detector de actividad ransomware por análisis de entropía de Shannon en ficheros.

---

## Descripción

Herramienta de defensa proactiva que detecta patrones de cifrado masivo de ficheros
característicos de ataques ransomware, mediante el cálculo de entropía de Shannon.

Un fichero cifrado (o comprimido sin cabecera reconocible) presenta una distribución de
bytes casi uniforme, con entropía próxima al máximo teórico de 8 bits/byte. Un umbral
de H ≥ 7.0 indica con alta probabilidad que el contenido ha sido cifrado.

Soporta dos modos de operación: monitorización continua de directorios con cuarentena
automática, y escaneo puntual con informe JSON.

## Concepto técnico

La entropía de Shannon se calcula como:

```
H(X) = -Σ P(xᵢ) × log₂(P(xᵢ))
```

Donde `P(xᵢ)` es la probabilidad de aparición de cada valor de byte (0-255). Rango: 0 a 8.

- **H < 5.0** — Texto plano, código fuente, datos estructurados
- **H 5.0–7.0** — Zona gris (multimedia, ejecutables)
- **H ≥ 7.0** — Alta probabilidad de cifrado o ransomware activo

## Requisitos

- Python 3.9+
- Dependencias: `rich>=13.7.0`

## Instalación

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Uso

```bash
# Monitorizar directorio en tiempo real (con cuarentena automática)
python3 vamp_entropy_watch.py monitor /ruta/a/vigilar

# Monitorizar sin cuarentena automática
python3 vamp_entropy_watch.py monitor /ruta/a/vigilar --no-quarantine

# Monitorizar de forma recursiva con umbral personalizado
python3 vamp_entropy_watch.py monitor /ruta/a/vigilar --recursive --threshold 6.8 --interval 5

# Escaneo puntual de directorio
python3 vamp_entropy_watch.py scan /ruta/a/escanear

# Escaneo con salida JSON
python3 vamp_entropy_watch.py scan /ruta/a/escanear --output-json resultado.json --recursive
```

## Opciones monitor

| Opción | Descripción |
|--------|-------------|
| `target` | Directorio a monitorizar |
| `--threshold` | Umbral de entropía (por defecto: 7.0) |
| `--interval` | Intervalo de escaneo en segundos (por defecto: 10) |
| `--recursive` | Monitorizar subdirectorios |
| `--no-quarantine` | Deshabilitar cuarentena automática |
| `--quarantine-dir` | Directorio de cuarentena (por defecto: `/tmp/vamp_quarantine`) |

## Opciones scan

| Opción | Descripción |
|--------|-------------|
| `target` | Directorio a escanear |
| `--threshold` | Umbral de entropía (por defecto: 7.0) |
| `--recursive` | Escanear subdirectorios |
| `--output-json` | Guardar resultados en JSON |

## Cuarentena

Al detectar un fichero con entropía superior al umbral, la herramienta mueve el fichero
automáticamente al directorio de cuarentena y aplica permisos `444` (solo lectura).
Los ficheros en cuarentena no se vuelven a analizar.

## Tipos de fichero ignorados por defecto

Formatos binarios nativamente de alta entropía: imágenes (jpg, png, gif, webp), vídeo
(mp4, avi, mkv), audio (mp3, ogg, flac), comprimidos (zip, gz, bz2, 7z, rar), ejecutables
(exe, dll), paquetes de apps (dmg, pkg, deb, rpm).

---

© VampSecure Studios — VampSecure Labs Security Research Division  
Licencia: MIT
