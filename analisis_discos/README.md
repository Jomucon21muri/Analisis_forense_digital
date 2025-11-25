# Análisis Forense de Discos

Objetivo: Identificar y preservar evidencia en dispositivos de almacenamiento (HDD/SSD).

Descripción: Recuperación de archivos borrados, análisis del sistema de archivos, identificación de artefactos y cronologías.

Herramientas comunes: `dd`, `dcfldd`, `FTK Imager`, `Autopsy`, `sleuthkit`, `TestDisk`, `PhotoRec`.

Pasos generales:
- Crear imagen forense (bit a bit) y trabajar sobre la copia.
- Calcular y guardar hashes (`md5`, `sha256`).
- Montar y examinar la imagen con `sleuthkit`/`Autopsy`.
- Buscar archivos borrados, metadatos y artefactos relevantes.

Artefactos importantes: archivos recuperados, logs del sistema de archivos, metadatos, tablas de particiones.
