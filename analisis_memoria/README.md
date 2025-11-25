# Análisis Forense de Memoria (RAM)

Objetivo: Capturar y analizar la memoria volátil para identificar procesos, credenciales y artefactos en ejecución.

Descripción: Obtención de una imagen de la RAM y análisis de procesos, conexiones de red, credenciales en texto claro y artefactos en memoria.

Herramientas comunes: `lime`, `volatility`, `rekall`, `FTK Imager` (para captura de memoria), `winpmem`.

Pasos generales:
- Capturar memoria en caliente con herramienta apropiada.
- Calcular hashes y preservar la imagen.
- Analizar con `volatility`/`rekall` (listado de procesos, DLLs, sockets, credenciales).

Artefactos importantes: dumps de procesos, credenciales, sesiones activas, malware en memoria, comunicación en curso.
