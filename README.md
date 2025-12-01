# Análisis forense infromático

Este repositorio contiene plantillas, guías y ejemplos para distintos tipos de análisis forense digital. Está pensado como catálogo de referencia y apoyo para tareas de triage, investigación y generación de informes.

## Objetivo

Proveer una estructura organizada con:
- Guías por tipo de análisis (discos, memoria, redes, sistemas, malware, registros y dispositivos móviles).
- Plantillas de informe (`REPORT_TEMPLATE.md`) para estandarizar entregables.
- Archivos de ejemplo con IOCs (`IOCs.md`) para pruebas y creación de reglas de detección.

## Estructura del repositorio

- `analisis_discos/` - Recuperación y análisis de evidencias en dispositivos de almacenamiento.
- `analisis_memoria/` - Captura y análisis de memoria RAM; detección de procesos y credenciales en memoria.
- `analisis_redes/` - Capturas PCAP, análisis de flujos y reglas de detección de red.
- `analisis_sistema/` - Artefactos y triage en sistemas operativos (Windows/Linux/macOS).
- `analisis_malware/` - Análisis estático y dinámico de muestras maliciosas.
- `analisis_registros/` - Recolección, normalización y correlación de logs.
- `analisis_movil/` - Extracción y análisis de evidencia en dispositivos móviles.
- `ataques/` - Catálogo de tipos de ataques, ejemplos y mitigaciones.

Cada carpeta incluye un `README.md` con descripción, un `REPORT_TEMPLATE.md` para los informes, y un `IOCs.md` con indicadores de ejemplo.

## Cómo usar

1. Navega a la carpeta correspondiente al tipo de análisis.
2. Abre `REPORT_TEMPLATE.md` y completa las secciones con los datos del caso.
3. Guarda IOCs reales en `IOCs.md` o en archivos separados (no subir muestras sensibles al repositorio público).
4. Añade artefactos de evidencia en un almacenamiento seguro (no en este repo).

## Buenas prácticas

- No subir muestras reales, PCAPs o binarios maliciosos a repositorios públicos.
- Mantener hashes y metadatos, pero almacenar muestras en repositorios/almacenamiento seguro controlado.
- Versionar informes y anexos sensibles fuera del código fuente.


---

Licencia y aviso: Este repositorio es solo para fines educativos y de referencia. No usar las plantillas para revelar información sensible en público.

