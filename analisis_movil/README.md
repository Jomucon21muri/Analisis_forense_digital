# Análisis Forense de Dispositivos Móviles

Objetivo: Recuperar evidencia de teléfonos y tablets (iOS/Android) relacionada con incidentes.

Descripción: Extracción lógica y física cuando sea posible, análisis de aplicaciones, mensajes, contactos y metadatos.

Herramientas comunes: `Cellebrite`, `ADB`, `Android Debug Bridge`, `MobSF`, `Autopsy (módulos móviles)`.

Pasos generales:
- Aislar el dispositivo y preservar estado (modo avión, imagen si procede).
- Realizar extracción lógica/física según posibilidades legales y técnicas.
- Analizar artefactos de aplicaciones, mensajería y almacenamiento.

Artefactos importantes: SMS, chats, contactos, historial de apps, localizaciones.
