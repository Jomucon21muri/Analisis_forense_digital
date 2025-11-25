# Análisis Forense de Redes

Objetivo: Investigar tráfico de red para reconstruir comunicaciones, identificar intrusiones y exfiltración de datos.

Descripción: Captura y análisis de paquetes, logs de dispositivos de red y correlación temporal para entender actividad maliciosa.

Herramientas comunes: `Wireshark`, `tcpdump`, `Zeek` (Bro), `Suricata`, `pcap` utilities.

Pasos generales:
- Capturar tráfico relevante (PCAP) y conservar original.
- Filtrar y analizar flujos con Wireshark/Zeek.
- Correlacionar con logs de firewall, IDS/IPS y sistemas finales.

Artefactos importantes: PCAPs, conexiones sospechosas, patrones de exfiltración, indicadores IoC (IPs, dominios).
