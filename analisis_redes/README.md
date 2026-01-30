# Análisis Forense de Redes (Network Forensics)

## 1. Fundamentos teóricos del Análisis de Red

### 1.1 Modelo OSI y capas de análisis

El análisis forense de redes opera en múltiples capas del modelo OSI:

| Capa | Protocolos | Artefactos Forenses | Herramientas |
|------|-----------|---------------------|--------------|
| **7. Aplicación** | HTTP, HTTPS, DNS, SMTP, FTP | URLs, credenciales, payloads | Wireshark, Zeek |
| **6. Presentación** | SSL/TLS, Compression | Certificados, cifrado | ssldump, tshark |
| **5. Sesión** | NetBIOS, RPC | Sesiones activas | netstat, tcpflow |
| **4. Transporte** | TCP, UDP | Puertos, conexiones, streams | tcpdump, ngrep |
| **3. Red** | IP, ICMP, IPsec | Routing, fragmentación | traceroute, ping |
| **2. Enlace** | Ethernet, ARP, WiFi | MAC addresses, switches | arpwatch, ettercap |
| **1. Física** | Cables, RF | Topología física | spectrum analyzer |

### 1.2 Tipos de Evidencia de Red

#### Evidencia Volátil
- **Conexiones activas**: Estado actual de sockets TCP/UDP
- **Tablas ARP/routing**: Mapeos dinámicos
- **Sesiones autenticadas**: Tokens, cookies en tránsito
- **Memoria de dispositivos de red**: Buffers, cache

#### Evidencia Semi-Volátil
- **Logs de dispositivos**: Firewall, IDS/IPS, routers
- **NetFlow/sFlow**: Metadatos de flujos de tráfico
- **DHCP leases**: Asignaciones IP temporales
- **DNS cache**: Consultas recientes

#### Evidencia Persistente
- **PCAPs archivados**: Capturas completas de paquetes
- **Logs centralizados**: SIEM, syslog
- **Configuraciones de red**: ACLs, reglas de firewall
- **Registros de autenticación**: RADIUS, 802.1X

### 1.3 Principios de captura forense

1. **Ubicación estratégica**: TAPs, SPAN ports, inline sensors
2. **Mínima intrusión**: Monitorización pasiva preferida
3. **Completitud**: Captura full packet vs metadatos
4. **Integridad**: Hashes criptográficos, chain of custody
5. **Legalidad**: Wiretap laws, expectativas de privacidad

---

## 2. Captura de tráfico de Red

### 2.1 Configuración del Entorno de Captura

```bash
# Variables de entorno
CASE_ID="NET-2026-001"
CAPTURE_DIR="/forensics/${CASE_ID}/pcaps"
LOGS_DIR="/forensics/${CASE_ID}/logs"
mkdir -p "${CAPTURE_DIR}" "${LOGS_DIR}"

# Identificar interfaces de red
ip link show
# O en sistemas más antiguos
ifconfig -a

# Ver estadísticas de interfaz
ethtool eth0
ip -s link show eth0

# Modo promiscuo (capturar todo el tráfico del segmento)
ip link set eth0 promisc on
# Verificar
ip link show eth0 | grep PROMISC
```

### 2.2 Captura con tcpdump

```bash
# Captura básica en interfaz específica
tcpdump -i eth0 -w "${CAPTURE_DIR}/capture_$(date +%Y%m%d_%H%M%S).pcap"

# Captura con opciones forenses completas
tcpdump -i eth0 \
  -s 0 \
  -n \
  -w "${CAPTURE_DIR}/forensic_capture.pcap" \
  -C 1000 \
  -W 100 \
  -Z root \
  'not port 22'

# Parámetros explicados:
# -s 0: capturar paquete completo (snaplen = 65535)
# -n: no resolver nombres (más rápido, preserva IPs)
# -C 1000: rotar archivo cada 1000 MB
# -W 100: mantener máximo 100 archivos
# -Z root: ejecutar como root pero cambiar permisos
# 'not port 22': excluir SSH para no capturar propia conexión

# Captura con timestamp de alta precisión
tcpdump -i eth0 -s 0 -tttt -n -w capture.pcap

# Filtros BPF (Berkeley Packet Filter) comunes
tcpdump -i eth0 'tcp port 80 or tcp port 443'  # Solo HTTP/HTTPS
tcpdump -i eth0 'host 192.168.1.100'  # Tráfico de/hacia host específico
tcpdump -i eth0 'net 10.0.0.0/8'  # Red específica
tcpdump -i eth0 'tcp[tcpflags] & (tcp-syn|tcp-fin) != 0'  # SYN/FIN packets

# Captura de DNS
tcpdump -i eth0 -s 0 'udp port 53' -w dns_traffic.pcap

# Captura de tráfico sospechoso (puertos no estándar)
tcpdump -i eth0 'tcp portrange 10000-65535' -w high_ports.pcap
```

### 2.3 Captura con tshark (Wireshark CLI)

```bash
# Captura básica
tshark -i eth0 -w capture.pcap

# Captura con display filters (más legible que BPF)
tshark -i eth0 -f "tcp port 80" -w http_traffic.pcap

# Captura con ring buffer y estadísticas
tshark -i eth0 -w capture.pcap -b filesize:1000000 -b files:50

# Captura con metadata detallada
tshark -i eth0 -w capture.pcap \
  -a duration:3600 \
  -q

# Captura múltiples interfaces simultáneamente
tshark -i eth0 -i eth1 -w multi_interface.pcap
```

### 2.4 Network TAPs y SPAN ports

```bash
# TAP (Test Access Point): dispositivo físico pasivo
# - No introduce latencia
# - Invisible para la red
# - Captura bidireccional garantizada

# SPAN Port (Switch Port Analyzer) / Mirror Port
# Configuración en switch Cisco:
# switch(config)# monitor session 1 source interface gigabitethernet0/1
# switch(config)# monitor session 1 destination interface gigabitethernet0/24

# Validar configuración SPAN
# switch# show monitor session 1

# Capturar desde SPAN port
tcpdump -i eth24 -s 0 -w span_capture.pcap
```

### 2.5 Captura de WiFi (802.11)

```bash
# Poner interfaz en modo monitor
ip link set wlan0 down
iw dev wlan0 set type monitor
ip link set wlan0 up

# Verificar modo monitor
iw dev wlan0 info

# Capturar en canal específico
iw dev wlan0 set channel 6

# Captura con airodump-ng (aircrack-ng suite)
airodump-ng -c 6 --bssid AA:BB:CC:DD:EE:FF \
  -w wifi_capture wlan0

# Captura con tcpdump (incluye 802.11 headers)
tcpdump -i wlan0 -s 0 -e -w wifi_forensic.pcap

# Desencriptar tráfico WPA2 (con PSK conocida)
airdecap-ng -e "SSID" -p "password" wifi_capture-01.cap
```

---

## 3. Análisis de Paquetes con Wireshark

### 3.1 Filtros de display (display filters)

```bash
# Abrir PCAP
wireshark capture.pcap &

# Filtros comunes en Wireshark GUI:

# Protocolo específico
http
dns
smtp
ssh
tls

# IP específica
ip.addr == 192.168.1.100
ip.src == 10.0.0.5
ip.dst == 8.8.8.8

# Rango de IPs
ip.addr == 192.168.1.0/24

# Puerto
tcp.port == 80
tcp.dstport == 443
udp.port == 53

# Flags TCP
tcp.flags.syn == 1 && tcp.flags.ack == 0  # SYN packets
tcp.flags.reset == 1  # RST packets

# HTTP
http.request.method == "POST"
http.request.uri contains "login"
http.response.code == 200
http contains "password"

# DNS
dns.qry.name contains "suspicious.com"
dns.flags.response == 1

# TLS/SSL
tls.handshake.type == 1  # Client Hello
ssl.record.content_type == 23  # Application Data

# Conexiones establecidas
tcp.flags == 0x012  # SYN-ACK

# Data exfiltration (large uploads)
tcp.len > 1000 && ip.src == 192.168.1.100

# Combinaciones
(http || https) && ip.addr == 192.168.1.100
```

### 3.2 Análisis de streams TCP

```bash
# CLI con tshark
# Extraer streams TCP
tshark -r capture.pcap -q -z follow,tcp,ascii,0

# Extraer todos los streams
for stream in $(tshark -r capture.pcap -T fields -e tcp.stream | sort -n | uniq); do
  tshark -r capture.pcap -q -z follow,tcp,ascii,${stream} > "stream_${stream}.txt"
done

# Reconstruir archivos transferidos
tcpflow -r capture.pcap -o extracted_files/

# Alternativa: Wireshark GUI
# Clic derecho en paquete → Follow → TCP Stream
```

### 3.3 Extracción de objetos HTTP

```bash
# CLI
tshark -r capture.pcap --export-objects http,http_objects/

# Listar objetos HTTP
tshark -r capture.pcap -Y http.response -T fields \
  -e http.request.method \
  -e http.request.uri \
  -e http.response.code \
  -e http.content_type

# Wireshark GUI:
# File → Export Objects → HTTP
```

### 3.4 Análisis de DNS

```bash
# Extraer todas las consultas DNS
tshark -r capture.pcap -Y "dns.flags.response == 0" \
  -T fields -e frame.time -e ip.src -e dns.qry.name \
  > dns_queries.txt

# Extraer respuestas DNS
tshark -r capture.pcap -Y "dns.flags.response == 1" \
  -T fields -e dns.qry.name -e dns.a \
  | sort -u > dns_resolutions.txt

# Detección de DNS tunneling
tshark -r capture.pcap -Y "dns" -T fields -e dns.qry.name | \
  awk '{print length($0), $0}' | sort -rn | head -20

# Consultas DNS sospechosas (subdominios largos)
tshark -r capture.pcap -Y "dns" -T fields -e dns.qry.name | \
  awk 'length > 50' > suspicious_dns.txt
```

---

## 4. Análisis con Zeek (Bro)

### 4.1 Instalación y Configuración

```bash
# Instalación
apt install zeek

# O desde repositorio
echo 'deb http://download.opensuse.org/repositories/security:/zeek/xUbuntu_20.04/ /' | \
  sudo tee /etc/apt/sources.list.d/security:zeek.list
wget -qO- https://download.opensuse.org/repositories/security:/zeek/xUbuntu_20.04/Release.key | \
  gpg --dearmor | sudo tee /etc/apt/trusted.gpg.d/security_zeek.gpg
apt update && apt install zeek

# Alias útil
export PATH=/opt/zeek/bin:$PATH
alias zeek-cut='/opt/zeek/bin/zeek-cut'
```

### 4.2 Análisis de PCAPs con Zeek

```bash
# Procesar PCAP
zeek -r capture.pcap

# Genera logs en directorio actual:
# conn.log - conexiones
# dns.log - consultas DNS
# http.log - solicitudes HTTP
# ssl.log - handshakes TLS
# files.log - archivos transferidos
# weird.log - anomalías

# Procesar con scripts específicos
zeek -r capture.pcap protocols/http/detect-sqli.zeek

# Extraer campos específicos de conn.log
zeek-cut ts id.orig_h id.resp_h id.resp_p proto < conn.log | head

# Análisis de HTTP
zeek-cut ts host uri < http.log | grep -i "suspicious"

# Top 10 hosts destino
zeek-cut id.resp_h < conn.log | sort | uniq -c | sort -rn | head -10

# Top 10 puertos
zeek-cut id.resp_p < conn.log | sort | uniq -c | sort -rn | head -10

# Transferencias de archivos
zeek-cut mime_type source < files.log | sort | uniq -c

# Extraer archivos detectados
for hash in $(zeek-cut sha256 < files.log); do
  find . -name "*${hash}*" -exec cp {} extracted_files/ \;
done
```

### 4.3 Zeek scripts personalizados

```zeek
# Detectar User-Agents sospechosos
# suspicious_ua.zeek

@load base/protocols/http

event http_header(c: connection, is_orig: bool, name: string, value: string)
{
    if ( is_orig && name == "USER-AGENT" )
    {
        local suspicious_patterns = vector("sqlmap", "nikto", "nmap", "masscan", 
                                           "python-requests", "curl/", "wget/");
        
        for ( pattern in suspicious_patterns )
        {
            if ( pattern in value )
            {
                print fmt("[SUSPICIOUS UA] %s -> %s: %s", 
                         c$id$orig_h, c$id$resp_h, value);
            }
        }
    }
}
```

---

## 5. Detección de intrusiones con Suricata

### 5.1 Configuración de Suricata

```bash
# Instalación
apt install suricata

# Actualizar reglas
suricata-update

# Habilitar rulesets adicionales
suricata-update enable-source et/open
suricata-update enable-source oisf/trafficid

# Configurar interfaz en /etc/suricata/suricata.yaml
# af-packet:
#   - interface: eth0

# Verificar configuración
suricata -T -c /etc/suricata/suricata.yaml
```

### 5.2 Análisis de PCAPs

```bash
# Procesar PCAP offline
suricata -c /etc/suricata/suricata.yaml \
  -r capture.pcap \
  -l "${LOGS_DIR}/suricata"

# Resultados en:
# fast.log - alertas rápidas
# eve.json - eventos en JSON (completo)
# stats.log - estadísticas

# Ver alertas
cat "${LOGS_DIR}/suricata/fast.log"

# Parsear JSON con jq
jq '.alert | select(.signature_id != null)' "${LOGS_DIR}/suricata/eve.json"

# Top 10 alertas
jq -r '.alert.signature' "${LOGS_DIR}/suricata/eve.json" | \
  sort | uniq -c | sort -rn | head -10

# Alertas por severidad
jq -r '.alert.severity' "${LOGS_DIR}/suricata/eve.json" | \
  sort | uniq -c
```

### 5.3 Reglas personalizadas

```bash
# Crear regla personalizada
cat >> /etc/suricata/rules/custom.rules <<'EOF'
# Detectar exfiltración a pastebin
alert http any any -> any any (msg:"Data exfiltration to Pastebin"; \
  content:"pastebin.com"; http_host; \
  flow:to_server,established; \
  classtype:policy-violation; sid:1000001; rev:1;)

# Detectar Cobalt Strike beacon
alert tcp any any -> any any (msg:"Cobalt Strike Beacon Detected"; \
  content:"|00 00 00|"; depth:3; \
  content:"MSSE-"; distance:0; \
  sid:1000002; rev:1;)

# SQL Injection en HTTP
alert http any any -> any any (msg:"SQL Injection Attempt"; \
  flow:to_server,established; \
  content:"union"; nocase; http_uri; \
  content:"select"; nocase; http_uri; \
  sid:1000003; rev:1;)

# Command injection
alert http any any -> any any (msg:"Command injection"; \
  flow:to_server,established; \
  pcre:"/(\||;|`|\$\(|<|>)/"; http_uri; \
  sid:1000004; rev:1;)
EOF

# Recargar reglas
suricatasc -c reload-rules
```

---

## 6. Análisis de NetFlow / sFlow

### 6.1 Configuración de Colectores

```bash
# nfdump para NetFlow
apt install nfdump

# Iniciar collector
nfcapd -w -D -l /var/nfcapd -p 9995

# Configurar router para enviar NetFlow
# router(config)# ip flow-export destination <collector_ip> 9995
# router(config)# ip flow-export version 5

# Leer datos capturados
nfdump -R /var/nfcapd -o extended

# Top talkers
nfdump -R /var/nfcapd -s srcip -n 20

# Flujos a IP específica
nfdump -R /var/nfcapd 'dst ip 8.8.8.8'

# Flujos grandes (posible exfiltración)
nfdump -R /var/nfcapd 'bytes > 10000000' -o extended
```

### 6.2 Análisis de Patrones

```bash
# Detectar port scanning
nfdump -R /var/nfcapd -s dstport 'duration < 1 and packets < 5' -n 100

# Conexiones de larga duración (C2 beacons)
nfdump -R /var/nfcapd 'duration > 3600' -o extended

# Tráfico en horarios inusuales
nfdump -R /var/nfcapd -t 2026/01/30.02:00-06:00

# Protocolos inusuales
nfdump -R /var/nfcapd -s proto -n 20
```

---

## 7. Análisis de protocolos Específicos

### 7.1 HTTPS/TLS analysis

```bash
# Extraer certificados
tshark -r capture.pcap -Y "tls.handshake.certificate" \
  -T fields -e tls.handshake.certificate > certs.hex

# Decodificar certificados
for cert in certs.hex; do
  echo "$cert" | xxd -r -p | openssl x509 -inform der -text
done

# Analizar Client Hello (detectar JA3)
tshark -r capture.pcap -Y "tls.handshake.type == 1" \
  -T fields -e tls.handshake.ciphersuite

# JA3 fingerprinting (requiere script)
python3 ja3.py capture.pcap > ja3_hashes.txt
```

### 7.2 SMB/CIFS analysis

```bash
# Extraer actividad SMB
tshark -r capture.pcap -Y "smb || smb2" \
  -T fields -e frame.time -e ip.src -e smb.path > smb_activity.txt

# Detectar movimiento lateral (PsExec, WMI)
tshark -r capture.pcap -Y "smb2.cmd == 5 && smb2.filename contains \"ADMIN$\""

# Ransomware activity (muchas escrituras SMB)
tshark -r capture.pcap -Y "smb2.cmd == 8" | wc -l  # CREATE operations
```

### 7.3 Email protocols (SMTP/POP3/IMAP)

```bash
# Extraer emails desde SMTP
tshark -r capture.pcap -Y "smtp.data.fragment" -T fields -e smtp.data.fragment | \
  xxd -r -p > emails.mbox

# Buscar credenciales en POP3/IMAP
tshark -r capture.pcap -Y "pop.request.command == \"USER\" || pop.request.command == \"PASS\""

# Detectar spam/phishing
tshark -r capture.pcap -Y "smtp" -T fields -e smtp.req.command -e smtp.req.parameter | \
  grep -i "MAIL FROM"
```

### 7.4 RDP analysis

```bash
# Detectar conexiones RDP
tshark -r capture.pcap -Y "tcp.port == 3389"

# Extraer intentos de login
tshark -r capture.pcap -Y "rdp" -T fields -e frame.time -e ip.src -e ip.dst

# Detección de brute-force RDP
tshark -r capture.pcap -Y "tcp.port == 3389" -T fields -e ip.src | \
  sort | uniq -c | sort -rn
```

---

## 8. Detección de amenazas avanzadas

### 8.1 Command & Control (C2) Detection

```bash
# Beaconing detection (conexiones periódicas)
python3 <<'EOF'
import pyshark

cap = pyshark.FileCapture('capture.pcap')
conn_times = {}

for pkt in cap:
    try:
        key = f"{pkt.ip.src}:{pkt.tcp.srcport}->{pkt.ip.dst}:{pkt.tcp.dstport}"
        if key not in conn_times:
            conn_times[key] = []
        conn_times[key].append(float(pkt.sniff_timestamp))
    except:
        pass

# Analizar intervalos
for conn, times in conn_times.items():
    if len(times) > 10:
        intervals = [times[i+1] - times[i] for i in range(len(times)-1)]
        avg_interval = sum(intervals) / len(intervals)
        if 10 < avg_interval < 600:  # Entre 10 seg y 10 min
            print(f"[BEACON DETECTED] {conn}: avg interval {avg_interval:.2f}s")
EOF

# DNS C2 detection (queries largas o inusuales)
tshark -r capture.pcap -Y "dns" -T fields -e dns.qry.name | \
  awk 'length > 40' | sort -u

# Entropy analysis para DNS tunneling
tshark -r capture.pcap -Y "dns.qry.name" -T fields -e dns.qry.name | \
  python3 -c "
import sys, math
from collections import Counter

for line in sys.stdin:
    domain = line.strip()
    subdomain = domain.split('.')[0]
    if len(subdomain) < 10:
        continue
    entropy = -sum((count/len(subdomain)) * math.log2(count/len(subdomain)) 
                   for count in Counter(subdomain).values())
    if entropy > 3.5:
        print(f'{entropy:.2f} - {domain}')
"
```

### 8.2 Data exfiltration detection

```bash
# Large uploads detection
tshark -r capture.pcap -Y "tcp" -T fields \
  -e frame.time -e ip.src -e ip.dst -e tcp.len | \
  awk '$4 > 1000 {sum[$2]+=$4} END {for (ip in sum) print sum[ip], ip}' | \
  sort -rn | head -10

# Unusual protocols on standard ports
tshark -r capture.pcap -Y "tcp.port == 80 && !http"
tshark -r capture.pcap -Y "tcp.port == 443 && !tls"

# ICMP tunneling detection
tshark -r capture.pcap -Y "icmp" -T fields -e data.len | \
  awk '{if ($1 > 64) count++} END {print count " large ICMP packets"}'

# DNS exfiltration (subdomain data encoding)
tshark -r capture.pcap -Y "dns.qry.name" -T fields -e dns.qry.name | \
  grep -E "[0-9a-f]{32,}" | head -20  # Hex encoding
```

### 8.3 Lateral movement detection

```bash
# SMB activity entre hosts internos
tshark -r capture.pcap -Y "smb2 && ip.src == 192.168.1.0/24 && ip.dst == 192.168.1.0/24" \
  -T fields -e ip.src -e ip.dst -e smb2.cmd | \
  sort | uniq -c | sort -rn

# WMI activity (port 135, 49152-65535)
tshark -r capture.pcap -Y "tcp.port == 135 || (tcp.port >= 49152 && tcp.port <= 65535)"

# PsExec detection
tshark -r capture.pcap -Y "smb2.filename contains \"PSEXESVC\""

# Pass-the-Hash detection (NTLM sin Kerberos)
tshark -r capture.pcap -Y "ntlmssp" -T fields -e ntlmssp.auth.username
```

---

## 9. Análisis de logs de Red

### 9.1 Firewall logs analysis

```bash
# Ejemplo: iptables logs
cat /var/log/kern.log | grep "iptables"

# Parsear logs de iptables
awk '/iptables/ {print $13,$14,$15}' /var/log/kern.log | \
  sed 's/SRC=//; s/DST=//; s/DPT=//' | \
  sort | uniq -c | sort -rn

# Detectar port scanning
awk '/iptables/ && /DPT/ {print $NF}' /var/log/kern.log | \
  sed 's/DPT=//' | sort | uniq -c | sort -rn

# Cisco ASA logs
# Show denied connections
grep "denied" asa.log | awk '{print $7,$9}' | sort | uniq -c | sort -rn
```

### 9.2 IDS/IPS Logs Analysis

```bash
# Snort logs
# /var/log/snort/alert

# Top alerts
cat /var/log/snort/alert | grep -oP '\[\*\*\] \K[^[]*' | \
  sort | uniq -c | sort -rn | head -20

# Suricata eve.json analysis
jq -r '.alert | "\(.timestamp) \(.src_ip):\(.src_port) -> \(.dest_ip):\(.dest_port) \(.signature)"' \
  eve.json | head -50
```

### 9.3 Proxy logs analysis

```bash
# Squid proxy logs
# /var/log/squid/access.log

# Top URLs visited
awk '{print $7}' /var/log/squid/access.log | \
  sort | uniq -c | sort -rn | head -20

# User activity
awk '{print $8}' /var/log/squid/access.log | \
  sort | uniq -c | sort -rn

# Detect C2 via proxy
awk '{print $3,$7}' /var/log/squid/access.log | \
  grep -vE "(google|microsoft|apple|cloudflare)" | \
  sort | uniq -c | sort -rn | head -50
```

---

## 10. Visualización y Reporting

### 10.1 Generación de Gráficos

```python
#!/usr/bin/env python3
# network_visualization.py

import pyshark
import matplotlib.pyplot as plt
from collections import Counter

cap = pyshark.FileCapture('capture.pcap')

protocols = []
for pkt in cap:
    try:
        protocols.append(pkt.highest_layer)
    except:
        pass

# Top protocols
protocol_counts = Counter(protocols)
plt.figure(figsize=(10, 6))
plt.bar(protocol_counts.keys(), protocol_counts.values())
plt.xlabel('Protocol')
plt.ylabel('Packet Count')
plt.title('Protocol Distribution')
plt.xticks(rotation=45)
plt.tight_layout()
plt.savefig('protocol_distribution.png')
```

### 10.2 Network graph con NetworkX

```python
#!/usr/bin/env python3
import pyshark
import networkx as nx
import matplotlib.pyplot as plt

cap = pyshark.FileCapture('capture.pcap')
G = nx.DiGraph()

for pkt in cap:
    try:
        src = pkt.ip.src
        dst = pkt.ip.dst
        if G.has_edge(src, dst):
            G[src][dst]['weight'] += 1
        else:
            G.add_edge(src, dst, weight=1)
    except:
        pass

# Visualizar
pos = nx.spring_layout(G)
nx.draw(G, pos, with_labels=True, node_size=500, node_color='lightblue')
plt.savefig('network_graph.png')
```

---

## 11. Referencias y Recursos

### Libros fundamentales
- Davidoff, S. & Ham, J. (2012). *Network Forensics: Tracking Hackers through Cyberspace*
- Sanders, C. (2017). *Practical Packet Analysis, 3rd Edition*. No Starch Press
- Nikkel, B. (2016). *Practical Forensic Imaging: Securing Digital Evidence*

### Papers académicos
- Kent, A. & Chev is, T. (2007). "Cyber Security: A Holistic Approach"
- Reith, M. et al. (2002). "An Examination of Digital Forensic Models"
- Paxson, V. (1999). "Bro: A System for Detecting Network Intruders in Real-Time"

### Herramientas y Frameworks
- **Wireshark**: https://www.wireshark.org/
- **Zeek**: https://zeek.org/
- **Suricata**: https://suricata.io/
- **NetworkMiner**: https://www.netresec.com/?page=NetworkMiner
- **Security Onion**: https://securityonionsolutions.com/

### Certificaciones
- **GCFA** (GIAC Certified Forensic Analyst)
- **GNFA** (GIAC Network Forensic Analyst)
- **GCIA** (GIAC Certified Intrusion Analyst)
- **CCFP** (Certified Cyber Forensics Professional)

### Estándares
- **RFC 3227**: Guidelines for Evidence Collection and Archiving
- **ISO/IEC 27043**: Incident investigation principles and processes
- **NIST SP 800-86**: Guide to Integrating Forensic Techniques into Incident Response
