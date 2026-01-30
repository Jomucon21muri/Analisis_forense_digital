# Análisis Forense de Registros y Logs

## 1. Fundamentos de log analysis

### 1.1 Taxonomía de Logs

**Tipos de logs por Fuente:**
- **Sistema Operativo**: syslog, Windows Event Logs, audit.log
- **Aplicaciones**: Apache, nginx, IIS, bases de datos
- **Seguridad**: IDS/IPS, firewalls, antivirus, EDR
- **Autenticación**: RADIUS, LDAP, Kerberos, Azure AD
- **Red**: NetFlow, firewall, DNS, DHCP, proxy
- **Cloud**: CloudTrail (AWS), Activity Log (Azure), Cloud Logging (GCP)

### 1.2 Estándares de Logging

- **Syslog (RFC 5424)**: Formato estándar Unix/Linux
- **CEF (Common Event Format)**: ArcSight
- **LEEF (Log Event Extended Format)**: IBM QRadar
- **Sysmon**: Telemetría avanzada Windows
- **OSSEC/Wazuh**: HIDS con formato JSON

---

## 2. Recolección y Preservación

### 2.1 Linux/Unix logs

```bash
CASE_ID="LOG-2026-001"
LOG_DIR="/forensics/${CASE_ID}/logs"
mkdir -p "${LOG_DIR}"

# Recolectar logs críticos con timestamps preservados
cp -p /var/log/syslog* "${LOG_DIR}/"
cp -p /var/log/auth.log* "${LOG_DIR}/"
cp -p /var/log/secure* "${LOG_DIR}/"  # RHEL/CentOS
cp -p /var/log/audit/audit.log* "${LOG_DIR}/"
cp -p /var/log/kern.log* "${LOG_DIR}/"
cp -p /var/log/messages* "${LOG_DIR}/"

# Logs de aplicaciones
cp -p /var/log/apache2/* "${LOG_DIR}/apache/"
cp -p /var/log/nginx/* "${LOG_DIR}/nginx/"
cp -p /var/log/mysql/* "${LOG_DIR}/mysql/"

# Journal (systemd)
journalctl --output=export > "${LOG_DIR}/journal_export.journal"
journalctl --output=json > "${LOG_DIR}/journal.json"

# Hash para integridad
find "${LOG_DIR}" -type f -exec sha256sum {} \; > "${LOG_DIR}/hashes.txt"
```

### 2.2 Windows Event Logs

```powershell
$CaseID = "LOG-2026-001"
$LogDir = "C:\Forensics\$CaseID\EventLogs"
New-Item -ItemType Directory -Path $LogDir -Force

# Exportar Event Logs críticos (.evtx)
$LogsToExport = @(
    'System',
    'Security',
    'Application',
    'Microsoft-Windows-Sysmon/Operational',
    'Microsoft-Windows-PowerShell/Operational',
    'Microsoft-Windows-Windows Defender/Operational',
    'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational'
)

foreach ($Log in $LogsToExport) {
    $FileName = $Log -replace '/','-'
    wevtutil epl $Log "$LogDir\$FileName.evtx"
    
    # Exportar a XML para análisis
    wevtutil qe $Log /f:xml > "$LogDir\$FileName.xml"
}

# Calcular hashes
Get-ChildItem $LogDir -Recurse -File | 
    ForEach-Object { 
        $hash = Get-FileHash $_.FullName -Algorithm SHA256
        "$($hash.Hash)  $($_.FullName)"
    } | Out-File "$LogDir\hashes.txt"
```

### 2.3 Preservación de Integridad

```bash
# Firma digital con GPG
gpg --output logs.tar.gz.sig --detach-sig logs.tar.gz

# Timestamp cryptográfico (RFC 3161)
openssl ts -query -data logs.tar.gz -sha256 -out request.tsq
curl -H "Content-Type: application/timestamp-query" \
  --data-binary @request.tsq \
  http://timestamp.server/tsa > response.tsr
```

---

## 3. Análisis con ELK Stack

### 3.1 Elasticsearch + Logstash + Kibana

```bash
# Instalación (Docker)
docker network create elastic

docker run -d --name elasticsearch --net elastic \
  -p 9200:9200 -e "discovery.type=single-node" \
  docker.elastic.co/elasticsearch/elasticsearch:8.11.0

docker run -d --name kibana --net elastic \
  -p 5601:5601 \
  docker.elastic.co/kibana/kibana:8.11.0

docker run -d --name logstash --net elastic \
  -p 5000:5000 \
  docker.elastic.co/logstash/logstash:8.11.0
```

### 3.2 Logstash pipeline para Syslog

```ruby
# /etc/logstash/conf.d/syslog.conf
input {
  file {
    path => "/forensics/logs/syslog*"
    start_position => "beginning"
    sincedb_path => "/dev/null"
  }
}

filter {
  grok {
    match => { "message" => "%{SYSLOGLINE}" }
  }
  
  date {
    match => [ "timestamp", "MMM  d HH:mm:ss", "MMM dd HH:mm:ss" ]
  }
  
  mutate {
    add_field => { "case_id" => "LOG-2026-001" }
  }
}

output {
  elasticsearch {
    hosts => ["localhost:9200"]
    index => "syslog-%{+YYYY.MM.dd}"
  }
}
```

### 3.3 Queries Elasticsearch

```bash
# Buscar eventos de autenticación fallida
curl -X GET "localhost:9200/syslog-*/_search?pretty" -H 'Content-Type: application/json' -d'
{
  "query": {
    "match": {
      "message": "authentication failure"
    }
  }
}'

# Aggregación: top usuarios con fallos
curl -X GET "localhost:9200/syslog-*/_search?pretty" -H 'Content-Type: application/json' -d'
{
  "size": 0,
  "aggs": {
    "failed_users": {
      "terms": {
        "field": "user.keyword",
        "size": 20
      }
    }
  },
  "query": {
    "match": { "message": "Failed password" }
  }
}'
```

---

## 4. Análisis con Splunk

```bash
# Búsqueda básica
index=main sourcetype=syslog "authentication failure"

# Time range con estadísticas
index=main earliest=-7d | stats count by host, user

# Detección de brute-force
index=main sourcetype=auth "Failed password" 
| stats count by src_ip 
| where count > 10

# Timeline de eventos
index=main | timechart span=1h count by source

# Búsqueda de IOCs
index=main ("192.168.1.100" OR "malicious.domain.com" OR "evil.exe")

# Correlación de eventos (lateral movement)
index=main EventCode=4624 
| transaction src_ip dest_ip maxspan=5m 
| where eventcount > 5
```

---

## 5. Windows Event Log analysis

### 5.1 Event IDs críticos

**Autenticación (Security):**
- **4624**: Logon exitoso
- **4625**: Logon fallido
- **4648**: Logon usando credenciales explícitas
- **4672**: Privilegios especiales asignados
- **4720**: Cuenta de usuario creada
- **4732**: Usuario agregado a grupo local

**Procesos y Objetos:**
- **4688**: Proceso creado (con Sysmon: línea de comandos)
- **4689**: Proceso terminado
- **4698**: Tarea programada creada
- **4697**: Servicio instalado

**Política y Configuración:**
- **4719**: Política de auditoría modificada
- **4946**: Windows Firewall excepción añadida

### 5.2 PowerShell analysis

```powershell
# Buscar eventos de autenticación fallida
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4625} | 
    Select-Object TimeCreated, @{N='User';E={$_.Properties[5].Value}}, 
                  @{N='SourceIP';E={$_.Properties[19].Value}} | 
    Group-Object SourceIP | Sort-Object Count -Descending

# Procesos creados (con Sysmon)
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; ID=1} |
    Select-Object TimeCreated, @{N='Image';E={$_.Properties[4].Value}}, 
                  @{N='CommandLine';E={$_.Properties[10].Value}}

# Análisis de PowerShell ejecutado
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'; ID=4104} |
    Where-Object {$_.Message -match "(Invoke-Expression|IEX|DownloadString)"}
```

### 5.3 Sysmon configuration

```xml
<!-- Sysmon config para forensics -->
<Sysmon schemaversion="4.70">
  <EventFiltering>
    <ProcessCreate onmatch="include">
      <CommandLine condition="contains">powershell</CommandLine>
      <CommandLine condition="contains">cmd.exe</CommandLine>
    </ProcessCreate>
    
    <NetworkConnect onmatch="include">
      <DestinationPort condition="is">4444</DestinationPort>
      <DestinationPort condition="is">8080</DestinationPort>
    </NetworkConnect>
    
    <FileCreate onmatch="include">
      <TargetFilename condition="contains">\\Temp\\</TargetFilename>
      <TargetFilename condition="end with">.exe</TargetFilename>
    </FileCreate>
  </EventFiltering>
</Sysmon>
```

---

## 6. Análisis de logs web

### 6.1 Apache/Nginx access logs

```bash
# Top IPs
awk '{print $1}' access.log | sort | uniq -c | sort -rn | head -20

# Requests por código de estado
awk '{print $9}' access.log | sort | uniq -c | sort -rn

# Detectar SQL injection
grep -iE "(union.*select|concat.*0x)" access.log

# Command injection
grep -E "(;|\||\`|\$\()" access.log | grep -v "User-Agent"

# Path traversal
grep -E "\.\./|%2e%2e" access.log

# User-Agents sospechosos
awk -F'"' '{print $6}' access.log | sort | uniq -c | sort -rn | head -20

# Análisis con GoAccess (visual)
goaccess access.log -o report.html --log-format=COMBINED
```

### 6.2 Error logs analysis

```bash
# PHP errors (possible exploitation)
grep -i "error\|warning" error.log | grep -v "deprecated"

# Failed auth attempts
grep "authentication failed" error.log | awk '{print $NF}' | sort | uniq -c
```

---

## 7. Timeline construction

### 7.1 Super timeline con Plaso

```bash
# Procesar múltiples fuentes
log2timeline.py --storage-file timeline.plaso \
  --parsers "linux,apache" \
  /forensics/logs/

# Filtrar y exportar
psort.py -o l2tcsv -w timeline.csv timeline.plaso

# Timeline de ventana temporal específica
psort.py -o l2tcsv timeline.plaso \
  "date > '2026-01-29 00:00:00' AND date < '2026-01-31 00:00:00'" \
  -w filtered_timeline.csv
```

### 7.2 Timeline manual con awk

```bash
# Combinar múltiples fuentes
{
  awk '{print $1,$2,$3,"[SYSLOG]",$0}' syslog
  awk '{print $4,"[APACHE]",$0}' access.log | sed 's/\[//; s/\].*/ /'
  # Windows: convertir primero a formato estándar
} | sort -k1,1 -k2,2 -k3,3 > combined_timeline.txt
```

---

## 8. Detección de anomalías

### 8.1 Baseline analysis

```python
#!/usr/bin/env python3
import pandas as pd
from scipy import stats

# Cargar logs históricos
df = pd.read_csv('auth_logs.csv')

# Establecer baseline (30 días)
baseline = df[df['timestamp'] < '2026-01-01']

# Calcular estadísticas
mean_logins = baseline.groupby('user')['count'].mean()
std_logins = baseline.groupby('user')['count'].std()

# Detectar anomalías (Z-score > 3)
current = df[df['timestamp'] >= '2026-01-01']
for user in current['user'].unique():
    user_logins = current[current['user'] == user]['count'].sum()
    z_score = (user_logins - mean_logins[user]) / std_logins[user]
    if abs(z_score) > 3:
        print(f"[ANOMALY] {user}: Z-score = {z_score:.2f}")
```

### 8.2 Machine learning para log anomalies

```python
from sklearn.ensemble import IsolationForest
import numpy as np

# Features: hour_of_day, request_size, response_time
X = df[['hour', 'size', 'response_time']].values

model = IsolationForest(contamination=0.1)
model.fit(X)

predictions = model.predict(X)
anomalies = df[predictions == -1]

print(f"Detected {len(anomalies)} anomalous entries")
anomalies.to_csv('log_anomalies.csv')
```

---

## 9. Correlación de Eventos

### 9.1 Detección de lateral movement

```bash
# Múltiples logons desde misma IP en corto tiempo
grep "Accepted password" auth.log | \
  awk '{print $1,$2,$3,$9,$11}' | \
  sort | uniq -c | \
  awk '$1 > 5 {print $0}'

# Correlación Windows: 4624 seguido de 4688 en múltiples hosts
# (requiere SIEM o script)
```

### 9.2 Kill chain detection

```bash
# Reconocimiento → Explotación → Instalación → C2
# Buscar secuencia de eventos:

# 1. Port scan (múltiples conexiones fallidas)
# 2. Exploit (web error 500 seguido de 200)
# 3. Malware drop (nuevo ejecutable + outbound connection)
# 4. C2 beacon (conexiones periódicas a IP externa)
```

---

## 10. Referencias

### Estándares
- **NIST SP 800-92**: Guide to Computer Security Log Management
- **ISO/IEC 27001**: Information Security Management
- **PCI DSS**: Requirement 10 (Log Management)

### Herramientas
- **ELK Stack**: https://www.elastic.co/
- **Splunk**: https://www.splunk.com/
- **Graylog**: https://www.graylog.org/
- **Wazuh**: https://wazuh.com/

### Certificaciones
- **GCFA**: GIAC Certified Forensic Analyst
- **Splunk Certified Power User**
- **Elastic Certified Analyst**
