# Análisis Forense de Dispositivos Móviles

## 1. Fundamentos de forensics móvil

### 1.1 Arquitectura de dispositivos móviles

#### Android (AOSP - Android Open Source Project)
- **Arquitectura en capas**: Linux Kernel → HAL → Android Runtime (ART) → Framework → Apps
- **Sistema de archivos**: ext4, f2fs, vfat
- **Particiones clave**: `/boot`, `/system`, `/vendor`, `/data`, `/cache`, `/recovery`
- **Seguridad**: SELinux (Security-Enhanced Linux), dm-verity, Verified Boot

#### iOS/iPadOS
- **XNU Kernel**: Híbrido Mach + BSD
- **Código signing obligatorio**: Todos los binarios deben estar firmados por Apple
- **Sandbox**: Cada app en contenedor aislado
- **Sistema de archivos**: APFS (Apple File System)
- **Secure Enclave**: Procesador criptográfico aislado (Touch ID/Face ID, claves)

### 1.2 Niveles de adquisición forense

| Nivel | Descripción | Datos Accesibles | Requerimientos |
|-------|-------------|------------------|----------------|
| **Manual** | Screenshots, fotos | Visible en UI | Ninguno |
| **Lógico** | Backup, APIs del OS | Apps, mensajes, media | USB debugging, autorización |
| **Sistema de archivos** | Acceso directo a particiones | Todo el filesystem | Root/Jailbreak |
| **Físico** | Imagen completa (NAND) | Datos eliminados, todo | Exploit, JTAG, chip-off |

### 1.3 Consideraciones legales

- **4th Amendment (EE.UU.)**: Expectativa razonable de privacidad
- **Riley v. California (2014)**: Warrant requerido para búsquedas de móviles
- **Carpenter v. United States (2018)**: Cell Site Location Information (CSLI) requiere warrant
- **GDPR (Europa)**: Protección de datos personales
- **Chain of Custody**: Documentación exhaustiva de posesión y análisis

---

## 2. Preparación y Aislamiento

### 2.1 Aislamiento de Dispositivo

```bash
# Objetivo: Evitar borrado remoto, sincronización, modificación de datos

# 1. INMEDIATAMENTE al obtener dispositivo:
# - Ponerlo en Modo Avión
# - Deshabilitar WiFi/Bluetooth
# - No introducir SIM propia
# - Mantener cargado (usar Faraday bag portable charger si disponible)

# 2. Jaula de Faraday
# - Bolsa de Faraday o caja metálica
# - Bloquea: GSM, 3G, 4G, 5G, WiFi, Bluetooth, NFC, GPS
# - Verificar con spectrum analyzer

# 3. Documentación inicial
CASE_ID="MOB-2026-001"
DEVICE_ID="IMEI_o_Serial"
TIMESTAMP=$(date -u +"%Y-%m-%d %H:%M:%S UTC")

cat > "${CASE_ID}_device_intake.txt" <<EOF
Case ID: ${CASE_ID}
Date/Time: ${TIMESTAMP}
Device Model: [anotar modelo exacto]
IMEI: [*#06# para ver]
Serial: [en settings o físicamente]
Condition: [encendido/apagado, batería %, daños físicos]
SIM Present: [Y/N]
Screen Lock: [Y/N - tipo]
Photos Taken: [de dispositivo físico, pantalla inicial]
Evidence Seal: [número de precinto]
Investigator: [nombre]
EOF
```

### 2.2 Decisión: Encendido vs Apagado

**SI el dispositivo está APAGADO:**
- **NO encenderlo** sin estrategia (puede activar cifrado, auto-wipe)
- Considerar extracción física (JTAG, chip-off) si es crítico
- Si debe encenderse: entorno Faraday, documentar todo

**SI el dispositivo está ENCENDIDO:**
- **NO apagar** (puede activar cifrado completo al reiniciar)
- Mantener cargado y en Faraday bag
- Intentar mantener desbloqueado si ya lo está
- Capturar datos volátiles inmediatamente

---

## 3. Extracción de Datos en Android

### 3.1 ADB (Android Debug Bridge) - extracción lógica

```bash
# Habilitar Developer Options & USB Debugging
# Settings → About Phone → tap "Build Number" 7 veces
# Settings → Developer Options → Enable "USB Debugging"

# Instalar Android SDK Platform Tools
wget https://dl.google.com/android/repository/platform-tools-latest-linux.zip
unzip platform-tools-latest-linux.zip
export PATH=$PATH:$PWD/platform-tools

# Verificar conexión
adb devices
# Autorizar en dispositivo cuando aparezca prompt

# Información del dispositivo
adb shell getprop ro.product.model
adb shell getprop ro.build.version.release
adb shell getprop ro.serialno

# Backup lógico (sin root)
adb backup -apk -shared -all -f "${CASE_ID}_backup.ab"
# Usuario debe confirmar en pantalla

# Convertir backup .ab a .tar
dd if="${CASE_ID}_backup.ab" bs=24 skip=1 | \
  openssl zlib -d > "${CASE_ID}_backup.tar"
tar -tf "${CASE_ID}_backup.tar" | head -20

# Extraer archivos específicos (si accesible sin root)
adb pull /sdcard/ "${CASE_ID}/sdcard/"
adb pull /sdcard/DCIM/ "${CASE_ID}/photos/"
adb pull /sdcard/Download/ "${CASE_ID}/downloads/"

# Logs del sistema
adb logcat -d > "${CASE_ID}/logcat.txt"
adb bugreport "${CASE_ID}/bugreport.zip"
```

### 3.2 Extracción con root (sistema de archivos completo)

```bash
# ADVERTENCIA: Rootear puede modificar evidencia
# Solo si legalmente autorizado y documentado

# Verificar si ya tiene root
adb shell su -c "id"

# Si tiene root, crear imagen completa
adb shell su -c "ls -la /dev/block/by-name/"
# Identificar particiones: userdata, system, boot

# Dump de partición /data (contiene todo lo importante)
adb shell su -c "dd if=/dev/block/mmcblk0p38 bs=4096" | \
  pv > "${CASE_ID}/userdata.img"

# O con netcat (más rápido)
# En PC:
nc -l -p 5555 > "${CASE_ID}/userdata.raw"
# En dispositivo:
adb shell su -c "dd if=/dev/block/mmcblk0p38 bs=4096 | nc <PC_IP> 5555"

# Hash de verificación
adb shell su -c "md5sum /dev/block/mmcblk0p38" > "${CASE_ID}/userdata.md5"

# Extraer filesystem completo
adb shell su -c "tar -czf /sdcard/full_backup.tar.gz /data/" 
adb pull /sdcard/full_backup.tar.gz "${CASE_ID}/"
```

### 3.3 Análisis de datos Android

```bash
# Estructura de /data/data/ (datos de apps)
# /data/data/com.android.providers.contacts/databases/contacts2.db
# /data/data/com.android.providers.telephony/databases/mmssms.db
# /data/data/com.whatsapp/databases/msgstore.db

# Extraer databases (con root)
adb shell su -c "cp /data/data/com.android.providers.telephony/databases/mmssms.db /sdcard/"
adb pull /sdcard/mmssms.db "${CASE_ID}/databases/"

# Analizar SQLite database
sqlite3 "${CASE_ID}/databases/mmssms.db" "SELECT * FROM sms LIMIT 10;"
sqlite3 "${CASE_ID}/databases/mmssms.db" ".schema"

# DB Browser for SQLite (GUI)
sqlitebrowser "${CASE_ID}/databases/mmssms.db"

# Contacts
sqlite3 "${CASE_ID}/databases/contacts2.db" \
  "SELECT display_name, data1 FROM view_contacts WHERE mimetype_id=5;" \
  > "${CASE_ID}/reports/contacts.txt"

# Call logs
sqlite3 "${CASE_ID}/databases/calllog.db" \
  "SELECT number, date, duration, type FROM calls ORDER BY date DESC;" \
  > "${CASE_ID}/reports/call_history.txt"

# Chrome history
sqlite3 "${CASE_ID}/databases/chrome_history.db" \
  "SELECT url, title, last_visit_time FROM urls ORDER BY last_visit_time DESC;" \
  > "${CASE_ID}/reports/browser_history.txt"
```

### 3.4 Análisis de aplicaciones Populares

#### WhatsApp

```bash
# Base de datos (necesita root o backup desencriptado)
# /data/data/com.whatsapp/databases/msgstore.db (cifrado si recent Android)

# Clave de cifrado (Android 4.4+)
adb shell su -c "cat /data/data/com.whatsapp/files/key" > whatsapp_key

# Descifrar con WhatsApp-Viewer o WhatCrypt
python3 wacrypt.py msgstore.db.crypt15 whatsapp_key msgstore_decrypted.db

# Analizar mensajes
sqlite3 msgstore_decrypted.db "SELECT * FROM message LIMIT 10;"
sqlite3 msgstore_decrypted.db <<EOF
SELECT 
  datetime(timestamp/1000, 'unixepoch') as time,
  key_remote_jid as contact,
  data as message,
  media_url
FROM message
ORDER BY timestamp DESC;
EOF
```

#### Telegram

```bash
# /data/data/org.telegram.messenger/files/
# cache4.db contiene mensajes

sqlite3 cache4.db "SELECT * FROM messages LIMIT 10;"
```

#### Gmail/Email

```bash
# /data/data/com.google.android.gm/databases/
sqlite3 mailstore.db "SELECT * FROM messages WHERE fromAddress LIKE '%@%';"
```

### 3.5 Herramientas forenses especializadas

```bash
# Autopsy con módulo Android Analyzer
# https://www.autopsy.com/

# ALEAPP (Android Logs Events And Protobuf Parser)
git clone https://github.com/abrignoni/ALEAPP.git
cd ALEAPP
python3 aleapp.py -t fs -i /path/to/extracted/data -o output_folder

# Andriller (Open Source)
pip3 install andriller
andriller-gui  # GUI mode

# AXIOM (Commercial - Magnet Forensics)
# Cellebrite UFED (Commercial)
# Oxygen Forensics (Commercial)
```

---

## 4. Extracción de Datos en iOS

### 4.1 iTunes Backup (método más común)

```bash
# Conectar dispositivo iOS via USB
# Confiar en la computadora (aparecerá prompt en dispositivo)

# Backup con iTunes/Finder (macOS Catalina+)
# macOS:
# Finder → Dispositivo → Backup Now → Encrypt (IMPORTANTE: recordar password)

# Windows/Linux con libimobiledevice:
sudo apt install libimobiledevice-utils ifuse
ideviceinfo  # Ver info del dispositivo
idevicepair pair  # Emparejar
idevicebackup2 backup --full "${CASE_ID}/ios_backup/"

# Localización de backups:
# macOS: ~/Library/Application Support/MobileSync/Backup/
# Windows: %APPDATA%\Apple Computer\MobileSync\Backup\
# Linux: ~/.local/share/idevicebackup/

# Listar archivos del backup
cd ~/Library/Application\ Support/MobileSync/Backup/[UDID]/
ls -lh
```

### 4.2 Análisis de Backup iOS

```bash
# Estructura de backup iOS:
# - Info.plist: metadata del dispositivo
# - Manifest.db: índice de archivos
# - Archivos hasheados (SHA1 de domain+path)

# Extraer Info.plist
plutil -p Info.plist

# Analizar Manifest.db
sqlite3 Manifest.db "SELECT fileID, domain, relativePath FROM Files LIMIT 10;"

# Backup Explorer tools
# iBackup Viewer (GUI)
# iMazing (Commercial)

# Herramienta CLI: iphone-backup-tools
npm install -g iphone-backup-tools
ibackuptool -b ~/Library/Application\ Support/MobileSync/Backup/[UDID] \
  --export "${CASE_ID}/ios_extracted/"
```

### 4.3 Extracción de Artefactos iOS

```python
#!/usr/bin/env python3
# ios_backup_parser.py

import sqlite3
import plistlib
import os
import hashlib

BACKUP_PATH = "/path/to/backup/[UDID]"
OUTPUT = "/output/path"

# Parse Manifest.db
conn = sqlite3.connect(f"{BACKUP_PATH}/Manifest.db")
cursor = conn.cursor()

# SMS/iMessage
cursor.execute("""
    SELECT fileID, relativePath 
    FROM Files 
    WHERE relativePath LIKE '%sms.db%'
""")

for row in cursor.fetchall():
    file_id = row[0]
    # iOS backup files named as hash
    src = f"{BACKUP_PATH}/{file_id[:2]}/{file_id}"
    if os.path.exists(src):
        os.system(f"cp {src} {OUTPUT}/sms.db")

# Contacts
cursor.execute("""
    SELECT fileID 
    FROM Files 
    WHERE relativePath LIKE '%AddressBook.sqlitedb%'
""")
# Similar extraction...

# Call history
cursor.execute("""
    SELECT fileID 
    FROM Files 
    WHERE relativePath LIKE '%call_history.db%'
""")
# ...

conn.close()
print("[+] Extraction complete")
```

### 4.4 Análisis de Databases iOS

```bash
# SMS/iMessage
sqlite3 "${CASE_ID}/ios_extracted/sms.db" <<EOF
SELECT 
  datetime(date + 978307200, 'unixepoch') as date,
  handle.id as contact,
  text,
  is_from_me
FROM message
LEFT JOIN handle ON message.handle_id = handle.ROWID
ORDER BY date DESC
LIMIT 50;
EOF

# Contacts
sqlite3 "${CASE_ID}/ios_extracted/AddressBook.sqlitedb" <<EOF
SELECT 
  First, Last, 
  (SELECT value FROM ABMultiValue WHERE record_id = ABPerson.ROWID AND label = 3) as phone
FROM ABPerson;
EOF

# Call History
sqlite3 "${CASE_ID}/ios_extracted/call_history.db" <<EOF
SELECT 
  datetime(date, 'unixepoch') as call_time,
  address as number,
  duration,
  CASE 
    WHEN service_provider = 1 THEN 'FaceTime'
    ELSE 'Phone'
  END as type
FROM call
ORDER BY date DESC;
EOF

# Safari history
sqlite3 "${CASE_ID}/ios_extracted/History.db" <<EOF
SELECT 
  url, 
  title,
  datetime(visit_time + 978307200, 'unixepoch') as visit
FROM history_visits
JOIN history_items ON history_visits.history_item = history_items.id
ORDER BY visit_time DESC;
EOF
```

### 4.5 Análisis de apps populares (iOS)

```bash
# WhatsApp
# Backup iOS incluye: AppDomain-net.whatsapp.WhatsApp
# ChatStorage.sqlite contiene mensajes

sqlite3 ChatStorage.sqlite <<EOF
SELECT 
  datetime(ZMESSAGEDATE + 978307200, 'unixepoch'),
  ZTEXT,
  ZFROMJID
FROM ZWAMESSAGE
ORDER BY ZMESSAGEDATE DESC
LIMIT 50;
EOF

# Health data (HealthKit)
# healthdb_secure.sqlite
sqlite3 healthdb_secure.sqlite "SELECT * FROM samples LIMIT 10;"

# Photos metadata
# Photos.sqlite in PhotoData/
sqlite3 Photos.sqlite "SELECT * FROM ZGENERICASSET LIMIT 10;"
```

### 4.6 Advanced: Jailbreak y SSH

```bash
# Si dispositivo ya está jailbroken (Checkra1n, unc0ver, etc.)
# SSH disponible en puerto 22 (credenciales default: root/alpine)

# Cambiar password root INMEDIATAMENTE
ssh root@<iPhone_IP>
passwd

# Montar filesystem via SSH
sshfs root@<iPhone_IP>:/ /mnt/iphone/

# Extraer particiones completas
ssh root@<iPhone_IP> "dd if=/dev/rdisk0s1s1" | dd of=iphone_system.img

# Instalar OpenSSH en jailbreak:
# Cydia → Search → OpenSSH
```

### 4.7 Herramientas forenses iOS

```bash
# libimobiledevice suite (open source)
apt install libimobiledevice-utils

# iLEAPP (iOS Logs, Events, And Plists Parser)
git clone https://github.com/abrignoni/iLEAPP.git
python3 ileapp.py -t fs -i /path/to/ios/data -o output/

# Elcomsoft iOS Forensic Toolkit (Commercial)
# Cellebrite Physical Analyzer (Commercial)
# Magnet AXIOM (Commercial)

# Checkra1n exploit (iOS 12-14.8)
# https://checkra.in/
# Permite jailbreak para análisis profundo
```

---

## 5. Análisis de Geolocalización

### 5.1 Android location data

```bash
# Google Location History
# /data/data/com.google.android.gms/databases/
sqlite3 gms.db "SELECT * FROM location_history;"

# Cache de ubicaciones (si disponible)
adb shell dumpsys location > location_dump.txt

# WiFi networks conocidas
adb shell cat /data/misc/wifi/WifiConfigStore.xml
```

### 5.2 iOS location data

```bash
# Consolidated.db (iOS antiguo)
sqlite3 consolidated.db <<EOF
SELECT 
  datetime(Timestamp + 978307200, 'unixepoch'),
  Latitude,
  Longitude,
  HorizontalAccuracy
FROM CellLocation
ORDER BY Timestamp DESC;
EOF

# Cache.sqlite (iOS moderno)
sqlite3 cache_encryptedA.db "SELECT * FROM zrtcllocationmo;"

# Visualizar en mapa (herramienta: iPhone Analyzer)
```

### 5.3 Visualización de Geo-datos

```python
#!/usr/bin/env python3
# plot_locations.py

import sqlite3
import folium

# Conectar a DB
conn = sqlite3.connect('location_data.db')
cursor = conn.cursor()

# Obtener coordenadas
cursor.execute("SELECT latitude, longitude FROM locations")
locations = cursor.fetchall()

# Crear mapa
m = folium.Map(location=[locations[0][0], locations[0][1]], zoom_start=12)

for lat, lon in locations:
    folium.Marker([lat, lon]).add_to(m)

m.save('location_map.html')
print("[+] Map generated: location_map.html")
```

---

## 6. Análisis de Medios y Artefactos

### 6.1 Recuperación de fotos/videos eliminados

```bash
# Photorec en imagen de partición
photorec /d "${CASE_ID}/recovered_media" userdata.img

# Extracción de thumbnails (Android)
adb pull /data/data/com.android.providers.media/databases/external.db
sqlite3 external.db "SELECT _data FROM thumbnails;"

# EXIF metadata analysis
exiftool -r -csv "${CASE_ID}/photos/" > photo_metadata.csv
```

### 6.2 Análisis de Audio/Grabaciones

```bash
# Grabadora de voz
# Android: /sdcard/Recordings/ o /sdcard/Voice Recorder/
# iOS: en backup bajo MediaDomain

# Convertir formatos
for file in *.m4a; do
  ffmpeg -i "$file" "${file%.m4a}.wav"
done

# Análisis forense de audio (detección de edición)
# Herramientas: Adobe Audition, Audacity (spectrum analysis)
```

---

## 7. Análisis de Red y Comunicaciones

### 7.1 Captura de tráfico móvil

```bash
# Método 1: tcpdump en dispositivo rooteado
adb shell su -c "tcpdump -i any -w /sdcard/traffic.pcap"
adb pull /sdcard/traffic.pcap

# Método 2: Proxy (mitmproxy, Burp Suite)
# Instalar certificado CA en dispositivo
# Configurar proxy: Settings → WiFi → Advanced → Proxy

mitmproxy --mode regular --host
# Dispositivo apunta a proxy en puerto 8080

# Método 3: WiFi hotspot en PC con Wireshark
# PC crea hotspot, dispositivo se conecta
# Capturar con Wireshark en interfaz de red compartida
```

### 7.2 Análisis de SIM card

```bash
# Leer SIM con card reader (USB)
# Herramientas: pysim, SIMtrace

# Extraer información
pySim-read.py -p0  # PC/SC reader en slot 0

# Contenido típico:
# - ICCID (SIM serial)
# - IMSI (International Mobile Subscriber Identity)
# - SMS almacenados en SIM
# - Contactos en SIM (ADN)
# - LOCI (Location Information)
# - Call history (si soportado)

# Clonar SIM (solo con fines forenses, requiere Ki)
# ADVERTENCIA: Ilegal sin autorización
```

---

## 8. Análisis de Cifrado y Seguridad

### 8.1 Android encryption

```bash
# Verificar estado de cifrado
adb shell getprop ro.crypto.state
# encrypted = FDE (Full Disk Encryption) o FBE (File-Based Encryption)

# FDE (Android <7): Todo /data cifrado con password/PIN
# FBE (Android 7+): Cada usuario/archivo con claves separadas

# Brute-force de patrón/PIN (solo con acceso físico)
# Herramientas comerciales: Cellebrite, GrayKey

# Desbloqueo con ADB (solo si USB debugging previamente habilitado)
adb shell input text <PIN>
adb shell input keyevent 66  # Enter
```

### 8.2 iOS encryption & Secure Enclave

```bash
# iOS siempre cifrado (desde iOS 8)
# Clave derivada de: passcode + UID hardware

# Data Protection Classes:
# NSFileProtectionComplete: accesible solo cuando desbloqueado
# NSFileProtectionCompleteUnlessOpen: ...
# NSFileProtectionCompleteUntilFirstUserAuthentication: default

# Ataques conocidos:
# - GrayKey (Grayshift): exploit de iOS <=14.6
# - Checkm8 (bootrom exploit): iPhone 4s - iPhone X
# - Pegasus (NSO Group): spyware avanzado

# Extracción con exploit checkm8
# https://github.com/axi0mX/ipwndfu
python3 ipwndfu.py -p  # Pwn DFU mode

# Después de exploit, extraer con herramientas forenses
```

---

## 9. Análisis cloud y sincronización

### 9.1 Google Account data

```bash
# Google Takeout: https://takeout.google.com/
# Exportar: Location History, Chrome, Photos, Drive, Gmail, etc.

# Analizar JSON de Location History
jq '.locations[] | {timestamp: .timestampMs, lat: .latitudeE7, lon: .longitudeE7}' \
  LocationHistory.json | head -20

# Timeline de Google
# https://www.google.com/maps/timeline
```

### 9.2 iCloud data

```bash
# Extracción de iCloud (requiere credenciales)
# Herramienta: Elcomsoft Phone Breaker (Commercial)

# iCloud Backup download
# pyicloud (Python library)
pip3 install pyicloud
icloud --username apple@id.com

# 2FA puede requerir código de verificación
# Descargar backup más reciente
```

### 9.3 WhatsApp cloud backups

```bash
# Android: Google Drive
# iOS: iCloud Drive

# Extraer de Google Drive (requiere acceso a cuenta)
# WhatsDump: https://github.com/

# Descifrado de backup (requiere key)
# Key almacenada localmente en /data/data/com.whatsapp/files/key
```

---

## 10. Reporting y Documentación

### 10.1 Plantilla de Reporte

```markdown
# Análisis Forense Móvil - ${CASE_ID}

## 1. Información del Dispositivo
- **Marca/Modelo**: [Samsung Galaxy S21 / iPhone 13 Pro]
- **IMEI**: [...]
- **Serial Number**: [...]
- **Sistema Operativo**: [Android 13 / iOS 16.2]
- **Capacidad**: [128GB]

## 2. Adquisición
- **Fecha/Hora**: [2026-01-30 14:30 UTC]
- **Método**: [ADB Backup / iTunes Encrypted Backup]
- **Hash de Imagen**: 
  - SHA256: [...]
- **Herramientas**: [adb, libimobiledevice]

## 3. Hallazgos clave
### 3.1 Comunicaciones
- Total SMS: [5,432]
- Mensajes WhatsApp: [12,453]
- Llamadas: [892]
- Período: [2024-01-01 to 2026-01-30]

### 3.2 Geolocalización
- Ubicaciones registradas: [45,234]
- Rango de fechas: [...]
- Mapa adjunto: [Anexo A]

### 3.3 Aplicaciones instaladas
[Lista de apps con versiones]

### 3.4 Contenido multimedia
- Fotos: [3,421]
- Videos: [234]
- Audio: [45]

## 4. Evidencia de Interés
[Describir hallazgos relevantes al caso]

## 5. Conclusiones
[Resumen ejecutivo]

## 6. Anexos
- A: Mapa de ubicaciones
- B: Timeline completo
- C: Lista de contactos
- D: Hash de todos los archivos extraídos
```

### 10.2 Generación automática de timeline

```python
#!/usr/bin/env python3
# mobile_timeline.py

import sqlite3
import csv
from datetime import datetime

def generate_timeline(sms_db, call_db, output_csv):
    events = []
    
    # SMS
    conn = sqlite3.connect(sms_db)
    cursor = conn.cursor()
    cursor.execute("SELECT date, address, body, type FROM sms")
    for row in cursor.fetchall():
        events.append({
            'timestamp': row[0],
            'type': 'SMS' if row[3] == 1 else 'SMS_Sent',
            'contact': row[1],
            'detail': row[2]
        })
    conn.close()
    
    # Calls
    conn = sqlite3.connect(call_db)
    cursor = conn.cursor()
    cursor.execute("SELECT date, number, duration, type FROM calls")
    for row in cursor.fetchall():
        events.append({
            'timestamp': row[0],
            'type': 'Call',
            'contact': row[1],
            'detail': f"Duration: {row[2]}s"
        })
    conn.close()
    
    # Sort by timestamp
    events.sort(key=lambda x: x['timestamp'])
    
    # Write CSV
    with open(output_csv, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=['timestamp', 'type', 'contact', 'detail'])
        writer.writeheader()
        writer.writerows(events)
    
    print(f"[+] Timeline generated: {output_csv}")

generate_timeline('sms.db', 'calllog.db', 'mobile_timeline.csv')
```

---

## 11. Referencias y recursos avanzados

### Libros fundamentales
- Hoog, A. (2011). *Android Forensics: Investigation, Analysis and Mobile Security for Google Android*
- Morrissey, S. (2010). *iOS Forensic Analysis for iPhone, iPad, and iPod touch*
- Tindall, D. (2015). *Practical Mobile Forensics*. Packt Publishing

### Papers académicos
- Barmpatsalou, K. et al. (2018). "A Critical Reflection on Cell Phone Forensic Tools"
- Levinson, A. et al. (2011). "Android Forensics: Techniques and Tools"
- Zareen, K. et al. (2013). "iOS Forensics: A Systematic Literature Review"

### Frameworks y Estándares
- **NIST SP 800-101 Rev. 1**: Guidelines on Mobile Device Forensics
- **SWGDE (Scientific Working Group on Digital Evidence)**: Best Practices for Mobile Phone Forensics
- **ISO/IEC 27037:2012**: Guidelines for digital evidence handling

### Herramientas open source
- **ALEAPP** (Android): https://github.com/abrignoni/ALEAPP
- **iLEAPP** (iOS): https://github.com/abrignoni/iLEAPP
- **libimobiledevice**: https://libimobiledevice.org/
- **Android Backup Extractor**: https://github.com/nelenkov/android-backup-extractor
- **MVT (Mobile Verification Toolkit)**: https://github.com/mvt-project/mvt (detección de Pegasus)

### Herramientas comerciales
- **Cellebrite UFED**: Líder de industria, soporte amplio
- **Magnet AXIOM**: Análisis completo de dispositivos
- **Oxygen Forensics**: Android/iOS/Cloud
- **XRY (MSAB)**: Extracción y análisis
- **GrayKey (Grayshift)**: Desbloqueo de iOS

### Certificaciones especializadas
- **GIAC Mobile Device Examiner (GMOB)**: SANS FOR585
- **Cellebrite Certified Mobile Examiner (CCME)**
- **Cellebrite Certified Physical Analyst (CCPA)**
- **EnCase Certified Examiner (EnCE)**

### Comunidad y Recursos
- **SANS DFIR Summit**: Conferencias y whitepapers
- **r/mobileforensics**: Reddit community
- **Forensic Focus**: Forums y artículos
- **MobileForensicsWorld**: Newsletter y recursos

---

## 12. Consideraciones Éticas y Legales

### Legalidad de Métodos
- **Jailbreaking/Rooting**: Legal para investigación pero modifica evidencia
- **Bypass de bloqueo**: Requiere autorización legal (warrant)
- **Acceso a cloud**: Requiere consentimiento o court order
- **Chain of custody**: Documentar TODOS los pasos

### Privacidad
- **PII (Personally Identifiable Information)**: Manejar con cuidado
- **Attorney-client privilege**: Identificar y segregar comunicaciones protegidas
- **Medical records**: HIPAA compliance (EE.UU.)
- **Financial data**: PCI-DSS considerations

### Mejores prácticas
1. **Documentación exhaustiva**: Fotos, logs, timestamps
2. **Verificación de integridad**: Hashes antes/después
3. **Trabajo en copias**: Nunca modificar original
4. **Herramientas validadas**: Software forense reconocido
5. **Formación continua**: Tecnología móvil evoluciona rápidamente
