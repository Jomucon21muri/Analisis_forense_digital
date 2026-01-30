# Análisis forense de dispositivos de almacenamiento

## 1. Fundamentos teóricos y marco metodológico

### 1.1 Principios de Locard y cadena de custodia digital

El análisis forense de discos se fundamenta en el **Principio de Intercambio de Locard** aplicado al contexto digital: toda interacción con un sistema de archivos deja rastros recuperables. La preservación de evidencia digital sigue el estándar **ISO/IEC 27037:2012** para identificación, recolección, adquisición y preservación de evidencia digital.

### 1.2 Taxonomía de dispositivos de almacenamiento

- **Dispositivos magnéticos (HDD)**: Sectores de 512B/4KB, recuperación por análisis de superficie
- **Dispositivos de estado sólido (SSD)**: TRIM, wear leveling, garbage collection (complejidad forense)
- **Dispositivos híbridos (SSHD)**: Combinación de tecnologías con cache SSD
- **Almacenamiento NVMe**: PCIe, latencias ultra-bajas, desafíos de adquisición en caliente
- **RAID y volúmenes lógicos**: LVM, mdadm, reconstrucción de arrays degradados

### 1.3 Sistemas de archivos: análisis estructural

#### ext4 (Linux)
- **Superblock**: Información crítica del filesystem (ubicación en offset 0x400)
- **Inodes**: Metadatos de archivos (timestamps: atime, mtime, ctime, crtime/btime)
- **Journal**: Registro de transacciones para recuperación (`jbd2`)
- **Extended attributes**: xattr para metadatos extendidos y contextos SELinux

#### NTFS (Windows)
- **$MFT (Master File Table)**: Entrada de 1024 bytes por archivo
- **$LogFile**: Registro transaccional NTFS
- **$USNJrnl**: Update Sequence Number Journal (tracking de cambios)
- **Alternate Data Streams (ADS)**: Flujos ocultos de datos
- **Volume Shadow Copies**: Copias VSS para recuperación temporal

#### APFS (macOS/iOS)
- **Container structure**: Contenedores con múltiples volúmenes
- **Snapshots**: Capturas instantáneas del sistema de archivos
- **Encryption**: FileVault 2 y encriptación nativa por archivo
- **Clone and Copy-on-Write**: Optimización espacial

#### exFAT/FAT32
- **FAT (File Allocation Table)**: Tabla de asignación de clusters
- **Directorio raíz**: Entradas de archivo con timestamps limitados
- **Slack space**: Espacio no utilizado en clusters

---

## 2. Metodología de adquisición forense

### 2.1 Preparación del entorno

```bash
# Verificar integridad de herramientas forenses
sha256sum /usr/bin/dcfldd /usr/bin/ewfacquire
apt list --installed | grep -E "sleuthkit|autopsy|libewf"

# Documentar hardware del sistema
lsblk -f -o NAME,SIZE,FSTYPE,MOUNTPOINT,UUID,MODEL
hdparm -I /dev/sdX  # Información detallada del disco
smartctl -a /dev/sdX  # SMART attributes

# Preparar directorio de trabajo con timestamps
CASE_ID="CASE-2026-001"
EVIDENCE_DIR="/mnt/evidence/${CASE_ID}"
mkdir -p "${EVIDENCE_DIR}"/{raw,mounts,reports,logs}
```

### 2.2 Adquisición de imagen forense (método 1: dd/dcfldd)

```bash
# Bloquear escritura física (recomendado: write blocker hardware)
blockdev --setro /dev/sdX

# Verificar estado de solo lectura
blockdev --getro /dev/sdX  # Debe retornar 1

# Adquisición bit-a-bit con dcfldd (con hashing integrado)
dcfldd if=/dev/sdX \
       of="${EVIDENCE_DIR}/raw/${CASE_ID}_disk.dd" \
       hash=sha256 \
       hashlog="${EVIDENCE_DIR}/logs/${CASE_ID}_hash.log" \
       bs=4M \
       conv=noerror,sync \
       status=progress

# Adquisición con compresión y split (discos grandes)
dcfldd if=/dev/sdX bs=4M conv=noerror,sync | \
  split -b 2G --filter='pigz -9 > "${EVIDENCE_DIR}/raw/${CASE_ID}_disk_part_$FILE.dd.gz"'

# Verificación post-adquisición
sha256sum "${EVIDENCE_DIR}/raw/${CASE_ID}_disk.dd" | \
  tee "${EVIDENCE_DIR}/logs/${CASE_ID}_verification.log"
```

### 2.3 Adquisición en formato EWF (Expert Witness Format)

```bash
# E01 format (compatible con FTK, EnCase)
ewfacquire /dev/sdX \
  -t "${EVIDENCE_DIR}/raw/${CASE_ID}" \
  -C "${CASE_ID}" \
  -D "Descripción del caso" \
  -E "Nombre del examinador" \
  -e "Organización" \
  -N "Notas adicionales" \
  -m removable \
  -M logical \
  -c deflate:best \
  -f encase6 \
  -S 4.0GiB \
  -u

# Verificación de integridad E01
ewfverify "${EVIDENCE_DIR}/raw/${CASE_ID}.E01"
ewfinfo "${EVIDENCE_DIR}/raw/${CASE_ID}.E01" > \
  "${EVIDENCE_DIR}/logs/${CASE_ID}_ewf_metadata.txt"
```

### 2.4 Adquisición de memoria de disco en caliente (live acquisition)

```bash
# Para sistemas en producción que no pueden detenerse
# Crear snapshot con LVM (si está disponible)
lvcreate -L 10G -s -n forensic_snap /dev/vg_data/lv_prod
dd if=/dev/vg_data/forensic_snap of=/mnt/external/live_snap.dd bs=4M

# O usar herramientas específicas
linpmem -o /mnt/external/memory_dump.aff4
```

---

## 3. Análisis del sistema de archivos

### 3.1 Montaje forense (read-only)

```bash
# Obtener información de particiones
mmls "${EVIDENCE_DIR}/raw/${CASE_ID}_disk.dd"
# Identificar offset de particiones (unidades de 512 bytes)

# Montar ext4 en solo lectura con norecovery
OFFSET_BYTES=$((2048 * 512))  # Ejemplo: sector 2048
mount -o ro,loop,noload,norecovery,offset=${OFFSET_BYTES} \
  "${EVIDENCE_DIR}/raw/${CASE_ID}_disk.dd" \
  "${EVIDENCE_DIR}/mounts/partition1"

# Montar NTFS con ntfs-3g (solo lectura)
mount -t ntfs-3g -o ro,loop,offset=${OFFSET_BYTES},norecovery \
  "${EVIDENCE_DIR}/raw/${CASE_ID}_disk.dd" \
  "${EVIDENCE_DIR}/mounts/partition1"

# Alternativa: usar ewfmount para E01
ewfmount "${EVIDENCE_DIR}/raw/${CASE_ID}.E01" /mnt/ewf1
mount -o ro,loop,offset=${OFFSET_BYTES} /mnt/ewf1/ewf1 \
  "${EVIDENCE_DIR}/mounts/partition1"
```

### 3.2 Análisis con The Sleuth Kit (TSK)

```bash
# Listar particiones y obtener layout
mmls -t dos "${EVIDENCE_DIR}/raw/${CASE_ID}_disk.dd"

# Identificar tipo de filesystem
fsstat -o ${OFFSET_SECTORS} "${EVIDENCE_DIR}/raw/${CASE_ID}_disk.dd"

# Listar archivos (incluidos borrados)
fls -r -p -o ${OFFSET_SECTORS} "${EVIDENCE_DIR}/raw/${CASE_ID}_disk.dd" > \
  "${EVIDENCE_DIR}/reports/file_listing_full.txt"

# Timeline (Body file format para Mactime)
fls -r -m "/" -o ${OFFSET_SECTORS} "${EVIDENCE_DIR}/raw/${CASE_ID}_disk.dd" > \
  "${EVIDENCE_DIR}/reports/body_file.txt"

# Generar timeline legible
mactime -b "${EVIDENCE_DIR}/reports/body_file.txt" \
  -d -z UTC > "${EVIDENCE_DIR}/reports/timeline_full.csv"

# Extraer archivo específico por inode
icat -o ${OFFSET_SECTORS} "${EVIDENCE_DIR}/raw/${CASE_ID}_disk.dd" 12345 > \
  "${EVIDENCE_DIR}/reports/extracted_file_inode12345.bin"

# Análisis de metadata de archivo
istat -o ${OFFSET_SECTORS} "${EVIDENCE_DIR}/raw/${CASE_ID}_disk.dd" 12345
```

### 3.3 Recuperación de archivos eliminados

```bash
# PhotoRec: Recuperación por file carving (headers/footers)
photorec /d "${EVIDENCE_DIR}/recovered" \
         /cmd "${EVIDENCE_DIR}/raw/${CASE_ID}_disk.dd" \
         partition_none,options,paranoid,fileopt,everything,search

# TestDisk: Recuperación de particiones y estructura
testdisk "${EVIDENCE_DIR}/raw/${CASE_ID}_disk.dd"

# Scalpel: File carving avanzado
scalpel "${EVIDENCE_DIR}/raw/${CASE_ID}_disk.dd" \
  -o "${EVIDENCE_DIR}/carved" \
  -c /etc/scalpel/scalpel.conf

# Foremost: Alternativa de carving
foremost -t all -i "${EVIDENCE_DIR}/raw/${CASE_ID}_disk.dd" \
  -o "${EVIDENCE_DIR}/foremost_output"
```

### 3.4 Análisis de slack space y unallocated space

```bash
# Extraer espacio no asignado
blkls -o ${OFFSET_SECTORS} "${EVIDENCE_DIR}/raw/${CASE_ID}_disk.dd" > \
  "${EVIDENCE_DIR}/reports/unallocated_space.raw"

# Buscar strings en espacio no asignado
strings -a -t d "${EVIDENCE_DIR}/reports/unallocated_space.raw" | \
  grep -iE "(password|credit.?card|ssn|confidential)" > \
  "${EVIDENCE_DIR}/reports/sensitive_strings.txt"

# Búsqueda de patrones con bulk_extractor
bulk_extractor -o "${EVIDENCE_DIR}/bulk_output" \
  -E email -E net -E json -E ccn \
  "${EVIDENCE_DIR}/raw/${CASE_ID}_disk.dd"
```

---

## 4. Análisis de artefactos específicos por sistema operativo

### 4.1 Windows: análisis NTFS profundo

```bash
# Parsear $MFT
analyzeMFT.py -f /mnt/evidence/\$MFT -o mft_timeline.csv

# Extraer $LogFile
icat -o ${OFFSET} "${CASE_ID}_disk.dd" 2 > \$LogFile
# Analizar con LogFileParser

# USN Journal analysis
icat -o ${OFFSET} "${CASE_ID}_disk.dd" "\$Extend/\$UsnJrnl:\$J" > usn_journal.bin
python usn.py -f usn_journal.bin -o usn_analysis.csv

# Volume Shadow Copy extraction
vshadowmount image.E01 /mnt/vss
ls /mnt/vss/  # vss1, vss2, etc.
```

### 4.2 Linux: análisis ext4 journal

```bash
# Extraer journal
debugfs -R "dump <8> journal.bin" "${CASE_ID}_disk.dd"

# Analizar journal con jls (TSK)
jls -o ${OFFSET} "${CASE_ID}_disk.dd"

# Extended attributes enumeration
getfattr -d -m ".*" -R /mnt/evidence/ > xattr_dump.txt
```

### 4.3 macOS: APFS forensics

```bash
# Montar APFS en Linux (requiere kernel 4.9+)
apt install apfs-fuse
mkdir /mnt/apfs
apfs-fuse -o ro "${CASE_ID}_disk.dd" /mnt/apfs

# Analizar snapshots
apfs-snap list "${CASE_ID}_disk.dd"

# Parsear registros unificados (si disponibles)
log show --predicate 'eventMessage contains "suspicious"' \
  --style syslog --source /mnt/apfs/var/db/diagnostics
```

---

## 5. Timeline forense y análisis temporal

### 5.1 Construcción de super timeline con Plaso/Log2timeline

```bash
# Generar plaso storage
log2timeline.py --storage-file "${CASE_ID}_timeline.plaso" \
  --partitions all --vss-stores all \
  "${EVIDENCE_DIR}/raw/${CASE_ID}_disk.dd"

# Filtrar y exportar a CSV
psort.py -o l2tcsv -w "${CASE_ID}_timeline_full.csv" \
  "${CASE_ID}_timeline.plaso"

# Análisis temporal con filtros
psort.py -o l2tcsv \
  --slice "2025-01-01 00:00:00" \
  --slice_size 24 \
  -w "${CASE_ID}_timeline_filtered.csv" \
  "${CASE_ID}_timeline.plaso"
```

### 5.2 Análisis de anomalías temporales

```bash
# Detección de timestomping
python3 <<EOF
import csv
import datetime

with open('mft_timeline.csv', 'r') as f:
    reader = csv.DictReader(f)
    for row in reader:
        created = datetime.datetime.fromisoformat(row['created'])
        modified = datetime.datetime.fromisoformat(row['modified'])
        if created > modified:
            print(f"ANOMALY: {row['filename']} - Created after Modified")
EOF
```

---

## 6. Análisis avanzado: hashing y correlación

### 6.1 Hash set analysis

```bash
# Generar hashes de todos los archivos
find /mnt/evidence -type f -exec sha256sum {} \; > \
  "${EVIDENCE_DIR}/reports/file_hashes.txt"

# Comparar con NSRL (National Software Reference Library)
# Descargar NSRL RDS: https://www.nist.gov/itl/ssd/software-quality-group/national-software-reference-library-nsrl/nsrl-download
hfind -q "${EVIDENCE_DIR}/reports/file_hashes.txt" \
  /opt/nsrl/NSRLFile.txt > known_files.txt

# Identificar archivos desconocidos (potencialmente maliciosos)
comm -23 <(sort "${EVIDENCE_DIR}/reports/file_hashes.txt") \
         <(sort known_files.txt) > unknown_files.txt

# VirusTotal batch checking
while read hash; do
  curl -s --request GET \
    --url "https://www.virustotal.com/api/v3/files/${hash}" \
    --header "x-apikey: YOUR_API_KEY" | \
    jq '.data.attributes.last_analysis_stats'
done < unknown_files.txt
```

### 6.2 Fuzzy hashing (ssdeep)

```bash
# Generar ssdeep hashes para detectar archivos similares
ssdeep -r /mnt/evidence > "${EVIDENCE_DIR}/reports/ssdeep_hashes.txt"

# Comparar conjuntos de hashes
ssdeep -m "${EVIDENCE_DIR}/reports/ssdeep_baseline.txt" \
       -r /mnt/evidence
```

---

## 7. Análisis de cifrado y protección

### 7.1 Detección de volúmenes cifrados

```bash
# Detectar LUKS (Linux)
cryptsetup luksDump /dev/sdX1

# Detectar BitLocker (Windows)
bdeinfo "${CASE_ID}_disk.dd"

# Intentar recuperación de claves (si disponibles en memoria)
bulk_extractor -E aes -E base64 \
  -o "${EVIDENCE_DIR}/crypto_keys" \
  memory_dump.raw
```

### 7.2 Análisis de containers cifrados

```bash
# TrueCrypt/VeraCrypt detection
veracrypt --text --list "${CASE_ID}_disk.dd"

# LUKS decryption (con clave)
cryptsetup luksOpen /dev/loop0 evidence_unlocked
mount -o ro /dev/mapper/evidence_unlocked /mnt/unlocked
```

---

## 8. Documentación y generación de informes

### 8.1 Cadena de custodia

```bash
# Generar reporte de integridad
cat > "${EVIDENCE_DIR}/reports/chain_of_custody.md" <<EOF
# Cadena de Custodia - ${CASE_ID}

## Información del Dispositivo
- Modelo: $(hdparm -I /dev/sdX | grep "Model Number")
- Serie: $(hdparm -I /dev/sdX | grep "Serial Number")
- Capacidad: $(blockdev --getsize64 /dev/sdX) bytes

## Hash de imagen original
\`\`\`
$(cat "${EVIDENCE_DIR}/logs/${CASE_ID}_hash.log")
\`\`\`

## Examinador
- Nombre: [Nombre del analista]
- Fecha/Hora de adquisición: $(date -u +"%Y-%m-%d %H:%M:%S UTC")
- Herramientas: dcfldd $(dcfldd --version | head -1)
EOF
```

### 8.2 Automatización con Autopsy/Sleuth Kit

```bash
# Crear caso en Autopsy (interfaz gráfica recomendada)
# Alternativa: análisis por línea de comandos

# Generar reporte HTML automático
tsk_recover -e "${EVIDENCE_DIR}/raw/${CASE_ID}_disk.dd" \
  "${EVIDENCE_DIR}/recovered_all"

# Indexar con Elasticsearch para búsquedas avanzadas
python3 <<EOF
from elasticsearch import Elasticsearch
import json

es = Elasticsearch(['http://localhost:9200'])

# Indexar timeline
with open('${CASE_ID}_timeline_full.csv') as f:
    # ... código de indexación ...
EOF
```

---

## 9. Validación y reproducibilidad

### 9.1 Verificación de integridad

```bash
# Validación continua con hash trees
hashdeep -c sha256 -r /mnt/evidence > hash_tree_baseline.txt

# Verificación posterior
hashdeep -c sha256 -r -a -k hash_tree_baseline.txt /mnt/evidence

# Firma digital del reporte
gpg --armor --detach-sign "${EVIDENCE_DIR}/reports/final_report.pdf"
```

### 9.2 Documentación de metodología

Cada paso debe documentarse siguiendo **ACPO (Association of Chief Police Officers) Guidelines**:
1. **Principio 1**: No alterar datos originales
2. **Principio 2**: Acceso controlado y documentado
3. **Principio 3**: Auditoría completa de procesos
4. **Principio 4**: Responsabilidad del investigador

---

## 10. Referencias académicas y estándares

### Estándares internacionales
- **ISO/IEC 27037:2012**: Guidelines for identification, collection, acquisition and preservation of digital evidence
- **ISO/IEC 27041:2015**: Guidance on assuring suitability and adequacy of incident investigative method
- **ISO/IEC 27042:2015**: Guidelines for the analysis and interpretation of digital evidence
- **NIST SP 800-86**: Guide to Integrating Forensic Techniques into Incident Response
- **RFC 3227**: Guidelines for Evidence Collection and Archiving

### Frameworks forenses
- **DFRWS (Digital Forensic Research Workshop)**: Investigative process model
- **NIJ (National Institute of Justice)**: Forensic examination process
- **ACPO Good Practice Guide**: UK digital evidence guidelines

### Literatura académica recomendada
- Carrier, B. (2005). *File System Forensic Analysis*. Addison-Wesley
- Casey, E. (2011). *Digital Evidence and Computer Crime*. Academic Press
- Garfinkel, S. (2009). "Automating Disk Forensic Processing for Large-Scale Investigations"
- Poisel, R. & Tjoa, S. (2013). "Forensics Investigations of Multimedia Data: A Review"

### Herramientas y repositorios
- **The Sleuth Kit**: https://www.sleuthkit.org/
- **SANS SIFT Workstation**: https://digital-forensics.sans.org/community/downloads
- **CAINE (Computer Aided INvestigative Environment)**: https://www.caine-live.net/

---

## 11. Consideraciones legales

- **Admisibilidad**: Cumplir Daubert/Frye standards para testimonio pericial
- **Privacidad**: GDPR, LOPD, expectativas razonables de privacidad
- **Autorización**: Warrants, consentimiento informado, políticas corporativas
- **Experticia**: Certificaciones (EnCE, GCFE, GCFA, CHFI) y formación continua
