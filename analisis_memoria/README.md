# Análisis Forense de Memoria Volátil (RAM Forensics)

## 1. Fundamentos teóricos de la memoria volátil

### 1.1 Arquitectura de Memoria y Orden de Volatilidad

Según el **RFC 3227** y el modelo de Carrier (2005), los datos forenses se organizan por orden de volatilidad:

**Orden de Volatilidad (más a menos volátil)**:
1. Registros CPU, cache L1/L2/L3
2. Contenido de RAM (proceso en ejecución, heap, stack)
3. Estado de red (conexiones TCP/UDP, sockets, routing tables)
4. Procesos en ejecución y servicios
5. Archivos temporales y swap/pagefile
6. Configuración y logs del sistema
7. Datos en disco (persistentes)

### 1.2 Espacios de Memoria

#### Kernel Space
- **Tablas de procesos**: EPROCESS (Windows), task_struct (Linux)
- **Drivers y módulos cargados**: LKMs, .sys
- **Page tables**: CR3, traducción virtual-física
- **SSDT (System Service Descriptor Table)**: Hooks de kernel
- **IDT (Interrupt Descriptor Table)**: Manejadores de interrupciones

#### User Space
- **Code segment**: Instrucciones ejecutables del proceso
- **Data segment**: Variables globales e inicializadas
- **Heap**: Memoria dinámica (malloc/new)
- **Stack**: Variables locales, frames de funciones, return addresses
- **Memory-mapped files**: DLLs, recursos, archivos mapeados

### 1.3 Conceptos clave: VAD, PTE y KPCR

- **VAD (Virtual Address Descriptor)**: Estructura que describe regiones de memoria virtual
- **PTE (Page Table Entry)**: Mapeo de páginas virtuales a físicas
- **KPCR (Kernel Processor Control Region)**: Estructura por CPU en Windows
- **KDBG (Kernel Debugger Data Block)**: Metadatos de debugging del kernel

---

## 2. Adquisición de memoria volátil

### 2.1 Consideraciones previas

```bash
# Documentar estado del sistema ANTES de captura
date -u > /tmp/acquisition_log.txt
uptime >> /tmp/acquisition_log.txt
ps aux --sort=-%mem | head -20 >> /tmp/acquisition_log.txt
netstat -antup >> /tmp/acquisition_log.txt
free -h >> /tmp/acquisition_log.txt

# Verificar espacio disponible (imagen = tamaño de RAM)
df -h

# Variables de entorno
CASE_ID="MEM-2026-001"
OUTPUT_DIR="/mnt/forensics/${CASE_ID}"
mkdir -p "${OUTPUT_DIR}"
```

### 2.2 Captura en sistemas Linux

#### Método 1: LiME (Linux Memory Extractor)

```bash
# Compilar módulo LiME para kernel actual
cd /opt/LiME/src
make

# Cargar módulo y capturar (formato LIME)
insmod lime-$(uname -r).ko "path=${OUTPUT_DIR}/memory.lime format=lime"

# O formato raw (compatible con Volatility)
insmod lime-$(uname -r).ko "path=${OUTPUT_DIR}/memory.raw format=raw"

# Calcular hash
sha256sum "${OUTPUT_DIR}/memory.raw" > "${OUTPUT_DIR}/memory.raw.sha256"

# Documentar información del sistema
uname -a > "${OUTPUT_DIR}/system_info.txt"
cat /proc/version >> "${OUTPUT_DIR}/system_info.txt"
lsmod > "${OUTPUT_DIR}/loaded_modules.txt"
```

#### Método 2: AVML (Azure VM Memory)

```bash
# Herramienta de Microsoft para captura rápida
wget https://github.com/microsoft/avml/releases/latest/download/avml
chmod +x avml

./avml "${OUTPUT_DIR}/memory.lime"
# Captura en formato LIME, compatible con Volatility 3
```

#### Método 3: Captura desde /dev/crash o /proc/kcore (no recomendado)

```bash
# /dev/crash requiere kernel con CONFIG_CRASH_DUMP
# /proc/kcore es interfaz a memoria física (puede ser inestable)
dd if=/dev/crash of="${OUTPUT_DIR}/memory_crash.raw" bs=4M

# ADVERTENCIA: Puede causar kernel panic o datos corruptos
```

### 2.3 Captura en sistemas Windows

#### Método 1: WinPmem (Recomendado)

```powershell
# Descargar: https://github.com/Velocidex/WinPmem
.\winpmem_v3.3.rc3.exe -o C:\Forensics\memory.raw

# Con metadata
.\winpmem_v3.3.rc3.exe -o C:\Forensics\memory.aff4

# Calcular hash
certutil -hashfile C:\Forensics\memory.raw SHA256 > C:\Forensics\memory.raw.sha256.txt
```

#### Método 2: FTK Imager

```powershell
# GUI: File → Capture Memory
# Command line:
FTKImager.exe --memorypath C:\Forensics --filename memory

# Genera memory.mem y memory.mem.txt (metadata)
```

#### Método 3: DumpIt (Comae)

```powershell
# Herramienta portable (requiere licencia para versiones recientes)
.\DumpIt.exe /O C:\Forensics\memory.dmp

# Snapshot completo incluyendo pagefile
.\DumpIt.exe /A /O C:\Forensics\memory_full.dmp
```

#### Método 4: Magnet RAM Capture

```powershell
# Free tool: https://www.magnetforensics.com/resources/magnet-ram-capture/
.\MagnetRAMCapture.exe
# GUI interactiva, genera .raw file
```

### 2.4 Captura en macOS

```bash
# Método 1: osxpmem (requiere deshabilitación de SIP)
# System Integrity Protection debe estar off: csrutil disable

sudo ./osxpmem -o memory.aff4

# Método 2: Volexity Surge Collect
# Herramienta comercial pero efectiva

# Método 3: Captura de hibernation file (alternativa)
# /var/vm/sleepimage contiene contenido de RAM
sudo cp /var/vm/sleepimage ~/Desktop/sleepimage.bin
```

### 2.5 Captura en entornos virtualizados

```bash
# VMware: Suspender VM genera .vmem file
# VirtualBox: Debugger
VBoxManage debugvm "VM_Name" dumpvmcore --filename memory.elf

# Hyper-V: Live dump
# Requiere PowerShell en host Hyper-V
Get-VM "VMName" | Checkpoint-VM -SnapshotName "ForensicCapture"
# Extraer .vmrs file del checkpoint

# Docker container memory
docker checkpoint create container_name checkpoint1
# Extraer de /var/lib/docker/containers/<id>/checkpoints/

# KVM/QEMU
virsh dump domain_name memory.dump --memory-only
```

---

## 3. Análisis con Volatility 3

### 3.1 Instalación y Configuración

```bash
# Instalar Volatility 3
pip3 install volatility3

# O desde repositorio
git clone https://github.com/volatilityfoundation/volatility3.git
cd volatility3
pip3 install -r requirements.txt

# Verificar instalación
python3 vol.py -h

# Descargar symbols (Windows)
git clone https://github.com/volatilityfoundation/volatility3-symbols.git
# Copiar a: volatility3/volatility3/symbols/
```

### 3.2 Identificación del perfil (Volatility 2) y banner info (Volatility 3)

```bash
# Volatility 3: Auto-detección de SO
python3 vol.py -f "${OUTPUT_DIR}/memory.raw" banners.Banners

# Listar plugins disponibles
python3 vol.py -f "${OUTPUT_DIR}/memory.raw" -h

# Para análisis posteriores
VOLPATH="python3 /opt/volatility3/vol.py"
MEMIMG="${OUTPUT_DIR}/memory.raw"
REPORT="${OUTPUT_DIR}/volatility_report"
mkdir -p "${REPORT}"
```

### 3.3 Análisis de Procesos

```bash
# Listar procesos (vista EPROCESS)
${VOLPATH} -f "${MEMIMG}" windows.pslist.PsList > "${REPORT}/pslist.txt"

# Árbol de procesos
${VOLPATH} -f "${MEMIMG}" windows.pstree.PsTree > "${REPORT}/pstree.txt"

# Procesos ocultos (técnicas de rootkit)
${VOLPATH} -f "${MEMIMG}" windows.psscan.PsScan > "${REPORT}/psscan.txt"

# Comparar pslist vs psscan para detectar ocultación
comm -13 <(grep -oP 'PID: \K\d+' "${REPORT}/pslist.txt" | sort) \
         <(grep -oP 'PID: \K\d+' "${REPORT}/psscan.txt" | sort) \
         > "${REPORT}/hidden_processes.txt"

# Análisis de servicios
${VOLPATH} -f "${MEMIMG}" windows.svcscan.SvcScan > "${REPORT}/services.txt"

# Línea de comandos de procesos
${VOLPATH} -f "${MEMIMG}" windows.cmdline.CmdLine > "${REPORT}/cmdline.txt"

# Variables de entorno
${VOLPATH} -f "${MEMIMG}" windows.envars.Envars > "${REPORT}/envars.txt"

# Handles de archivos abiertos
${VOLPATH} -f "${MEMIMG}" windows.handles.Handles --pid <PID> > "${REPORT}/handles_<PID>.txt"
```

### 3.4 Análisis de Red

```bash
# Conexiones de red activas
${VOLPATH} -f "${MEMIMG}" windows.netscan.NetScan > "${REPORT}/netscan.txt"

# Filtrar conexiones establecidas
grep "ESTABLISHED" "${REPORT}/netscan.txt" > "${REPORT}/netscan_established.txt"

# Sockets (Linux)
${VOLPATH} -f "${MEMIMG}" linux.sockstat.Sockstat > "${REPORT}/sockstat.txt"

# Extraer IPs externas sospechosas
awk '{print $5}' "${REPORT}/netscan_established.txt" | \
  grep -vE "^(192\.168\.|10\.|172\.(1[6-9]|2[0-9]|3[01])\.|127\.)" | \
  sort -u > "${REPORT}/external_ips.txt"
```

### 3.5 Análisis de DLLs y Módulos

```bash
# DLLs cargadas por proceso
${VOLPATH} -f "${MEMIMG}" windows.dlllist.DllList --pid <PID> > "${REPORT}/dlllist_<PID>.txt"

# Módulos del kernel (drivers)
${VOLPATH} -f "${MEMIMG}" windows.modules.Modules > "${REPORT}/kernel_modules.txt"

# Drivers cargados
${VOLPATH} -f "${MEMIMG}" windows.driverscan.DriverScan > "${REPORT}/driverscan.txt"

# Detección de DLL injection
${VOLPATH} -f "${MEMIMG}" windows.malfind.Malfind > "${REPORT}/malfind.txt"

# Linux kernel modules
${VOLPATH} -f "${MEMIMG}" linux.lsmod.Lsmod > "${REPORT}/lsmod.txt"
```

### 3.6 Extracción de Ejecutables y DLLs

```bash
# Extraer proceso completo
${VOLPATH} -f "${MEMIMG}" -o "${REPORT}/dumps" \
  windows.memmap.Memmap --pid <PID> --dump

# Dump de ejecutable (PE reconstruido)
${VOLPATH} -f "${MEMIMG}" -o "${REPORT}/dumps" \
  windows.dumpfiles.DumpFiles --pid <PID>

# Extraer todos los ejecutables
${VOLPATH} -f "${MEMIMG}" -o "${REPORT}/dumps" \
  windows.dumpfiles.DumpFiles --physaddr <ADDR>

# Reconstruir PE con pe-sieve
pe-sieve.exe /pid <PID> /shellc /data 3
```

### 3.7 Análisis de Registry (Windows)

```bash
# Listar hives de registro cargados
${VOLPATH} -f "${MEMIMG}" windows.registry.hivelist.HiveList > "${REPORT}/hivelist.txt"

# Extraer claves específicas
# PrintKey: Imprimir contenido de clave
${VOLPATH} -f "${MEMIMG}" windows.registry.printkey.PrintKey \
  --key "Software\Microsoft\Windows\CurrentVersion\Run" > "${REPORT}/reg_run.txt"

# UserAssist (programas ejecutados)
${VOLPATH} -f "${MEMIMG}" windows.registry.userassist.UserAssist > "${REPORT}/userassist.txt"

# ShimCache (AppCompatCache)
${VOLPATH} -f "${MEMIMG}" windows.shimcache.Shimcache > "${REPORT}/shimcache.txt"

# Historial de regedit
${VOLPATH} -f "${MEMIMG}" windows.registry.printkey.PrintKey \
  --key "Software\Microsoft\Windows\CurrentVersion\Applets\Regedit" > "${REPORT}/regedit_history.txt"
```

### 3.8 Extracción de Credenciales

```bash
# Mimikatz-style credential extraction
# hashdump: Local password hashes
${VOLPATH} -f "${MEMIMG}" windows.hashdump.Hashdump > "${REPORT}/hashdump.txt"

# LSA secrets
${VOLPATH} -f "${MEMIMG}" windows.lsadump.Lsadump > "${REPORT}/lsadump.txt"

# Cached domain credentials
${VOLPATH} -f "${MEMIMG}" windows.cachedump.Cachedump > "${REPORT}/cachedump.txt"

# Memoria de LSASS para credenciales en claro (requiere plugin adicional)
# pypykatz para análisis offline
pypykatz lsa minidump "${REPORT}/dumps/lsass.dmp" > "${REPORT}/pypykatz_creds.txt"
```

### 3.9 Detección de Malware y Anomalías

```bash
# Malfind: Detectar código inyectado y secciones sospechosas
${VOLPATH} -f "${MEMIMG}" windows.malfind.Malfind > "${REPORT}/malfind_full.txt"

# Extraer secciones sospechosas automáticamente
${VOLPATH} -f "${MEMIMG}" -o "${REPORT}/malfind_dumps" \
  windows.malfind.Malfind --dump

# SSDT hooks (rootkits)
${VOLPATH} -f "${MEMIMG}" windows.ssdt.SSDT > "${REPORT}/ssdt_hooks.txt"

# Callbacks del kernel (persistencia avanzada)
${VOLPATH} -f "${MEMIMG}" windows.callbacks.Callbacks > "${REPORT}/callbacks.txt"

# Timers del kernel (beacon implants)
${VOLPATH} -f "${MEMIMG}" windows.timers.Timers > "${REPORT}/timers.txt"

# Mutantes (mutex objects - indicador de infección)
${VOLPATH} -f "${MEMIMG}" windows.mutantscan.MutantScan > "${REPORT}/mutants.txt"
```

### 3.10 Análisis de Timeline

```bash
# Timeline completo de eventos
${VOLPATH} -f "${MEMIMG}" timeliner.Timeliner > "${REPORT}/timeline.csv"

# Importar a herramientas de visualización (Timesketch, Plaso)
# Formato body file para mactime
${VOLPATH} -f "${MEMIMG}" mftparser.MFTParser --output-file="${REPORT}/mft_timeline.body"
```

### 3.11 Análisis de Archivos y Filesystem

```bash
# Escanear file objects
${VOLPATH} -f "${MEMIMG}" windows.filescan.FileScan > "${REPORT}/filescan.txt"

# Buscar archivos específicos
grep -i "suspicious.exe" "${REPORT}/filescan.txt"

# Extraer archivo de memoria
${VOLPATH} -f "${MEMIMG}" -o "${REPORT}/extracted_files" \
  windows.dumpfiles.DumpFiles --virtaddr <VADDR>
```

---

## 4. Análisis avanzado: YARA scanning en memoria

### 4.1 Crear reglas YARA para memory scanning

```bash
# Reglas YARA específicas para memoria
cat > /tmp/memory_rules.yar <<'EOF'
rule InMemory_Cobalt_Strike
{
    meta:
        description = "Detects Cobalt Strike beacon in memory"
        author = "Forensics Lab"
    
    strings:
        $beacon1 = {4d 5a 90 00 03 00 00 00}
        $beacon2 = "ReflectiveLoader" ascii
        $beacon3 = "%c%c%c%c%c%c%c%c%cMSSE" ascii
        
    condition:
        any of them
}

rule Process_Hollowing_Indicators
{
    strings:
        $s1 = "NtUnmapViewOfSection" ascii
        $s2 = "ZwUnmapViewOfSection" ascii
        $api1 = "CreateProcessA" ascii
        $api2 = "WriteProcessMemory" ascii
        
    condition:
        2 of ($s*) and all of ($api*)
}

rule Mimikatz_In_Memory
{
    strings:
        $a = "sekurlsa::logonpasswords" ascii
        $b = "gentilkiwi" ascii
        $c = "KIWI_MSV1_0_PRIMARY_CREDENTIALS" ascii
        
    condition:
        any of them
}
EOF

# Escanear con Volatility + YARA
${VOLPATH} -f "${MEMIMG}" yarascan.YaraScan \
  --yara-rules /tmp/memory_rules.yar > "${REPORT}/yara_hits.txt"

# Escanear proceso específico
${VOLPATH} -f "${MEMIMG}" yarascan.YaraScan \
  --yara-rules /tmp/memory_rules.yar \
  --pid <PID> > "${REPORT}/yara_hits_pid_<PID>.txt"
```

---

## 5. Análisis de Memoria en Linux

### 5.1 Plugins específicos de Linux (Volatility 3)

```bash
# Procesos
${VOLPATH} -f "${MEMIMG}" linux.pslist.PsList > "${REPORT}/linux_pslist.txt"
${VOLPATH} -f "${MEMIMG}" linux.pstree.PsTree > "${REPORT}/linux_pstree.txt"

# Bash history de procesos activos
${VOLPATH} -f "${MEMIMG}" linux.bash.Bash > "${REPORT}/bash_history.txt"

# Módulos del kernel
${VOLPATH} -f "${MEMIMG}" linux.lsmod.Lsmod > "${REPORT}/lsmod.txt"

# Detección de rootkits
${VOLPATH} -f "${MEMIMG}" linux.check_afinfo.Check_afinfo > "${REPORT}/check_afinfo.txt"
${VOLPATH} -f "${MEMIMG}" linux.check_creds.Check_creds > "${REPORT}/check_creds.txt"

# Syscall table hooks
${VOLPATH} -f "${MEMIMG}" linux.check_syscall.Check_syscall > "${REPORT}/syscall_hooks.txt"

# Interfaces de red
${VOLPATH} -f "${MEMIMG}" linux.ifconfig.Ifconfig > "${REPORT}/ifconfig.txt"

# Archivos abiertos
${VOLPATH} -f "${MEMIMG}" linux.lsof.Lsof > "${REPORT}/lsof.txt"

# Mapeos de memoria
${VOLPATH} -f "${MEMIMG}" linux.proc_maps.Maps --pid <PID> > "${REPORT}/maps_<PID>.txt"

# Claves SSH en memoria
${VOLPATH} -f "${MEMIMG}" linux.keyboard_notifiers.Keyboard_notifiers > "${REPORT}/keyboard.txt"
```

### 5.2 Extracción de Credenciales en Linux

```bash
# Buscar claves privadas SSH
${VOLPATH} -f "${MEMIMG}" linux.bash.Bash | grep -i "id_rsa\|id_ecdsa\|id_ed25519"

# Passwords en variables de entorno
${VOLPATH} -f "${MEMIMG}" linux.envars.Envars | grep -iE "password|passwd|pwd|secret|token"

# Buscar en memoria de procesos (manual)
strings -e l "${MEMIMG}" | grep -iE "BEGIN RSA PRIVATE KEY|BEGIN OPENSSH PRIVATE KEY"
```

---

## 6. Análisis de Memoria en macOS

### 6.1 Volatility con macOS

```bash
# Descargar símbolos de macOS
# https://github.com/volatilityfoundation/volatility3-symbols

# Procesos
${VOLPATH} -f "${MEMIMG}" mac.pslist.PsList > "${REPORT}/mac_pslist.txt"

# Red
${VOLPATH} -f "${MEMIMG}" mac.netstat.Netstat > "${REPORT}/mac_netstat.txt"

# Bash history
${VOLPATH} -f "${MEMIMG}" mac.bash.Bash > "${REPORT}/mac_bash.txt"

# Dyld (dynamic libraries)
${VOLPATH} -f "${MEMIMG}" mac.dmesg.Dmesg > "${REPORT}/mac_dmesg.txt"
```

---

## 7. Análisis con Rekall (Alternativa a Volatility)

```bash
# Instalación (deprecado pero aún útil)
pip2 install rekall

# Análisis interactivo
rekall -f "${MEMIMG}" --profile Win10x64_17134

# Comandos útiles en Rekall
# > pslist
# > netscan
# > malfind
# > dlldump --pid <PID>

# Modo no interactivo
rekall -f "${MEMIMG}" --profile Win10x64_17134 pslist > "${REPORT}/rekall_pslist.txt"
```

---

## 8. Análisis manual: técnicas sin herramientas

### 8.1 Strings analysis avanzado

```bash
# Extraer strings de largo mínimo 10 caracteres
strings -a -n 10 "${MEMIMG}" > "${REPORT}/strings_all.txt"

# Buscar patrones específicos
grep -aE "http[s]?://[^\s]+" "${REPORT}/strings_all.txt" > "${REPORT}/urls_in_memory.txt"
grep -aE "([0-9]{1,3}\.){3}[0-9]{1,3}" "${REPORT}/strings_all.txt" > "${REPORT}/ips_in_memory.txt"
grep -aiE "(password|passwd|pwd|login|username)[:=\s]+" "${REPORT}/strings_all.txt" > "${REPORT}/potential_creds.txt"

# Comandos ejecutados
grep -aE "(cmd\.exe|powershell\.exe|bash|/bin/sh)" "${REPORT}/strings_all.txt" > "${REPORT}/commands.txt"

# Registry keys
grep -aE "HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKLM|HKCU" "${REPORT}/strings_all.txt" | head -100
```

### 8.2 Bulk Extractor en memoria

```bash
# Extraer emails, URLs, JSON, credit cards, etc.
bulk_extractor -o "${REPORT}/bulk_output" \
  -E email -E net -E json -E ccn -E url \
  "${MEMIMG}"

# Revisar resultados
cat "${REPORT}/bulk_output/email.txt"
cat "${REPORT}/bulk_output/url.txt"
cat "${REPORT}/bulk_output/ccn.txt"  # Credit card numbers
```

---

## 9. Casos de uso específicos

### 9.1 Detección de proceso hollowing / process injection

```bash
# Malfind detecta memoria executable/writable inusual
${VOLPATH} -f "${MEMIMG}" windows.malfind.Malfind > "${REPORT}/malfind.txt"

# Buscar procesos con paths sospechosos
grep -E "Wow64|Temp|AppData|Users.*Desktop" "${REPORT}/pslist.txt"

# Comparar base address de ejecutable con DLLs
# Si hay discrepancias, posible hollowing
${VOLPATH} -f "${MEMIMG}" windows.vadinfo.VadInfo --pid <PID>
```

### 9.2 Detección de Backdoors y RATs

```bash
# Buscar conexiones a puertos no estándar
awk '$6 ~ /ESTABLISHED/ && ($3 !~ /80|443|22|3389/)' "${REPORT}/netscan.txt"

# Buscar procesos con nombres comunes de RATs
grep -iE "(njrat|darkcomet|poison ivy|gh0st|bladabindi)" "${REPORT}/cmdline.txt"

# Mutantes conocidos de malware
grep -iE "(HGL345|MUTEX_.*|RDP.*Clip)" "${REPORT}/mutants.txt"
```

### 9.3 Análisis de Ransomware en Memoria

```bash
# Buscar extensiones de archivos cifrados
strings "${MEMIMG}" | grep -oE "\.[a-z0-9]{4,10}$" | sort | uniq -c | sort -rn | head

# Buscar nota de rescate en memoria
strings "${MEMIMG}" | grep -i "ransom\|decrypt\|bitcoin\|payment"

# Buscar APIs de cifrado
grep -iE "(CryptEncrypt|CryptDecrypt|BCryptEncrypt|AES)" "${REPORT}/dlllist_<PID>.txt"

# Extracción de claves de cifrado (si están en memoria)
# Usar herramientas específicas: ransomware_decryptors
```

### 9.4 Análisis de web browsers en memoria

```bash
# Extraer historial de navegación
strings "${MEMIMG}" | grep -E "http[s]?://[^\s]+" | sort -u > "${REPORT}/browser_history.txt"

# Cookies y sesiones
strings "${MEMIMG}" | grep -i "cookie:\|set-cookie:" | head -50

# Credenciales en formularios
strings "${MEMIMG}" | grep -iE "username=|password=|email=" | head -100
```

---

## 10. Automatización y Scripting

### 10.1 Script completo de análisis

```bash
#!/bin/bash
# comprehensive_memory_analysis.sh

MEMIMG=$1
REPORT_DIR="./analysis_$(date +%Y%m%d_%H%M%S)"
mkdir -p "${REPORT_DIR}"

VOL="python3 /opt/volatility3/vol.py -f ${MEMIMG}"

echo "[*] Starting comprehensive memory analysis..."

# Identificación
${VOL} banners.Banners > "${REPORT_DIR}/00_banners.txt"

# Procesos
${VOL} windows.pslist.PsList > "${REPORT_DIR}/01_pslist.txt"
${VOL} windows.pstree.PsTree > "${REPORT_DIR}/02_pstree.txt"
${VOL} windows.psscan.PsScan > "${REPORT_DIR}/03_psscan.txt"

# Red
${VOL} windows.netscan.NetScan > "${REPORT_DIR}/04_netscan.txt"

# DLLs y drivers
${VOL} windows.modules.Modules > "${REPORT_DIR}/05_modules.txt"
${VOL} windows.driverscan.DriverScan > "${REPORT_DIR}/06_drivers.txt"

# Malware detection
${VOL} windows.malfind.Malfind > "${REPORT_DIR}/07_malfind.txt"
${VOL} windows.ssdt.SSDT > "${REPORT_DIR}/08_ssdt.txt"

# Registry
${VOL} windows.registry.hivelist.HiveList > "${REPORT_DIR}/09_hivelist.txt"

# Credenciales
${VOL} windows.hashdump.Hashdump > "${REPORT_DIR}/10_hashdump.txt" 2>/dev/null

echo "[+] Analysis complete. Results in ${REPORT_DIR}/"
```

### 10.2 Análisis diferencial (baseline vs infected)

```python
#!/usr/bin/env python3
# Compare two memory dumps

import sys

def parse_pslist(filename):
    processes = {}
    with open(filename, 'r') as f:
        for line in f:
            if 'PID' in line:
                parts = line.split()
                if len(parts) > 2:
                    pid = parts[0]
                    name = parts[1]
                    processes[pid] = name
    return processes

baseline = parse_pslist(sys.argv[1])
infected = parse_pslist(sys.argv[2])

print("[+] New processes in infected system:")
for pid, name in infected.items():
    if pid not in baseline:
        print(f"  PID {pid}: {name}")

print("\n[+] Terminated processes:")
for pid, name in baseline.items():
    if pid not in infected:
        print(f"  PID {pid}: {name}")
```

---

## 11. Documentación y Generación de Informes

### 11.1 Formato de Reporte

```markdown
# Análisis Forense de Memoria - ${CASE_ID}

## 1. Información del Sistema
- **Fecha de captura**: $(date)
- **Tamaño de imagen**: $(stat -f%z "${MEMIMG}")
- **Hash SHA256**: $(sha256sum "${MEMIMG}")
- **Sistema operativo**: $(grep "Windows\|Linux" "${REPORT}/00_banners.txt")

## 2. Procesos sospechosos
$(grep -i "suspicious" "${REPORT}/pslist.txt")

## 3. Conexiones de Red
$(grep "ESTABLISHED" "${REPORT}/netscan.txt")

## 4. Indicadores de Compromiso (IOCs)
### IPs externas
$(cat "${REPORT}/external_ips.txt")

### Dominios contactados
$(cat "${REPORT}/dns_queries.txt")

## 5. Artefactos de Malware
$(cat "${REPORT}/malfind.txt" | grep -A5 "Process:")

## 6. Recomendaciones
- Aislar sistemas comprometidos
- Cambiar credenciales expuestas
- Aplicar reglas de firewall
```

---

## 12. Referencias académicas y recursos avanzados

### Libros fundamentales
- Ligh, M. et al. (2014). *The Art of Memory Forensics: Detecting Malware and Threats in Windows, Linux, and Mac Memory*. Wiley
- Case, A. & Richard, G. (2017). *Memory Forensics: The Path Forward*. Digital Investigation
- Raiu, C. & Golovkin, V. (2012). *Malware Forensics: Investigating and Analyzing Malicious Code*

### Papers académicos clave
- Schatz, B. (2007). "BodySnatcher: Towards Reliable Volatile Memory Acquisition by Software"
- Carrier, B. & Grand, J. (2004). "A Hardware-Based Memory Acquisition Procedure for Digital Investigations"
- Cohen, M. (2015). "Robust Linux Memory Acquisition with Minimal Target Impact"
- Dolan-Gavitt, B. et al. (2011). "Virtuoso: Narrowing the Semantic Gap in Virtual Machine Introspection"

### Frameworks y Estándares
- **Volatility Foundation**: https://volatilityfoundation.org/
- **Rekall Memory Forensics**: http://www.rekall-forensic.com/
- **DFRWS Memory Challenge**: https://www.dfrws.org/

### Herramientas avanzadas
- **Volatility 3**: https://github.com/volatilityfoundation/volatility3
- **Redline (FireEye)**: Free triage tool
- **Memoryze**: Free memory forensics by Mandiant
- **AVML**: https://github.com/microsoft/avml
- **LiME**: https://github.com/504ensicsLabs/LiME

### Datasets públicos para práctica
- **DFRWS Forensic Challenges**: Memory images con escenarios
- **Volatility Test Images**: https://github.com/volatilityfoundation/volatility/wiki/Memory-Samples
- **SANS DFIR Challenges**: https://www.sans.org/

### Certificaciones especializadas
- **GCFA (GIAC Certified Forensic Analyst)**: Incluye memoria forensics
- **GREM (GIAC Reverse Engineering Malware)**: Análisis en memoria
- **SANS FOR508**: Advanced Incident Response, Threat Hunting, and Digital Forensics

---

## 13. Consideraciones legales y Éticas

### Aspectos legales
- **Consentimiento**: Autorización para capturar memoria (políticas corporativas)
- **Privacidad**: Contenido sensible (contraseñas, PII, datos médicos/financieros)
- **Cadena de custodia**: Documentación exhaustiva de adquisición
- **Admisibilidad**: Métodos forenses aceptados por tribunales

### Mejores prácticas
1. **Captura inmediata**: Minimizar cambios en memoria volátil
2. **Documentación completa**: Timestamp, herramientas, hash
3. **Almacenamiento seguro**: Cifrado de imágenes de memoria
4. **Análisis en entorno controlado**: Evitar contaminación
5. **Reporte transparente**: Metodología reproducible
