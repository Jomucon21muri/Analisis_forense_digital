# Análisis Forense de Sistemas Operativos

## 1. Artefactos Windows

### 1.1 Registry analysis

```powershell
# Recolección de Registry Hives
reg save HKLM\SAM C:\Forensics\SAM
reg save HKLM\SECURITY C:\Forensics\SECURITY
reg save HKLM\SYSTEM C:\Forensics\SYSTEM
reg save HKLM\SOFTWARE C:\Forensics\SOFTWARE
reg save HKCU\SOFTWARE C:\Forensics\NTUSER.DAT

# Análisis con RegRipper
rip.pl -r SYSTEM -p compname
rip.pl -r SOFTWARE -p uninstall
rip.pl -r NTUSER.DAT -p userassist
```

**Claves Críticas:**
```
# Persistencia
HKLM\Software\Microsoft\Windows\CurrentVersion\Run
HKCU\Software\Microsoft\Windows\CurrentVersion\Run
HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce
HKLM\System\CurrentControlSet\Services (Type=0x2 para auto-start)

# UserAssist (programas ejecutados)
HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist

# MRU (Most Recently Used)
HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs
HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU

# ShimCache (AppCompatCache)
HKLM\System\CurrentControlSet\Control\Session Manager\AppCompatCache

# BAM/DAM (Background Activity Moderator)
HKLM\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings
```

### 1.2 Prefetch files

```powershell
# Ubicación: C:\Windows\Prefetch\*.pf
# Contiene: últimas 8 ejecuciones, timestamps, archivos accedidos

# Análisis con PECmd (Eric Zimmerman)
PECmd.exe -d C:\Windows\Prefetch --csv C:\Forensics\prefetch_analysis.csv

# Buscar ejecutables sospechosos
Get-ChildItem C:\Windows\Prefetch -Filter *.pf | 
    ForEach-Object { PECmd.exe -f $_.FullName --json }
```

### 1.3 $MFT y USN Journal

```bash
# Extraer $MFT desde imagen forense
icat -o 2048 disk.dd 0 > \$MFT

# Parsear con MFTECmd
MFTECmd.exe -f \$MFT --csv mft_analysis.csv

# Buscar archivos eliminados recientemente
MFTECmd.exe -f \$MFT --csv deleted.csv --de

# USN Journal
icat -o 2048 disk.dd 0-144-2 > \$J
MFTECmd.exe -f \$J --csv usn.csv
```

### 1.4 Jump lists & LNK files

```powershell
# Jump Lists: C:\Users\*\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations
JLECmd.exe -d "C:\Users\$env:USERNAME\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations" --csv jumplist.csv

# LNK files (shortcuts)
LECmd.exe -d "C:\Users\$env:USERNAME\AppData\Roaming\Microsoft\Windows\Recent" --csv lnk_analysis.csv
```

### 1.5 NTFS Forensics

```bash
# $LogFile analysis
logFileParser.py --file \$LogFile --csv logfile.csv

# Volume Shadow Copies
vshadowmount disk.dd /mnt/vss/
ls /mnt/vss/vss*/Users/*/Desktop/

# ADS (Alternate Data Streams)
dir /r C:\Users
Get-Item -Path file.txt -Stream *
```

---

## 2. Artefactos Linux

### 2.1 Authentication & Users

```bash
# Logs de autenticación
cat /var/log/auth.log | grep "Accepted\|Failed"
last -f /var/log/wtmp  # Logons exitosos
lastb -f /var/log/btmp  # Logons fallidos
lastlog  # Último login por usuario

# Usuarios y grupos
cat /etc/passwd | grep -v nologin
cat /etc/shadow  # Hashes de passwords
cat /etc/sudoers
cat /etc/sudoers.d/*

# Usuarios con UID 0 (root privileges)
awk -F: '$3 == 0 {print $1}' /etc/passwd

# Usuarios creados recientemente
find /home -maxdepth 1 -type d -mtime -30
```

### 2.2 Persistencia mechanisms

```bash
# Cron jobs
crontab -l  # Usuario actual
cat /etc/crontab
ls -la /etc/cron.*
cat /var/spool/cron/crontabs/*

# Systemd services
systemctl list-unit-files --state=enabled
find /etc/systemd /lib/systemd -name '*.service' -mtime -30

# Init scripts
ls -la /etc/init.d/
ls -la /etc/rc*.d/

# Shell profiles
cat ~/.bashrc ~/.bash_profile ~/.profile
cat /etc/profile /etc/bash.bashrc

# SSH keys autorizadas
cat ~/.ssh/authorized_keys
find /home -name authorized_keys 2>/dev/null
```

### 2.3 Process & Network

```bash
# Procesos en ejecución
ps auxf  # Tree view
ps -eo pid,user,cmd,%cpu,%mem --sort=-%cpu

# Conexiones de red
netstat -tulnp
ss -tulnp
lsof -i  # Files/sockets abiertos

# Procesos con network activity
lsof -i -P -n | grep ESTABLISHED

# LD_PRELOAD hijacking
cat /etc/ld.so.preload
env | grep LD_
```

### 2.4 File integrity

```bash
# AIDE (Advanced Intrusion Detection Environment)
aide --init
aide --check

# Buscar binarios modificados
rpm -Va  # Red Hat/CentOS
debsums -c  # Debian/Ubuntu

# SUID binaries (potencial privilege escalation)
find / -perm -4000 -type f 2>/dev/null

# World-writable files
find / -perm -002 -type f 2>/dev/null
```

### 2.5 Logs del Sistema

```bash
# Syslog
cat /var/log/syslog | grep -iE "error|failed|invalid"

# Audit logs (auditd)
ausearch -m execve  # Comandos ejecutados
ausearch -ua <uid> -ts recent

# Kernel logs
dmesg -T
cat /var/log/kern.log

# Package manager logs
cat /var/log/dpkg.log  # Debian/Ubuntu
cat /var/log/yum.log   # Red Hat/CentOS
```

---

## 3. Artefactos macOS

### 3.1 System logs

```bash
# Unified Logging System
log show --predicate 'eventMessage contains "error"' --last 1h
log show --style syslog --last 1d > system.log

# Legacy logs
cat /var/log/system.log
```

### 3.2 LaunchAgents & LaunchDaemons

```bash
# Persistencia
ls -la ~/Library/LaunchAgents/
ls -la /Library/LaunchAgents/
ls -la /Library/LaunchDaemons/
ls -la /System/Library/LaunchDaemons/

# Analizar plist
plutil -p /Library/LaunchDaemons/suspicious.plist
```

### 3.3 File system events

```bash
# FSEvents (File system events)
fseventer -f /Volumes/MacHD/.fseventsd/ -o output.txt

# Spotlight metadata
mdfind "kMDItemFSCreationDate > $time.iso(2026-01-01)"
```

---

## 4. Triage con OSQuery

```bash
# Instalación
wget https://pkg.osquery.io/deb/osquery_5.10.2_amd64.deb
dpkg -i osquery_5.10.2_amd64.deb

# Queries útiles
osqueryi

# Usuarios
SELECT * FROM users WHERE uid = 0;

# Procesos escuchando en red
SELECT DISTINCT process.name, listening.port, listening.address 
FROM processes AS process 
JOIN listening_ports AS listening ON process.pid = listening.pid;

# Scheduled tasks (Windows)
SELECT * FROM scheduled_tasks WHERE enabled=1;

# Crontab (Linux)
SELECT * FROM crontab;

# Kernel modules
SELECT * FROM kernel_modules WHERE name NOT IN ('kvm', 'bridge');

# Autoruns
SELECT * FROM startup_items;
```

---

## 5. Herramientas especializadas

### 5.1 KAPE (Kroll Artifact Parser and Extractor)

```powershell
kape.exe --tsource C:\ --tdest C:\Forensics\KAPE \
         --target !SANS_Triage \
         --mdest C:\Forensics\KAPE_Modules \
         --module !EZParser
```

### 5.2 Velociraptor

```bash
# Deploy and collect artifacts
velociraptor --config server.config.yaml artifacts collect Windows.KapeFiles.Targets
```

### 5.3 Eric Zimmerman Tools

```powershell
# Timeline de sistema completo
MFTECmd.exe -f \$MFT --csv mft.csv
PECmd.exe -d C:\Windows\Prefetch --csv prefetch.csv
JLECmd.exe -d AutomaticDestinations --csv jumplist.csv
LECmd.exe -d Recent --csv lnk.csv
RECmd.exe -d C:\Forensics\Registry --bn batch.reb --csv registry.csv

# Timeline LECmd
TimelineExplorer.exe  # GUI para visualizar CSVs
```

---

## 6. Referencias

### Frameworks
- **SANS FOR508**: Advanced Incident Response
- **Sysmon**: https://docs.microsoft.com/sysinternals/sysmon
- **OSQuery**: https://osquery.io/

### Herramientas
- **Eric Zimmerman Tools**: https://ericzimmerman.github.io/
- **RegRipper**: https://github.com/keydet89/RegRipper3.0
- **KAPE**: https://www.kroll.com/kape
