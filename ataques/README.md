# Tipos de ataques Cibernéticos

Objetivo: Referencia de los principales tipos de ataques, con una breve descripción para uso educativo y de triage.

# 🛡️ Tipos de Ciberamenazas y Explicación Ampliada

## 🎣 Phishing  
Engaños mediante **correos, SMS, llamadas o webs falsas** diseñadas para obtener credenciales, datos sensibles o inducir acciones peligrosas (como descargar malware o transferir dinero).  
Incluye variantes como spear phishing (dirigido), whaling (altos cargos) y smishing.

---

## 🦠 Malware  
Software malicioso diseñado para infiltrarse, dañar o tomar control de sistemas. Incluye:  
- **Troyanos**: se ocultan como software legítimo.  
- **Backdoors**: permiten acceso remoto no autorizado.  
- **Keyloggers**: registran pulsaciones del teclado.  
- **Botnets**: redes de equipos infectados controlados por un atacante.

---

## 🔐 Ransomware  
Malware que **cifra los datos** del sistema y exige un pago para permitir su recuperación.  
Puede propagarse por correo, vulnerabilidades, dispositivos USB o redes mal configuradas.

---

## 🌊 DDoS (Denegación de Servicio Distribuida)  
Ataques que **saturan los recursos** de un servidor, red o servicio mediante tráfico masivo proveniente de múltiples equipos comprometidos.  
Su objetivo es dejar servicios **inaccesibles**.

---

## 🕵️ Man-in-the-Middle (MitM)  
Un atacante **intercepta y manipula** la comunicación entre dos partes sin que lo sepan.  
Se aprovecha de redes Wi-Fi inseguras, suplantación de DNS/ARP o certificados falsos.

---

## 🗄️ SQL Injection (SQLi)  
Inyección de comandos maliciosos en aplicaciones web para **manipular bases de datos**, obtener información, modificarla o destruirla.  
Suele originarse por falta de validación de entradas.

---

## 💥 Cross-Site Scripting (XSS)  
Inserción de scripts maliciosos en páginas web que se ejecutan en el navegador de la víctima.  
Permite robar cookies, suplantar sesiones o modificar la interfaz del sitio.

---

## 🔑 Credential Stuffing / Fuerza Bruta  
- **Credential stuffing**: uso automático de credenciales filtradas para intentar acceder a cuentas.  
- **Brute force**: prueba sistemática y masiva de contraseñas.  
Ambas técnicas buscan **accesos no autorizados** a servicios.

---

## 🔗 Supply Chain Attacks  
Ataques dirigidos a **proveedores, servicios externos o software de terceros**, que luego se utilizan como vía para comprometer a una organización final.  
Afectan a actualizaciones, librerías, integraciones y hardware.

---

## 🧑‍💼 Insider Threat  
Amenazas provenientes **desde dentro de la organización**, ya sea por empleados, proveedores o socios.  
Pueden ser intencionadas (sabotaje, filtraciones) o accidentales (errores).

---

## 🕳️ Zero-day Exploits  
Ataques que se aprovechan de **vulnerabilidades desconocidas** por el fabricante y aún sin parche.  
Suelen tener un alto impacto debido a la falta de protección específica.

---

## 📦 Otros ataques relevantes (opcional para ampliar)

### 🧪 Ingeniería social  
Manipulación psicológica para obtener información, acceso o ejecutar acciones que comprometan la seguridad.

### 🛰️ Spoofing  
Suplantación de identidad (IP, email, DNS) para engañar a sistemas o usuarios.

### 🧷 Ataques a API  
Explotación de fallos en interfaces de programación mal protegidas para extraer información o tomar control de servicios.

### 🧩 Vulnerabilidades de configuración (Misconfiguration)  
Servidores, redes o aplicaciones con configuraciones débiles como puertos abiertos, permisos excesivos o credenciales por defecto.

--- 

# 🛡️ Pasos para controlar las vías de ataque

Las vías de ataque suelen aprovechar vulnerabilidades humanas, organizativas, técnicas o de configuración. Para mitigarlas, es necesario actuar en ambos frentes.

---

## 👥 1. Frente a vulnerabilidades humanas y organizativas

- **Formación y concienciación**  
  Capacitar al personal en buenas prácticas de seguridad.

- **Aplicación de políticas de uso**  
  Definir restricciones, usos permitidos y posibles sanciones por incumplimiento.

- **Establecimiento de acuerdos desde el inicio**  
  Incluir compromisos de seguridad al contratar servicios externos.

- **Asignación de responsables de seguridad**  
  Identificar responsables de cada servicio TIC y asegurar su formación y competencia.

---

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


Cómo usar esta carpeta: agregar ejemplos, IOCs, procedimientos de mitigación y plantillas de reporte.
