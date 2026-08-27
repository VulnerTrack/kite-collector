# kite-collector

Agente de descubrimiento de activos de ciberseguridad, auditoria de configuracion y analisis de postura.

Un solo binario que escanea tu red, inventaria el software instalado, audita la configuracion del sistema en busca de debilidades de seguridad (CWE), y recomienda mitigaciones basadas en patrones de ataque (CAPEC). Los resultados se almacenan en una base de datos SQLite local -- sin servidores, sin dependencias, completamente offline.

## Instalacion

### Ubuntu / Debian (Repositorio APT)

Puedes instalar `kite-collector` en distribuciones basadas en Debian (como Ubuntu, Linux Mint o Pop!_OS) utilizando nuestro repositorio oficial de APT:

1. Descargar e instalar la clave pública del repositorio:
   ```bash
   curl -fsSL https://vulnertrack.github.io/kite-collector/repository.key | sudo tee /usr/share/keyrings/kite-collector-keyring.asc > /dev/null
   ```

2. Agregar el repositorio a tus fuentes de sistema:
   ```bash
   echo "deb [signed-by=/usr/share/keyrings/kite-collector-keyring.asc] https://vulnertrack.github.io/kite-collector/ stable main" | sudo tee /etc/apt/sources.list.d/kite-collector.list
   ```

3. Actualizar la lista de paquetes e instalar el agente:
   ```bash
   sudo apt update
   sudo apt install kite-collector
   kite-collector install
   ```

¿Necesitas también [osquery](https://osquery.io) en el host? Instala
`kite-collector-osquery` — el mismo agente más un osqueryd incluido que corre
como el servicio systemd `kite-osqueryd` (socket de extensiones en
`/run/kite-osquery/kite-osquery.em`, que la fuente de descubrimiento osquery
del collector detecta automáticamente). Está aislado bajo
`/opt/kite-collector` para no chocar con una instalación independiente de
osquery, e instalar cualquiera de `kite-collector`/`kite-collector-osquery`
reemplaza limpiamente al otro.

### Snap (Linux Universal)

Para cualquier distribución de Linux compatible con Snap (incluyendo Ubuntu, Debian, Fedora, Arch Linux, etc.), puedes instalar el agente directamente desde la Snap Store:

```bash
sudo snap install kite-collector
sudo kite-collector install
sudo kite-collector enroll
sudo snap start --enable kite-collector.kite-collector-daemon
```

En la edición Snap, `install` prepara el almacenamiento persistente en
`/var/snap/kite-collector/common/certs`; el directorio padre `common` permanece
bajo control de snapd, mientras el collector puede proteger el subdirectorio
`certs`. snapd ya administra el binario, el servicio y las actualizaciones.
Consulta el estado con `snap services kite-collector` y los logs con
`sudo snap logs -f kite-collector.kite-collector-daemon`.

### Otras distribuciones Linux (Fedora, Red Hat, Arch Linux, etc.)

Para aquellas distribuciones que NO utilizan el gestor de paquetes `apt` (como Fedora, Red Hat Enterprise Linux, CentOS o Arch Linux, las cuales usan `dnf`, `yum` o `pacman`):

- **Fedora / Red Hat / CentOS**: Puedes descargar el paquete `.rpm` directamente desde la pestaña de [GitHub Releases](https://github.com/VulnerTrack/kite-collector/releases) e instalarlo usando tu gestor de paquetes (por ejemplo, `sudo dnf install ./kite-collector-*.rpm`).
- **Arch Linux / Otras distribuciones**: Descarga el binario precompilado dentro del archivo `.tar.gz` desde la página de Releases, extráelo y colócalo en tu `PATH`. Alternativamente, puedes compilarlo desde el código fuente.

### macOS (Homebrew)

Instala `kite-collector` en macOS desde nuestro tap de Homebrew. El cask elimina automáticamente el atributo de cuarentena de Gatekeeper, por lo que el binario se ejecuta sin el aviso de "desarrollador no identificado":

```bash
brew install --cask vulnertrack/tap/kite-collector
kite-collector install
```

¿Necesitas también [osquery](https://osquery.io) en el endpoint? macOS no
recibe un osqueryd incluido — un binario empaquetado por kite correría bajo la
firma de kite y necesitaría el permiso de Acceso Total al Disco de kite en
lugar del de osquery — así que kite adopta el daemon que ya tienes:

```bash
brew install --cask osquery
sudo kite-collector install --with-osquery
```

Eso registra el daemon launchd hermano `kite-osqueryd` apuntando a
`/opt/osquery/lib/osquery.app`, con nombres propios para no chocar con el
trabajo `io.osquery.agent` de osquery. Si prefieres ejecutar el daemon propio
de osquery (`sudo osqueryctl start`), el descubrimiento lo detecta solo y no
hace falta configurar nada. Una advertencia de macOS antes de confiar en un
resultado limpio: sin Acceso Total al Disco, osqueryd lee las rutas protegidas
por TCC *vacías en lugar de fallar*. Detalles en
[docs/macos-osquery.md](docs/macos-osquery.md).

### Despliegue masivo desde el dashboard

El dashboard local de kite-collector incluye la opción **Mass deployment**.
Desde allí se genera un único paquete Ansible temporal para computadoras
Windows, Linux y macOS:

1. Abre el dashboard y selecciona **Mass deployment**.
2. Presiona **Discover computers**. Con un solo clic Kite combina escaneo TCP,
   banners SSH, Bonjour/mDNS, NetBIOS, SSDP y WS-Discovery. Muestra la IP local
   detectada y sólo consulta su red `/24` después de la confirmación explícita.
3. Selecciona las computadoras compatibles que Kite ya descubrió en
   **Machines**. Kite obtiene automáticamente su sistema operativo y
   arquitectura. También puedes agregar hosts o IP adicionales con el formato
   `hostname,os,arch`.
4. Presiona **Generate deployment package**. Kite solicita automáticamente al
   PKI un token distinto, de un solo uso y dos horas, para cada computadora y
   descarga el ZIP. El operador no copia ni escribe credenciales de enrolamiento.
5. Lleva el ZIP a una computadora de control Linux que tenga acceso de red a
   los equipos, descomprímelo y ejecuta `./deploy.sh`.

#### Preparar computadoras Windows sin copiar archivos

El mismo comando puede ejecutarse en cualquier cantidad de computadoras
Windows 7/8/10/11 y Windows Server 2008 R2 o posterior. En cada una, abre
**Símbolo del sistema (CMD) como administrador** y pega:

```cmd
sc.exe config WinRM start= auto & sc.exe start WinRM & winrm quickconfig -quiet & netsh advfirewall firewall add rule name="Kite WinRM HTTP 5985" dir=in action=allow protocol=TCP localport=5985 profile=any remoteip=localsubnet & netstat -ano | findstr ":5985"
```

Este comando sólo habilita el canal administrativo WinRM; no instala ni enrola
Kite y no contiene tokens, credenciales ni valores específicos del equipo. La
regla permite conexiones únicamente desde la subred local. Al finalizar debe
aparecer una línea que contenga `:5985`. Después de ejecutarlo en las
computadoras seleccionadas, el operador genera un solo ZIP y ejecuta
`./deploy.sh` una vez desde Linux. El despliegue instala y enrola todas las
computadoras usando el token único incluido para cada una. Para cada Windows,
`deploy.sh` propone automáticamente `NOMBRE-PC\Administrador`; pulsa Enter para
aceptarlo o escribe otra cuenta administrativa. Esto también funciona de forma
dinámica cuando el paquete contiene decenas o cientos de equipos.

El script solicita las credenciales de AD/WinRM y SSH al ejecutarse; las
contraseñas de infraestructura no se guardan en el paquete. Windows requiere
WinRM y Linux/macOS requieren SSH y elevación de privilegios. El token de
credenciales de enrolamiento están dentro del ZIP y son confidenciales: elimina
el ZIP cuando termine el despliegue o expiren.
La versión del collector, el endpoint PKI y los códigos únicos de cada equipo
se completan automáticamente desde el controlador; el operador no debe
ingresarlos.

La detección del sistema operativo usa evidencia de alta confianza, como WinRM
o un banner SSH que identifica la distribución. Si la red o el firewall no
ofrecen una señal concluyente, Kite deja el sistema sin seleccionar para evitar
instalar por error en un router, una impresora u otro dispositivo.
Cuando un equipo anuncia OpenSSH pero no permite distinguir Linux de macOS, el
paquete ejecuta esa comprobación automáticamente al conectarse, detecta también
`amd64`/`arm64` y guarda el resultado en `detected-platforms.csv`. El operador
no necesita escribir esos comandos.

### Windows

Para Windows, puedes instalar `kite-collector` usando cualquiera de estos métodos rápidos y sencillos:

#### 1. Instalador MSI (Recomendado)
Descarga el último instalador `kite-collector_<version>_amd64.msi` desde la página de [GitHub Releases](https://github.com/VulnerTrack/kite-collector/releases). Haz doble clic en él para iniciar el asistente de instalación, o realiza un despliegue silencioso para empresas (GPO/Intune) como administrador:
```powershell
msiexec /i kite-collector_amd64.msi /quiet
```

¿Necesitas también [osquery](https://osquery.io) en el endpoint? Usa
`kite-collector-osquery_<version>_amd64.msi` — la misma instalación más un
osqueryd incluido, registrado como el servicio `kite-osqueryd` con nombres
propios para no chocar con una instalación independiente de osquery. Detalles
en [docs/window_install.md](docs/window_install.md#bundled-osquery-msi-kite-collector-osquery)
(en inglés).

Para desplegar una versión fija por lotes en cientos de computadoras Windows
unidas al dominio, utiliza el [despliegue de flota con Ansible](deploy/ansible/README.md).

#### 2. Asistente Gráfico Integrado
Descarga el binario para Windows `kite-collector_windows_amd64.exe` y haz doble clic sobre él en el Explorador de Archivos. El binario detectará el doble clic y abrirá automáticamente el asistente gráfico de instalación para registrar el servicio.

#### 3. PowerShell de una línea
Abre una consola de PowerShell y ejecuta el script de instalación automatizado:
```powershell
irm https://get.kite-collector.dev/install.ps1 | iex
```

#### 4. Windows Package Manager (WinGet)
Instálalo usando el gestor de paquetes nativo de Windows 10 y 11:
```powershell
winget install VulnerTrack.KiteCollector
```

#### 5. Scoop
Si utilizas Scoop, añade nuestro repositorio e instálalo con:
```powershell
scoop bucket add vulnertrack https://github.com/VulnerTrack/homebrew-tap
scoop install kite-collector
```

### Descarga Manual / Otros Sistemas

Si prefieres descargar directamente los binarios precompilados o estás en macOS/Windows:

```bash
# Linux
curl -sSL https://github.com/VulnerTrack/kite-collector/releases/latest/download/kite-collector_linux_amd64 -o kite-collector
chmod +x kite-collector

# macOS
curl -sSL https://github.com/VulnerTrack/kite-collector/releases/latest/download/kite-collector_darwin_arm64.tar.gz | tar xz

# Windows (PowerShell)
irm https://get.kite-collector.dev/install.ps1 | iex

# Windows rapido, solo binario
& ([scriptblock]::Create((irm https://get.kite-collector.dev/install.ps1))) -NoService
```

### Compilar desde el código fuente

```bash
make build
```

## Uso

```bash
# Escanear el host local (funciona inmediatamente, sin configuracion)
./kite-collector scan

# Escanear una subred
./kite-collector scan --scope 192.168.1.0/24

# Incluir contenedores Docker
./kite-collector scan --source docker

# Salida en JSON
./kite-collector scan --output json

# Comparar dos escaneos para detectar cambios
./kite-collector diff scan1.db scan2.db

# Monitoreo continuo
./kite-collector agent --stream --interval 6h

# Asistente de configuracion interactivo
./kite-collector init

# Consultar la base de datos
./kite-collector query assets
./kite-collector query software --limit 20
./kite-collector query findings --severity high

# Abrir el dashboard en el navegador
./kite-collector dashboard
```

## Que descubre

| Fuente | Activos | Autenticacion |
|--------|---------|---------------|
| Agente local | Hostname, OS, interfaces, paquetes instalados | No |
| Escaneo de red | Hosts alcanzables via TCP connect | No |
| Docker / Podman | Contenedores, imagenes, redes | Acceso al socket |
| UniFi | Clientes (VLAN, puerto switch, senal), dispositivos de red | Credenciales del controlador |
| AWS EC2 | Instancias EC2 en todas las regiones | Credenciales IAM |
| GCP Compute | VMs de Compute Engine | ADC |
| Azure | Maquinas virtuales en todas las suscripciones | Service principal |
| Proxmox | VMs y contenedores LXC | Token API |
| SNMP | Switches, routers, UPS | Community string |

## Que audita

La auditoria de configuracion verifica tu sistema y mapea los hallazgos a identificadores de debilidad [CWE](https://cwe.mitre.org/):

| Verificacion | Ejemplo | CWE |
|-------------|---------|-----|
| Login root por SSH permitido | `PermitRootLogin yes` | CWE-250 |
| Autenticacion por contrasena habilitada | `PasswordAuthentication yes` | CWE-287 |
| Sin firewall activo | iptables/nftables/ufw todos inactivos | CWE-284 |
| ASLR deshabilitado | `randomize_va_space=0` | CWE-330 |
| Archivo shadow legible por todos | `/etc/shadow` modo 644 | CWE-732 |
| Servicio Telnet ejecutandose | Puerto 23 escuchando | CWE-319 |
| Base de datos expuesta | Puerto 5432 en 0.0.0.0 | CWE-284 |

Los hallazgos se cruzan con patrones de ataque [CAPEC](https://capec.mitre.org/) para generar mitigaciones accionables.

## Inventario de software

Detecta automaticamente y consulta los gestores de paquetes instalados:

| Gestor de paquetes | Plataformas |
|-------------------|-------------|
| dpkg | Debian, Ubuntu, Kali |
| pacman | Arch, Manjaro, EndeavourOS |
| rpm | RHEL, Fedora, CentOS, SUSE |

Cada paquete recibe un identificador [CPE 2.3](https://nvd.nist.gov/products/cpe) para correlacion de vulnerabilidades con bases de datos CVE.

## Configuracion

Funciona inmediatamente con valores predeterminados sensatos y sin archivo de configuracion. Para personalizar, crea un archivo YAML:

```yaml
discovery:
  sources:
    agent:
      enabled: true
      collect_software: true
    network:
      enabled: true
      scope: [192.168.1.0/24]
      tcp_ports: [22, 80, 443, 3389, 8080, 8443]
    docker:
      enabled: true
      host: unix:///var/run/docker.sock

classification:
  authorization:
    allowlist_file: ./configs/authorized-machines.yaml
    match_fields: [hostname]

audit:
  enabled: true

stale_threshold: 168h   # 7 dias
```

Las variables de entorno sobrescriben la configuracion con el prefijo `KITE_` (ej. `KITE_LOG_LEVEL=debug`).

Consulta `configs/kite-collector.example.yaml` para todas las opciones.

## Formatos de salida

| Formato | Caso de uso |
|---------|------------|
| `--output table` | Visualizacion en terminal (predeterminado) |
| `--output json` | Ingestion SIEM, pipelines CI/CD, consumo API |
| `--output csv` | Hojas de calculo, reportes |

## Comandos

| Comando | Descripcion |
|---------|-------------|
| `scan` | Descubrimiento + auditoria + analisis de postura (una vez) |
| `agent --stream` | Modo continuo con intervalo configurable |
| `diff <db1> <db2>` | Comparar dos bases de datos de escaneo |
| `report` | Generar reporte de activos |
| `init` | Asistente de configuracion interactivo |
| `query <target>` | Consultar la base de datos SQLite |
| `db` | Abrir shell SQLite con formato tabla |
| `dashboard` | Abrir dashboard en el navegador |
| `error <code>` | Buscar un codigo de error |
| `version` | Imprimir version, commit, fecha de compilacion |

## Clasificacion de activos

Cada activo descubierto se clasifica en dos ejes:

**Autorizacion** (este activo deberia estar aqui?):
- `unknown` -- predeterminado, aun no evaluado
- `authorized` -- coincide con una entrada en la lista blanca
- `unauthorized` -- explicitamente no esta en la lista blanca

**Estado de gestion** (este activo cumple nuestros controles de seguridad?):
- `unknown` -- predeterminado, controles no configurados
- `managed` -- todos los controles requeridos presentes
- `unmanaged` -- falta uno o mas controles requeridos

Los activos nunca se clasifican como `authorized` por defecto. Solo las coincidencias positivas contra tu fuente de verdad producen `authorized`.

## Base de datos

Todos los resultados se almacenan en un archivo SQLite portatil en `./kite.db`:

```bash
# Consultar activos
kite-collector query assets

# Consultar software instalado
kite-collector query software --limit 20

# Consultar hallazgos de configuracion
kite-collector query findings

# Historial de escaneos
kite-collector query scans

# O usar el shell SQLite directamente
kite-collector db
```

## Integracion con la plataforma

kite-collector puede alimentar al [Vulnertrack Intelligence Engine](https://github.com/VulnerTrack/vulnertrack-intelligence-engine) para cruzar activos contra bases de datos CVE/CWE/CAPEC:

```bash
# Importar resultados de escaneo a ClickHouse
vie kite scan --scope 192.168.1.0/24 --import

# Consultar activos importados
vie kite assets --authorized unauthorized
```

En modo streaming, los eventos OTLP se envian a un OpenTelemetry Collector para monitoreo en tiempo real.

## Seguridad

- **Solo lectura** -- nunca escribe, modifica, ni ejecuta codigo en los sistemas descubiertos
- **Sin credenciales en almacenamiento** -- SQLite contiene solo datos de activos, nunca tokens ni contrasenas
- **Logging estructurado** -- salida JSON `log/slog` con redaccion automatica de credenciales
- **Privilegios minimos** -- funciona como usuario no-root con degradacion elegante para rutas sin permiso

## Licencia

MIT -- ver [LICENSE](LICENSE).
# Compatibilidad con Windows 7 (legacy)

El despliegue masivo detecta automáticamente Windows 7 y los equipos Windows
de 32 bits. En esos casos instala `kite-collector-legacy`, compilado con Go
1.17/386 softfloat para Windows 7 SP1; los Windows modernos de 64 bits siguen usando el MSI
completo. El operador ejecuta el mismo `./deploy.sh`: no debe elegir el
instalador ni actualizar PowerShell manualmente.

La edición legacy permite enrolamiento por token, validación de certificados,
heartbeat firmado, ejecución como servicio e inventario local persistente. La
base transaccional se guarda en `C:\ProgramData\kite-collector\kite.db`; el
dashboard local está disponible en `http://127.0.0.1:9090` y el servicio
actualiza el inventario al iniciar y cada seis horas. Incluye sistema,
hardware, software, actualizaciones, usuarios, servicios, procesos, red,
puertos, discos, drivers, tareas, inicio y controles de seguridad disponibles
en Windows 7. Cada snapshot también se sincroniza automáticamente por OTLP con
mTLS: el resumen llega a `analytics_asset_current_state` y todas las categorías
completas llegan a `analytics_windows_inventory_categories` en Supabase. Si la
red no está disponible, el agente conserva el snapshot local y reintenta cada
cinco minutos. Windows 7 ya no recibe soporte del fabricante, por lo que esta
edición debe tratarse como un puente de migración y WinRM debe limitarse a la
red de administración.
