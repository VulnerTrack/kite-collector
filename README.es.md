# kite-collector

[English](README.md)

Agente de Base de Datos de Gestión de Configuración (CMDB) para el descubrimiento de activos de TI.

Un solo binario que escanea tu red, inventaría el software instalado y registra el estado de configuración real de cada host que observa. Las fuentes de descubrimiento abarcan APIs de nube, hipervisores, el sistema operativo, servicios en escucha y decenas de archivos de configuración (SSH, firewall, PAM, nsswitch, MongoDB, MySQL, …).

Los resultados se guardan en una base de datos SQLite local. Sin servidores, sin dependencias, completamente offline.

**Contenido:** [Instalación](#instalación), [Primer escaneo](#primer-escaneo), [Qué descubre](#qué-descubre), [Configuración](#configuración), [Comandos](#comandos), [Base de datos](#base-de-datos), [Dashboard](#dashboard), [API de escaneo](#api-de-escaneo), [Envío a OpenTelemetry](#envío-a-opentelemetry), [Seguridad](#seguridad)

## Instalación

### Instalación rápida (Linux, macOS, FreeBSD, OpenBSD)

```bash
curl -fsSL https://raw.githubusercontent.com/VulnerTrack/kite-collector/main/installers/installer.sh | sh
sudo kite-collector enroll    # inicia sesión; el servicio arranca al quedar enrolado
```

El script instala el collector y registra su servicio en segundo plano
(habilitado al arranque; se inicia en cuanto el host queda enrolado), así que
solo falta iniciar sesión. Elige el canal nativo: el repositorio APT en
Debian/Ubuntu, el `.rpm` del release en Fedora/RHEL/SUSE y el binario estático
en `/usr/local/bin` en los demás, y verifica cada descarga contra el
`checksums.txt` del release. En un host donde el script no pudo registrar el
servicio, `sudo kite-collector install` por sí solo lo registra, inicia sesión
y lo arranca.

Define estas variables del lado `sh` de la tubería, por ejemplo
`curl -fsSL …/installer.sh | KITE_OSQUERY=no sh`:

| variable | efecto |
|----------|--------|
| `KITE_VERSION=1.2.3` | fija un release |
| `KITE_OSQUERY=no` | collector simple, y lo conserva en ejecuciones posteriores, aunque exista el paquete con osquery (`yes` exige el paquete) |
| `KITE_INSTALL_METHOD=binary` | fuerza `apt`, `rpm` o `binary` |
| `KITE_INSTALL_DIR=$HOME/.local/bin` | destino del binario; un directorio en el que puedes escribir no requiere root |

### Ubuntu / Debian (repositorio APT)

```bash
curl -fsSL https://vulnertrack.github.io/kite-collector/repository.key \
  | sudo tee /usr/share/keyrings/kite-collector-keyring.asc > /dev/null
echo "deb [signed-by=/usr/share/keyrings/kite-collector-keyring.asc] https://vulnertrack.github.io/kite-collector/ stable main" \
  | sudo tee /etc/apt/sources.list.d/kite-collector.list
sudo apt update && sudo apt install kite-collector
sudo kite-collector enroll
```

El paquete trae y habilita su propia unidad de systemd, así que después de
`apt install` solo queda enrolar. El repositorio conserva los tres releases más
recientes de cada paquete: `apt-cache policy kite-collector` los lista y
`sudo apt install kite-collector=1.2.3` fija una versión o regresa a una
anterior. Los releases más antiguos siguen en la página de
[GitHub Releases](https://github.com/VulnerTrack/kite-collector/releases).

### Fedora, RHEL, SUSE, Arch

- **Fedora / RHEL / SUSE:** la instalación rápida usa el `.rpm` del release.
  Para hacerlo a mano, descárgalo de
  [GitHub Releases](https://github.com/VulnerTrack/kite-collector/releases) y
  ejecuta `sudo dnf install ./kite-collector-*.rpm`.
- **Arch:** instala desde el repositorio pacman firmado con
  `sudo pacman -Syu kite-collector` después de agregarlo como se describe en
  [packaging/pacman/README.md](packaging/pacman/README.md#client-install).

### Snap

```bash
sudo snap install kite-collector
sudo kite-collector install
sudo kite-collector enroll
```

snapd administra el binario, el servicio y las actualizaciones; `install`
prepara el almacenamiento persistente en `/var/snap/kite-collector/common/certs`
y `enroll` habilita e inicia el servicio. Revisa el servicio con
`snap services kite-collector` y sigue sus logs con
`sudo snap logs -f kite-collector.kite-collector-daemon`.

### macOS (Homebrew)

```bash
brew install --cask vulnertrack/tap/kite-collector
sudo kite-collector install   # registra launchd contra el binario que administra brew, sin una segunda copia
```

El cask elimina el atributo de cuarentena de Gatekeeper, así que el binario se
ejecuta sin el aviso de "desarrollador no identificado". Para actualizar basta
`brew upgrade --cask kite-collector`: el servicio en ejecución detecta el
binario nuevo y se reinicia con él. Ejecuta `sudo kite-collector uninstall`
antes de `brew uninstall`, porque el cask solo elimina el job de launchd con
`brew uninstall --zap`.

### Windows

Descarga `kite-collector_<version>_amd64.msi` de
[GitHub Releases](https://github.com/VulnerTrack/kite-collector/releases) y haz
doble clic, o despliégalo en silencio (GPO/Intune) como administrador:

```powershell
msiexec /i kite-collector_<version>_amd64.msi /quiet
```

Otras formas de instalar:

| Método | Cómo |
| ------ | ---- |
| Asistente gráfico | Doble clic en `kite-collector_windows_amd64_bin.exe`; detecta el doble clic y abre el instalador |
| PowerShell | `irm https://get.kite-collector.dev/install.ps1 \| iex` |
| PowerShell, solo binario (sin servicio) | `& ([scriptblock]::Create((irm https://get.kite-collector.dev/install.ps1))) -NoService` |
| WinGet | `winget install VulnerTrack.KiteCollector` |
| Scoop | `scoop bucket add vulnertrack https://github.com/VulnerTrack/homebrew-tap` y después `scoop install kite-collector` |

Guías paso a paso (en inglés): [docs/windows-quickstart.md](docs/windows-quickstart.md)
y [docs/window_install.md](docs/window_install.md). Las computadoras con
Windows 7 SP1 y Windows 8 necesitan la compilación legacy aislada de 32 bits:
[legacy/windows7/README.md](legacy/windows7/README.md).

### Agregar osquery

| Plataforma | Cómo |
| ---------- | ---- |
| Debian / Ubuntu amd64 | La instalación rápida elige `kite-collector-osquery` por defecto; con apt, `sudo apt install kite-collector-osquery` |
| Windows | `kite-collector-osquery_<version>_amd64.msi` ([detalles](docs/window_install.md#bundled-osquery-msi-kite-collector-osquery)) |
| macOS | `brew install --cask osquery` y después `sudo kite-collector install --with-osquery` ([detalles](docs/macos-osquery.md)) |

En Linux y Windows el paquete es el mismo agente más un osqueryd que corre como
el servicio `kite-osqueryd`. Vive bajo las rutas propias de kite, así que nunca
choca con una instalación independiente de osquery, y la fuente osquery del
collector encuentra su socket por sí sola. Los dos paquetes de Debian se
reemplazan entre sí al instalarse.

macOS no tiene paquete con osquery. kite adopta el osquery que ya tienes,
porque un osqueryd incluido tendría que correr bajo la firma de kite y su
permiso de Acceso total al disco. Si ejecutas el daemon propio de osquery
(`sudo osqueryctl start`), el descubrimiento lo detecta sin configurar nada en
kite. Sin Acceso total al disco, osqueryd lee las rutas protegidas por TCC
como *vacías en lugar de fallar*; lee
[docs/macos-osquery.md](docs/macos-osquery.md) antes de confiar en un
resultado limpio.

### Descarga manual y compilación desde el código fuente

```bash
# Linux
curl -sSL https://github.com/VulnerTrack/kite-collector/releases/latest/download/kite-collector_linux_amd64.tar.gz | tar xz

# macOS
curl -sSL https://github.com/VulnerTrack/kite-collector/releases/latest/download/kite-collector_darwin_arm64.tar.gz | tar xz

# Desde el código fuente
make build

# Compilación cruzada para Windows
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -trimpath -ldflags="-s -w -H=windowsgui" -o bin/kite-collector.exe ./cmd/kite-collector
```

### Actualizaciones y desinstalación

Cuando un gestor de paquetes (Homebrew, apt, dnf, pacman) instaló el binario,
`kite-collector install` registra el servicio contra la ruta que administra el
paquete en lugar de copiarlo. Una actualización del paquete reinicia entonces
el servicio con la versión nueva; el agente nota que su binario cambió en disco
y se relanza, esperando antes a que termine cualquier escaneo en curso.

- `install --copy` fuerza una copia en la ruta del servicio.
- `install --repair` corrige un servicio que quedó apuntando a una copia
  desactualizada (`kite-collector doctor` te avisa cuando es el caso).
- `uninstall --purge` también elimina el directorio de datos.

### Despliegue masivo

La página **Mass deployment** del dashboard descubre computadoras en la red
local y genera un paquete de Ansible de corta duración que instala y enrola
collectors en equipos Windows, Linux y macOS, con una credencial de
enrolamiento de un solo uso por computadora. Los equipos Windows necesitan
WinRM habilitado primero. El recorrido completo y el comando para preparar
WinRM están en [docs/mass-deployment.md](docs/mass-deployment.md) (en inglés).

## Primer escaneo

```bash
kite-collector status                          # ¿instalado, enrolado, sano?
kite-collector scan                            # escanea este host (sin configuración)
kite-collector scan --scope 192.168.1.0/24     # escanea una subred
kite-collector scan --source docker            # incluye contenedores Docker
kite-collector scan --output json              # table (por defecto), json o csv
kite-collector dashboard                       # explora los resultados
kite-collector agent --stream --interval 6h    # monitoreo continuo
```

Cuando algo no se ve bien, `kite-collector doctor` explica por qué y qué
ejecutar a continuación.

## Qué descubre

| Fuente          | Activos                                                     | Autenticación             |
| --------------- | ----------------------------------------------------------- | ------------------------- |
| Agente local    | Hostname, SO, interfaces, paquetes instalados               | No                        |
| Escaneo de red  | Hosts alcanzables por conexión TCP                          | No                        |
| Docker / Podman | Contenedores, imágenes, redes                               | Acceso al socket          |
| UniFi           | Clientes (VLAN, puerto de switch, señal), equipos de red    | Credenciales del controlador |
| AWS EC2         | Instancias EC2 en todas las regiones                        | Credenciales IAM          |
| GCP Compute     | VMs de Compute Engine                                       | ADC                       |
| Azure           | Máquinas virtuales en todas las suscripciones               | Service principal         |
| Proxmox         | VMs y contenedores LXC                                      | Token de API              |
| SNMP            | Switches, routers, UPS                                      | Community string          |

Estas son las fuentes comunes. Todas las fuentes, con las credenciales que
necesita cada una, están en
[configs/kite-collector.example.yaml](configs/kite-collector.example.yaml).

### Revisiones de configuración

Para cada host, el agente registra:

| Revisión              | Qué registra                                               |
| --------------------- | ---------------------------------------------------------- |
| Configuración SSH     | `PermitRootLogin`, `PasswordAuthentication`, ciphers, MACs |
| Firewall              | Tablas de reglas de iptables / nftables / ufw              |
| Kernel                | Ajuste de ASLR, línea de comandos del kernel, módulos cargados |
| Permisos de archivos  | `/etc/shadow`, `/etc/sudoers`, secretos legibles por todos |
| Servicios en escucha  | Puertos TCP/UDP abiertos por proceso                       |
| Bases de datos en escucha | Direcciones de enlace de Postgres / MySQL / MongoDB    |

Estas observaciones llegan a la CMDB como datos de inventario. kite-collector
reporta el estado de configuración y no lo califica contra una taxonomía de
vulnerabilidades.

### Inventario de software

El agente lee los paquetes instalados de los gestores de paquetes del sistema
(dpkg, rpm, dnf, zypper, pacman, apk, xbps, portage, nix, Homebrew, MacPorts,
Flatpak, Snap, el registro de Windows, WinGet, Chocolatey, Scoop, …) y de los
ecosistemas de lenguajes (npm, pip, Cargo, módulos de Go, Maven, NuGet,
RubyGems, Composer, Conda, …). Cada paquete recibe un identificador
[CPE 2.3](https://nvd.nist.gov/products/cpe) para que las herramientas que lo
consumen (tu SIEM, tu CMDB, tu escáner de vulnerabilidades) puedan cruzar el
inventario con sus propios datos.

## Configuración

kite-collector funciona sin archivo de configuración. Para cambiar su
comportamiento, crea una configuración YAML:

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
    unifi:
      enabled: true
      endpoint: https://192.168.1.1:8443
      site: default

classification:
  authorization:
    allowlist_file: ./configs/authorized-machines.yaml
    match_fields: [hostname]

audit:
  enabled: true

stale_threshold: 168h # 7 días
```

Las variables de entorno con prefijo `KITE_` sobrescriben la configuración (por
ejemplo `KITE_LOG_LEVEL=debug`).

Consulta `configs/kite-collector.example.yaml` para ver todas las opciones.

## Comandos

| Comando          | Descripción                                                     |
| ---------------- | --------------------------------------------------------------- |
| `install`        | Instala como servicio e inicia sesión (`--agent-code` + `--token` sin interfaz) |
| `uninstall`      | Elimina el servicio                                             |
| `enroll`         | Enrola con VulnerTrack (navegador, código de inicio de sesión o token con alcance) |
| `unenroll`       | Elimina el enrolamiento local                                   |
| `scan`           | Descubrimiento único + auditoría de configuración (`--detect` solo sondea) |
| `agent --stream` | Modo continuo con intervalo configurable                        |
| `service`        | Start/stop/restart/status del servicio instalado                |
| `status`         | Estado del agente de un vistazo (`--json` para scripts)         |
| `doctor`         | Diagnóstico por etapas con sugerencias de corrección (alias: `check`) |
| `dashboard`      | UI local en el navegador; aquí se exploran los datos            |
| `fleet`          | Descubre computadoras y despliega collectors                    |
| `integrations`   | Lista y configura los servicios conectados a Kite               |
| `version`        | Muestra versión, commit y fecha de compilación                  |

Los comandos anteriores (`stream`, `query`, `db`, `diff`, `report`, …) siguen
funcionando pero no aparecen en la ayuda, y cada uno indica su reemplazo al
ejecutarse.

## Clasificación de activos

Cada activo descubierto se clasifica en dos ejes:

**Autorización** (¿este activo debería estar aquí?):

- `unknown`: valor por defecto, aún sin evaluar
- `authorized`: coincide con una entrada de la lista de permitidos
- `unauthorized`: explícitamente fuera de la lista de permitidos

**Estado de gestión** (¿este activo cumple nuestros controles de seguridad?):

- `unknown`: valor por defecto, controles sin configurar
- `managed`: tiene todos los controles requeridos
- `unmanaged`: le falta uno o más controles requeridos

Los activos nunca son `authorized` por defecto. Solo una coincidencia positiva
contra tu fuente de verdad produce `authorized`.

## Base de datos

Todos los resultados se guardan en un archivo SQLite, `kite.db`, cifrado en
reposo con una llave derivada de la identidad del agente. Un `scan` único
escribe `./kite.db`; el servicio instalado lo guarda en su directorio de datos
y `kite-collector status` muestra la ruta. Explora y exporta sus tablas desde
el dashboard en <http://127.0.0.1:9090/tables>, o consulta la copia de trabajo
descifrada con `sqlite3` mientras kite-collector la tiene abierta:
[docs/sqlite-cheatsheet.md](docs/sqlite-cheatsheet.md) (en inglés).

## Integración con la plataforma

kite-collector puede alimentar al [Vulnertrack Intelligence Engine](https://github.com/VulnerTrack/vulnertrack-intelligence-engine) para que su inventario sea la fuente de verdad de las herramientas que lo consumen:

```bash
# Importar resultados de escaneo a ClickHouse
vie kite scan --scope 192.168.1.0/24 --import

# Consultar activos importados
vie kite assets --authorized unauthorized
```

## Dashboard

`kite-collector dashboard` sirve la UI local. Su banner de inicio muestra las
URLs que lo alcanzan, cada una etiquetada **this machine**, **local network** o
**public**, así que el banner indica si está expuesto. Las direcciones de
puentes de contenedores y VMs se cuentan en lugar de listarse. Con
`kite-collector agent --dashboard-addr` las mismas URLs aparecen en el log de
inicio.

- **Containers**: vista en vivo de los contenedores locales de Docker / Podman
  / Compose con gráficas de CPU y memoria e historial de imágenes:
  [docs/container-observability.md](docs/container-observability.md).
- **Volumes**: capacidad, presión de inodos y estado de cifrado de cada sistema
  de archivos montado en toda la flota:
  [docs/storage-observability.md](docs/storage-observability.md).

## API de escaneo

En modo de larga duración (`kite-collector agent`), el agente sirve una API
REST que inicia, sigue (Server-Sent Events) y cancela escaneos; el dashboard
usa los mismos endpoints. Escucha en `127.0.0.1:8080` por defecto (`api.addr`).
Define `fleet.api_key` antes de enlazarla a otra dirección; sin llave la API no
tiene autenticación. Solo corre un escaneo a la vez. Referencia:
[docs/scan-api.md](docs/scan-api.md).

## Envío a OpenTelemetry

kite-collector envía los eventos del ciclo de vida de las máquinas a cualquier
collector compatible con OTLP (Grafana Alloy, OpenTelemetry Collector, Datadog
Agent, etc.) como registros de log OTLP sobre HTTP/JSON:

```yaml
streaming:
  interval: 6h
  otlp:
    endpoint: http://localhost:4318
    protocol: http
```

```bash
kite-collector agent --stream --interval 6h
```

- Atributos y tipos de eventos: [docs/telemetry-contract.md](docs/telemetry-contract.md)
- mTLS, firma y cifrado del payload, reintentos:
  [docs/otlp-streaming.md](docs/otlp-streaming.md)
- Un collector listo para ejecutar con Docker Compose:
  [examples/streaming-to-otel/](examples/streaming-to-otel/)

## Seguridad

- **Solo lectura**: nunca escribe, modifica ni ejecuta código en los sistemas descubiertos
- **Almacenamiento dedicado de credenciales**: las contraseñas de los conectores nunca entran a SQLite ni al YAML; Kite usa el almacén de credenciales del sistema operativo cuando está disponible y, en hosts sin interfaz, un almacén AES-256-GCM cifrado con la llave de identidad
- **Logs estructurados**: salida JSON de `log/slog` con redacción automática de credenciales
- **Privilegios mínimos**: funciona sin root y degrada con gracia en rutas sin permiso

## Licencia

MIT, ver [LICENSE](LICENSE).
