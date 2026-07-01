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
   ```

### Snap (Linux Universal)

Para cualquier distribución de Linux compatible con Snap (incluyendo Ubuntu, Debian, Fedora, Arch Linux, etc.), puedes instalar el agente directamente desde la Snap Store:

```bash
sudo snap install kite-collector
```

### Otras distribuciones Linux (Fedora, Red Hat, Arch Linux, etc.)

Para aquellas distribuciones que NO utilizan el gestor de paquetes `apt` (como Fedora, Red Hat Enterprise Linux, CentOS o Arch Linux, las cuales usan `dnf`, `yum` o `pacman`):

- **Fedora / Red Hat / CentOS**: Puedes descargar el paquete `.rpm` directamente desde la pestaña de [GitHub Releases](https://github.com/VulnerTrack/kite-collector/releases) e instalarlo usando tu gestor de paquetes (por ejemplo, `sudo dnf install ./kite-collector-*.rpm`).
- **Arch Linux / Otras distribuciones**: Descarga el binario precompilado dentro del archivo `.tar.gz` desde la página de Releases, extráelo y colócalo en tu `PATH`. Alternativamente, puedes compilarlo desde el código fuente.

### Descarga Manual / Otros Sistemas

Si prefieres descargar directamente los binarios precompilados o estás en macOS/Windows:

```bash
# Linux
curl -sSL https://github.com/VulnerTrack/kite-collector/releases/latest/download/kite-collector_linux_amd64 -o kite-collector
chmod +x kite-collector

# macOS
brew install vulnertrack/tap/kite-collector

# Windows (PowerShell)
irm https://get.kite-collector.dev/install.ps1 | iex
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
    allowlist_file: ./configs/authorized-assets.yaml
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
