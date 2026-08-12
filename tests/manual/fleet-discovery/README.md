# Laboratorio de descubrimiento de equipos

Este laboratorio levanta exactamente dos equipos objetivo en la red
`172.30.50.0/24`:

- `kite-test-ubuntu` (`172.30.50.10`, nombre NetBIOS `UBUNTU-KITE`): Ubuntu
  24.04 con OpenSSH. Kite lo clasifica como Linux por el banner SSH y obtiene
  su nombre por NetBIOS.
- `kite-test-windows` (`172.30.50.20`, nombre NetBIOS `WIN-KITE-TEST`):
  simulador ligero de Windows con WinRM y un servidor SMB/NetBIOS independiente.
  Kite lo clasifica como Windows por WinRM y puede obtener su identidad NetBIOS.

Cada objetivo tiene su propio hostname, dirección IP, dirección MAC, procesos,
sistema de archivos y espacio de red. Para Kite son dos computadoras separadas.
El segundo contenedor no ejecuta el kernel de Windows: Docker Engine sobre
Linux no puede ejecutar imágenes Windows nativas. Reproduce las señales de red
que utiliza el descubrimiento de Kite y evita descargar/activar una VM completa.

## Iniciar los objetivos

Desde este directorio:

```bash
docker compose up -d --build
docker compose ps
```

## Probar el botón "Discover computers"

Kite tiene que estar conectado a la misma red Docker para que su interfaz
`eth0` quede dentro del `/24` del laboratorio. Desde la raíz de
`kite-collector`:

```bash
docker build -t kite-collector:local .
docker run --rm --name kite-discovery-ui \
  --network kite-fleet-discovery-lab \
  -p 9090:9090 \
  kite-collector:local dashboard \
  --addr 0.0.0.0:9090 \
  --no-browser \
  --with-agent=false \
  --enable-install=false \
  --db /tmp/kite.db \
  --certs-dir /tmp/kite-certs
```

Abrir <http://localhost:9090/fleet>, confirmar la red `172.30.50.0/24` y
presionar **Discover computers**. Deben aparecer `172.30.50.10` como Linux y
`172.30.50.20` como Windows.

El usuario de laboratorio para SSH es `kite` y la contraseña es `kite-test`.
El simulador Windows sirve para descubrimiento y para probar acceso SMB como
invitado; no implementa una sesión WinRM autenticada ni permite probar el
despliegue remoto de ejecutables Windows. Para eso hace falta una VM Windows.

## Detener el laboratorio

```bash
docker compose down
```
