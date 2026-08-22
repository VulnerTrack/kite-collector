# Active Directory laboratory

This Compose stack starts a disposable Samba Active Directory Domain
Controller for manually testing the LDAP discovery and machine graph.
It is isolated to loopback ports and must never be used as production AD.

## Start

```bash
cp .env.example .env
docker compose up -d
docker compose logs -f dc01
```

Verify the domain once the container is ready:

```bash
docker compose exec dc01 samba-tool domain level show
docker compose exec dc01 samba-tool user list
```

The lab domain is `KITE.LAB` (`DC=KITE,DC=LAB`). The LDAP endpoint exposed to
the host is `127.0.0.1:1389`; bind as `Administrator@KITE.LAB` using the
password in `.env`. Configure kite-collector with `tls_mode: none` for this
first local test because port 1389 maps plain LDAP. Do not use that setting
outside this loopback-only lab.

## Run the collector test

The `collector` profile builds the repository's current source in Docker, so
the host does not need Go installed:

```bash
docker compose --profile collector up --build collector
docker compose logs collector
```

The scan uses the internal `dc01:389` endpoint and writes its encrypted SQLite
database to the `collector_data` volume. It should discover `dc01` through
LDAP and materialize the AD graph.

## View the results

```bash
docker compose --profile dashboard up -d --build dashboard
```

Open [http://127.0.0.1:19090](http://127.0.0.1:19090). The dashboard is
read-only and uses the same `collector_data` volume as the scan.

## Stop or reset

```bash
docker compose down
docker compose down -v # also deletes the laboratory domain state
```
