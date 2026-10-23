# SQLite Cheatsheet

Quick reference for querying kite-collector's SQLite database.

## Reading the database

`kite.db` is encrypted at rest (AES-256-GCM, with a key derived from the agent
identity), so `sqlite3 kite.db` cannot open it. A one-shot `scan` writes
`./kite.db`; the installed service keeps it in its data directory, and
`kite-collector status` prints the path.

**Without SQL.** `kite-collector dashboard` serves a browser for every table at
<http://127.0.0.1:9090/tables>, and each table exports as CSV:

```bash
curl -o machines.csv http://127.0.0.1:9090/api/v1/tables/machines/export.csv
```

**With SQL.** While the agent or the dashboard has the database open, its
decrypted working copy sits in RAM-backed storage. On Linux that is
`/dev/shm/kite-collector/<id>/kite.db.work` for the service, or
`/run/user/<uid>/kite-collector/<id>/kite.db.work` for a per-user process,
with one `<id>` directory per database path. The service's directory is
readable only by root, so list it through `sudo`, then open the copy
read-only so a stray statement cannot change what the agent recorded:

```bash
sudo sh -c 'ls /dev/shm/kite-collector/*/kite.db.work'
sudo sqlite3 -readonly -table /dev/shm/kite-collector/<id>/kite.db.work
```

The copy exists only while a kite-collector process holds the database open.
If the service is not running, start `kite-collector dashboard` first.

## Common queries

### List all machines

```sql
SELECT hostname, machine_type, is_authorized, is_managed, last_seen_at
FROM machines
ORDER BY last_seen_at DESC;
```

### Software with CVE-matching CPE

```sql
SELECT software_name, version, cpe23
FROM installed_software
WHERE cpe23 != ''
LIMIT 20;
```

### Configuration findings by severity

```sql
SELECT severity, count(*) AS total
FROM config_findings
GROUP BY severity
ORDER BY CASE severity
  WHEN 'critical' THEN 1
  WHEN 'high' THEN 2
  WHEN 'medium' THEN 3
  WHEN 'low' THEN 4
  ELSE 5
END;
```

### Findings with remediation

```sql
SELECT m.hostname, f.check_id, f.severity, f.title, f.remediation
FROM config_findings f
JOIN machines m ON m.id = f.machine_id
ORDER BY CASE f.severity
  WHEN 'critical' THEN 1
  WHEN 'high' THEN 2
  WHEN 'medium' THEN 3
  ELSE 4
END;
```

### Machines not seen in 7 days

Timestamps are stored as RFC 3339 text; `datetime()` normalizes them so the
comparison holds whatever offset they were written with.

```sql
SELECT hostname, machine_type, last_seen_at
FROM machines
WHERE datetime(last_seen_at) < datetime('now', '-7 days')
ORDER BY last_seen_at;
```

### Unauthorized machines

```sql
SELECT hostname, machine_type, discovery_source, first_seen_at
FROM machines
WHERE is_authorized = 'unauthorized'
ORDER BY first_seen_at DESC;
```

### Unmanaged machines

```sql
SELECT hostname, machine_type, os_family, discovery_source
FROM machines
WHERE is_managed = 'unmanaged';
```

### Machines with their software count

```sql
SELECT m.hostname, m.machine_type, count(s.id) AS packages
FROM machines m
LEFT JOIN installed_software s ON s.machine_id = m.id
GROUP BY m.id
ORDER BY packages DESC;
```

### Scan history

```sql
SELECT started_at, status, total_machines, new_machines, stale_machines, coverage_percent
FROM scan_runs
ORDER BY started_at DESC
LIMIT 10;
```

### Machines discovered per source

```sql
SELECT discovery_source, count(*) AS total
FROM machines
GROUP BY discovery_source
ORDER BY total DESC;
```

### Network interfaces with public IPs

```sql
SELECT m.hostname, n.ip_address, n.mac_address
FROM network_interfaces n
JOIN machines m ON m.id = n.machine_id
WHERE n.is_public = 1;
```

## SQLite shell tips

```
.mode table        -- formatted table output
.mode csv          -- CSV output
.mode json         -- JSON output
.headers on        -- show column headers
.schema machines   -- show table schema
.tables            -- list all tables
.quit              -- exit
```

## Export a query to CSV

```bash
sudo sqlite3 -readonly -header -csv /dev/shm/kite-collector/<id>/kite.db.work \
  "SELECT hostname, machine_type, last_seen_at FROM machines" > machines.csv
```

## Core tables

The database holds about 260 tables, most of them per-collector host detail;
`.tables` lists them all. The ones most queries start from:

| Table | Description |
|-------|-------------|
| `machines` | Discovered machines (hostname, type, classification) |
| `network_interfaces` | IP/MAC addresses per machine |
| `installed_software` | Packages with CPE identifiers |
| `config_findings` | Configuration audit results with remediation and CIS control |
| `scan_runs` | Scan history with coverage metrics |
| `events` | Machine lifecycle events |
