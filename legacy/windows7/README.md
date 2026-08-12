# Kite Collector Legacy for Windows 7

This isolated 32-bit edition exists for Windows 7 SP1 and Windows 8 systems
that cannot run the current collector. It uses Go 1.17 plus the software
floating-point 386 backend for compatibility with unpatched and very old
Windows 7 hardware.

The legacy service now maintains a local transactional inventory database at
`C:\ProgramData\kite-collector\kite.db` and serves a loopback-only dashboard at
`http://127.0.0.1:9090`. It scans on startup and every six hours. Inventory
categories include system/OS facts, CPU, memory, BIOS, motherboard, storage,
network adapters, routes, ports, software from both registry views, hotfixes,
users/groups, services, processes, startup entries, shares, printers, drivers,
scheduled tasks, PnP devices, antivirus, firewall, audit policy, BitLocker,
certificates, event-log catalog, and time synchronization.

After enrollment, each completed snapshot is also sent through the same
mTLS-protected OTLP pipeline as the modern collector. The asset summary lands
in `analytics_asset_current_state`, while the complete category payloads land
in `analytics_windows_inventory_categories` in Supabase. A snapshot is marked
synced only after every category is accepted; failures retry every five
minutes without affecting the local database or dashboard.

Manual operations:

```cmd
kite-collector-legacy scan
kite-collector-legacy query
kite-collector-legacy query installed_software_native
kite-collector-legacy dashboard
```

The Windows 7 database uses Bolt rather than SQLite because the maintained
pure-Go SQLite backend does not ship a Windows/386 port compatible with Go
1.17. It remains a single embedded database file with atomic transactions and
retains the newest 30 full snapshots.

Build it with:

```sh
make build-windows7
```

Windows 7 is end-of-life. Use this edition only as a migration bridge and
restrict WinRM to the management subnet.
