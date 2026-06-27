# Hostname signal catalog

A multi-layer survey of where hostnames leak into observable network
traffic, organised by OSI layer and tagged with a reliability tier so
collectors can rank competing signals deterministically.

Companion to the `intranetweb.HostSignal` taxonomy (`probe.go`). Each
entry below is a candidate `HostSignal` constant.

## Reliability tiers

| Tier   | Trust property                                                            | Example signals               |
| ------ | ------------------------------------------------------------------------- | ----------------------------- |
| **A**  | Operator-curated; no network round-trip. Mismatch == operator error.      | `Target.Host`, /etc/hosts     |
| **B**  | Server self-asserts the name on the wire; cryptographically signed.       | TLS SAN, SSH host key cert    |
| **C**  | Server self-asserts the name on the wire; unsigned but on a live socket.  | SSH banner, SMTP HELO, SNMP   |
| **D**  | Third-party assertion; spoofable but cheap.                               | DNS PTR, NetBIOS, mDNS PTR    |
| **E**  | Heuristic / derived; only useful as a last-resort hint.                   | DHCP hostname, Server header  |
| **F**  | Synthetic; not actually a hostname.                                       | IP-fallback                   |

Within a tier, prefer the source closest to the wire (lower OSI layer)
because it's harder to forge end-to-end. Across tiers, A always wins.

## Catalog by OSI layer

### Layer 2 — link

| Source                              | Port/proto    | Field                                 | Tier | Notes                                                                                                |
| ----------------------------------- | ------------- | ------------------------------------- | ---- | ---------------------------------------------------------------------------------------------------- |
| **LLDP** (IEEE 802.1AB)             | EtherType 0x88CC | System Name TLV (type 5)            | C    | Switches/APs/IP-phones broadcast every 30s. Read-only via pcap or `lldpctl`. Unspoofable from off-LAN. |
| **CDP** (Cisco)                     | EtherType 0x2000 | Device-ID TLV                       | C    | Cisco-only equivalent. Same trust properties.                                                        |
| **EDP/FDP/NDP/SONMP**               | various       | Vendor-specific name TLV              | C    | Extreme/Foundry/Nortel proprietary.                                                                  |
| **DHCP options 12 / 81**            | UDP 67/68     | Host Name (12), Client FQDN (81)      | E    | Sent by *client* on lease — clients lie. Useful when reading lease-database server-side.             |
| **DHCPv6 FQDN option 39**           | UDP 546/547   | Client FQDN                           | E    | Same trust as DHCPv4.                                                                                |
| **ARP / NDP**                       | EtherType 0x0806 / ICMPv6 | (no name)                  | —    | MAC→IP only. Use as join-key into other signals.                                                     |
| **IPv6 RA + DHCPv6**                | ICMPv6 type 134 | DNS Search List option (RFC 8106)   | E    | Domain suffix only.                                                                                  |

### Layer 3 / 4 — network + transport

| Source                              | Port/proto    | Field                                 | Tier | Notes                                                                                                |
| ----------------------------------- | ------------- | ------------------------------------- | ---- | ---------------------------------------------------------------------------------------------------- |
| **ICMP echo reply**                 | IP proto 1    | (no name)                             | —    | Confirms liveness only. Hostname comes from joined L7 lookup.                                        |
| **TCP RST timing / fingerprint**    | TCP           | (no name, OS hint only)               | —    | p0f-style. Useful for OS-class enrichment, not hostname.                                             |
| **QUIC initial packet**             | UDP 443       | SNI (in encrypted ClientHello once ECH is universal — until then, plaintext) | B-ish | Client-supplied — server-side trust depends on whether you're the server or eavesdropper. |

### Service-discovery (multicast/broadcast)

| Source                              | Port/proto    | Field                                  | Tier | Notes                                                                                                |
| ----------------------------------- | ------------- | -------------------------------------- | ---- | ---------------------------------------------------------------------------------------------------- |
| **mDNS** (Bonjour, RFC 6762)        | UDP 5353      | PTR / SRV / A / AAAA / `_device-info._tcp` TXT | C    | `<name>.local.` Reliable on LAN, broadcasted unprompted by every Apple device + many printers/NAS.   |
| **mDNS service enumeration**        | UDP 5353      | `_services._dns-sd._udp.local`         | C    | Browse-all-services then resolve each instance to a hostname.                                        |
| **SSDP / UPnP**                     | UDP 1900      | M-SEARCH response → LOCATION → description.xml `friendlyName` + `modelName` + UDN | D    | LAN-only. SmartTVs/routers/NAS. UDN is a UUID; friendlyName is user-editable. |
| **WS-Discovery** (Microsoft)        | UDP 3702      | XMLAddressing → ProbeMatch → ComputerName | D    | Windows + network printers. Common on AD-joined LANs.                                                |
| **NetBIOS Name Service**            | UDP 137       | Node Status (NBSTAT) → name table     | D    | Windows pre-AD. Returns 16-byte names (server, workstation, AD groups). Trivially spoofable.         |
| **LLMNR** (Link-Local Multicast NR) | UDP 5355      | Single-shot resolution                | D    | Windows fallback when DNS fails. Spoofable (Responder attack class).                                 |
| **NBT (NetBIOS over TCP)**          | UDP 138 / TCP 139 | Same as NBNS                       | D    | Datagram + session services.                                                                         |
| **BOOTP/PXE**                       | UDP 67        | sname field                           | E    | Server hostname, present in PXE boot offers.                                                         |

### Naming / directory

| Source                              | Port/proto    | Field                                 | Tier | Notes                                                                                                |
| ----------------------------------- | ------------- | ------------------------------------- | ---- | ---------------------------------------------------------------------------------------------------- |
| **DNS PTR**                         | UDP/TCP 53    | in-addr.arpa / ip6.arpa               | D    | Already wired (`HostSignalReverseDNS`). Operator-curated *if* you trust the resolver.                |
| **DNS A/AAAA (forward)**            | UDP/TCP 53    | Hostname → IP                         | A    | When the caller already has a name and wants to validate the IP — flips the trust direction.        |
| **DNS-SD via DNS** (RFC 6763)       | UDP/TCP 53    | `b._dns-sd._udp.<domain>` PTR         | C    | Unicast DNS Service Discovery. Same shape as mDNS but enterprise-grade.                              |
| **DNS SRV**                         | UDP/TCP 53    | `_service._proto.<domain>` → target   | C    | LDAP `_ldap._tcp.dc._msdcs.<forest>`, Kerberos `_kerberos._udp.<realm>`, etc. Gives DC hostnames.    |
| **LDAP rootDSE**                    | TCP 389/636   | `dnsHostName`, `serverName`, `defaultNamingContext` | C | Active Directory DC self-identification. Bind-anonymous works in most deployments.              |
| **Kerberos AS-REQ / TGS-REQ**       | UDP/TCP 88    | `srealm`, `sname`                     | C    | Principal carries realm + service name; KDC discovery via DNS SRV.                                   |

### Layer 7 — transport-security

| Source                              | Port/proto    | Field                                 | Tier | Notes                                                                                                |
| ----------------------------------- | ------------- | ------------------------------------- | ---- | ---------------------------------------------------------------------------------------------------- |
| **TLS SNI** (ClientHello)           | TCP 443 etc.  | server_name extension                 | A-ish | What the *client* wants to reach. Useful when you're observing client traffic; not server-asserted.  |
| **TLS Cert SAN DNSName**            | TCP TLS-any   | x509 extension `subjectAltName`       | B    | Already wired (`HostSignalTLSSAN`). Browser-trust baseline per RFC 6125.                             |
| **TLS Cert Subject CN**             | TCP TLS-any   | Subject.CommonName                    | B    | Already wired (`HostSignalTLSCN`). Pre-RFC-6125 legacy.                                              |
| **TLS Cert SubjectAltName IPAddr**  | TCP TLS-any   | x509 extension `subjectAltName` (IP)  | —    | Confirms IP↔cert binding but adds no *name*.                                                         |
| **TLS Cert Issuer CN**              | TCP TLS-any   | Issuer.CommonName                     | E    | The CA's name, not the host's. Useful for fingerprinting fleets.                                     |
| **TLS Cert SAN URI / emailAddress** | TCP TLS-any   | x509 SAN type URI / rfc822Name        | D    | Sometimes carries `https://hostname/...` or `admin@hostname`. Parse defensively.                     |
| **SSH host key fingerprint**        | TCP 22        | SHA256 of public host key             | B    | Stable identity that survives DNS changes. Pair with operator's `known_hosts` for verification.      |
| **SSH host certificate**            | TCP 22        | `principals` field of host cert       | B    | OpenSSH 5.4+ CA-signed host certs name the host(s) they're valid for. Best signal where deployed.    |

### Layer 7 — application banners

| Source                              | Port/proto    | Field                                 | Tier | Notes                                                                                                |
| ----------------------------------- | ------------- | ------------------------------------- | ---- | ---------------------------------------------------------------------------------------------------- |
| **SSH server banner**               | TCP 22        | `SSH-2.0-OpenSSH_X.Y` + comment       | C-ish | Many distros suffix the hostname in the comment ("Ubuntu-3ubuntu0.7 hostname"). Operator-toggleable. |
| **SMTP HELO / EHLO response**       | TCP 25/465/587 | `220 mail.example.com ESMTP ...`      | C    | Server states the name it thinks it is. Hardened deployments mask this; most don't.                  |
| **FTP 220 banner**                  | TCP 21        | `220 ftp.example.com FTP server ready` | C    | Same shape as SMTP.                                                                                  |
| **POP3 / IMAP greeting**            | TCP 110/995 / 143/993 | `+OK Dovecot ready` or `* OK mail.example.com IMAP4rev1` | C | Some servers include hostname; others don't.                                              |
| **IRC RPL_WELCOME**                 | TCP 6667/6697 | 001 numeric: server-name              | C    | First message after registration.                                                                    |
| **Telnet banner**                   | TCP 23        | freeform text                         | D    | If telnet is open, hostname leak is the least of your worries.                                       |
| **SMB / CIFS**                      | TCP 445       | NEGOTIATE_RESPONSE → ServerName (Netbios) + DnsHostName + DnsDomainName | C | Windows reveals both NetBIOS name *and* FQDN. SMB2+ specifies these explicitly. |
| **RDP X.224 connection request**    | TCP 3389      | Cookie field, MCS connect-initial → ClientName | E | Client supplies name; server-side leaks via `X.509 certificate` (server cert binds to hostname). |
| **VNC RFB version handshake**       | TCP 5900–5999 | `RFB 003.008` + ServerInit DesktopName | D    | DesktopName often = `<username>@<hostname>`.                                                         |
| **HTTP Server header**              | TCP 80/443    | `Server: nginx/1.27 (hostname.example)` | E  | Rarely contains the hostname directly. Useful for product fingerprinting.                            |
| **HTTP X-* custom headers**         | TCP 80/443    | `X-Backend-Server`, `X-Served-By`, `X-Origin-Server` | E | LB-injected. Frequent on Fastly/Varnish/HAProxy.                                                |
| **HTTP redirect Location**          | TCP 80/443    | `Location: https://canonical.example.com/...` | C | Server tells you its canonical name. Already trustable as a probe target.                       |
| **HTTP /server-info, /server-status** | TCP 80/443  | Apache mod_status content             | C    | When enabled. Page contains `ServerName`.                                                            |
| **HTTP WebDAV PROPFIND**            | TCP 80/443    | `D:href` resolves to server-relative URL with optional FQDN | D | Niche.                                                                                |

### Layer 7 — management / monitoring

| Source                              | Port/proto    | Field                                 | Tier | Notes                                                                                                |
| ----------------------------------- | ------------- | ------------------------------------- | ---- | ---------------------------------------------------------------------------------------------------- |
| **SNMP sysName.0**                  | UDP 161       | OID 1.3.6.1.2.1.1.5.0                 | C    | `RFC1213-MIB::sysName.0`. Standard on every SNMP-enabled device. Community string `public` often works in lab. |
| **SNMP sysLocation.0**              | UDP 161       | OID 1.3.6.1.2.1.1.6.0                 | E    | Building/rack hint, not a hostname.                                                                  |
| **IPMI Get Device ID**              | UDP 623       | Manufacturer + product strings        | D    | BMC fingerprint. Hostname often *not* in IPMI; pair with sysName via separate management VLAN.       |
| **Redfish `/redfish/v1/Systems/<id>`** | TCP 443    | `HostName`                            | B-ish | Server-asserted via authenticated REST. Replaces IPMI on modern BMCs.                                |
| **WS-Management (WinRM)**           | TCP 5985/5986 | EnumerateInstances → `CSName`         | C    | Windows host inventory protocol.                                                                     |
| **WMI over DCOM**                   | TCP 135 + dynamic | `Win32_ComputerSystem.Name`        | C    | Same data, older API.                                                                                |
| **Docker daemon /info**             | TCP 2375/2376 | `Name` field                          | C    | When exposed without TLS, returns full daemon facts including hostname.                              |
| **Kubernetes API /api/v1/nodes**    | TCP 6443      | `metadata.name`                       | B    | Authenticated, cluster-internal name.                                                                |
| **etcd /v2/stats/self**             | TCP 2379/2380 | `name`                                | C    | Member identifier in cluster.                                                                        |
| **Consul /v1/agent/self**           | TCP 8500      | `Member.Name`                         | C    | Cluster member name.                                                                                 |

### Layer 7 — databases

| Source                              | Port/proto    | Field                                 | Tier | Notes                                                                                                |
| ----------------------------------- | ------------- | ------------------------------------- | ---- | ---------------------------------------------------------------------------------------------------- |
| **PostgreSQL startup**              | TCP 5432      | `application_name` echoed back; `pg_settings.cluster_name` requires auth | D | Banner-grade signal pre-auth: server version only.                                              |
| **MySQL handshake**                 | TCP 3306      | Server greeting carries server version; hostname *not* included pre-auth | E | Post-auth: `SHOW VARIABLES LIKE 'hostname'`.                                                  |
| **MongoDB `hello`**                 | TCP 27017     | `hosts` array in replSet response     | B    | Replicaset config lists every member by hostname. Often unauthenticated.                             |
| **Redis INFO server**               | TCP 6379      | `redis_version` + (config-dependent) `executable` path | E | Hostname usually absent. Sometimes in `info replication` for replicas.                          |
| **Elasticsearch `/`**               | TCP 9200      | `name` field                          | B    | Node name = hostname by default.                                                                     |
| **Cassandra CQL handshake**         | TCP 9042      | `STARTUP` response → cluster name     | D    | Cluster, not host.                                                                                   |

### Layer 7 — routing / time

| Source                              | Port/proto    | Field                                 | Tier | Notes                                                                                                |
| ----------------------------------- | ------------- | ------------------------------------- | ---- | ---------------------------------------------------------------------------------------------------- |
| **BGP OPEN**                        | TCP 179       | BGP Identifier (router-id)            | C    | Router ID is usually an IP; in pcap traces it pairs with the *neighbor name* if known via `iBGP-confed-id`. |
| **OSPF Hello**                      | IP proto 89   | Router ID                             | C    | Same as BGP.                                                                                         |
| **NTP server**                      | UDP 123       | refid (4 bytes, ASCII for stratum-1)  | E    | Refid is a clock-source code (`GPS`, `PPS`), not a hostname.                                         |
| **NTP control mode 6**              | UDP 123       | `sysstats` → `hostname` (varies)      | D    | Older ntpd exposed via mode 6. Many sites firewall it.                                               |

### Layer 7 — Bluetooth + wireless

| Source                              | Port/proto    | Field                                 | Tier | Notes                                                                                                |
| ----------------------------------- | ------------- | ------------------------------------- | ---- | ---------------------------------------------------------------------------------------------------- |
| **Bluetooth Classic — HCI Remote Name Request** | HCI / L2CAP | Friendly name (UTF-8, ≤248 bytes) | C    | Bonded device name. Requires HCI access (root on Linux, IOBluetoothFamily on macOS, Win32 BT API on Windows). |
| **Bluetooth SDP — `ServiceName`**   | L2CAP PSM 1   | Service attribute 0x0100              | D    | Per-service name; less stable than device name.                                                      |
| **BLE GAP — Device Name characteristic** | GATT 0x2A00 | Read on connection                   | C    | The advertised name. Often `<vendor> <model>`; consumer devices show user-set name.                  |
| **BLE Advertising — Complete Local Name (0x09)** | adv data | TLV 0x09 in advertisement      | C    | Broadcast unprompted; scanner sees this without pairing.                                             |
| **Wi-Fi probe-request SSID list**   | 802.11        | wildcard SSID requests                | E    | Client device leaks its remembered SSIDs; SSID ≠ hostname but yields fleet attribution.              |

### Layer 7 — IoT / industrial

| Source                              | Port/proto    | Field                                 | Tier | Notes                                                                                                |
| ----------------------------------- | ------------- | ------------------------------------- | ---- | ---------------------------------------------------------------------------------------------------- |
| **CoAP** (Constrained App Protocol) | UDP 5683      | `/.well-known/core` → `if=` attribute | E    | Mostly schemas, not names.                                                                           |
| **MQTT CONNECT**                    | TCP 1883/8883 | ClientID                              | E    | Client-supplied, but often the device's hostname.                                                    |
| **Modbus**                          | TCP 502       | (no name)                             | —    | Industrial; identity is the unit number, not a hostname.                                             |
| **OPC UA `GetEndpoints`**           | TCP 4840      | `endpointUrl`, `serverName`           | C    | Industrial OPC server self-id.                                                                       |

## Implementation priorities

If extending `HostSignal` to incorporate these:

1. **Wire SSH host key + banner** — high signal density on every Linux server; cheap probe.
2. **Wire SNMP sysName.0** — covers printers, switches, routers, IPMI.
3. **Wire mDNS + SSDP** — covers Apple, IoT, SmartTVs, NAS, printers (LAN).
4. **Wire NetBIOS NS / SMB negotiate** — covers all unjoined Windows hosts.
5. **Wire BLE GAP + Bluetooth SDP** — covers personal devices, peripherals.
6. **Wire LDAP rootDSE** — covers AD-joined fleets in a single query.

Each becomes a `HostSignal` constant slotted into the tier table at the
top of this document, with the existing five (Explicit / TLS-SAN /
TLS-CN / Reverse-DNS / IP) anchoring the high end and the low end.

## Forgery surface (what *not* to trust without correlation)

- **DHCP option 12, mDNS service names, NetBIOS, LLMNR, NTP refid** are
  trivially spoofable on the same broadcast domain. Use them as
  *additional* signals only; never as a unique identifier.
- **TLS SNI** is client-asserted; trustworthy only when you are the
  server logging incoming connections, not when probing.
- **HTTP `Server` / `X-*` headers** are operator-set strings. Treat as
  fingerprint hints, never as a hostname.
- **Bluetooth advertised name** is user-editable on every consumer OS.
  Pair with BD_ADDR (which is harder to forge) for stable identity.

## Cross-correlation strategy

For a given IP / MAC observed on the network, query multiple sources in
parallel, then collapse via the tier ranking. When two A-tier sources
disagree, surface the conflict to operators rather than silently
picking one — disagreement at the top tier almost always means
misconfiguration or active poisoning.

Persist *every* observed name alongside its `HostSignal` so audits can
later reconstruct *why* a host was identified the way it was. The
existing `intranetweb.Endpoint.Host` field captures the winning name;
a sibling `host_signal` column would capture the producing tier.
