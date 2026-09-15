package model

import (
	"encoding/json"
	"sort"
	"strings"
)

// Service categories — the closed, low-cardinality vocabulary used to say
// what kind of thing a machine offers. The platform filters on these
// ("every host with a directory service", "all databases reachable from the
// DMZ"), so new values must be added here and in the telemetry contract
// docs, not invented at the call site.
const (
	ServiceCategoryDirectory         = "directory"          // Active Directory, LDAP, Kerberos, FreeIPA
	ServiceCategoryDatabase          = "database"           // relational + document + column stores
	ServiceCategoryCache             = "cache"              // Redis, Memcached, Valkey
	ServiceCategorySearch            = "search"             // Elasticsearch, OpenSearch, Solr
	ServiceCategoryMessageQueue      = "message_queue"      // RabbitMQ, Kafka, MQTT, NATS
	ServiceCategoryWeb               = "web"                // HTTP servers, reverse proxies
	ServiceCategoryRemoteAccess      = "remote_access"      // SSH, RDP, VNC, Telnet, WinRM
	ServiceCategoryFileSharing       = "file_sharing"       // SMB, FTP, NFS
	ServiceCategoryObjectStorage     = "object_storage"     // MinIO, Ceph RGW
	ServiceCategoryMail              = "mail"               // SMTP, IMAP, POP3
	ServiceCategoryDNS               = "dns"                // BIND, CoreDNS, Pi-hole
	ServiceCategoryMonitoring        = "monitoring"         // Prometheus, Grafana, Zabbix
	ServiceCategoryIdentity          = "identity"           // Keycloak, Authentik (SSO/IdP, not a directory)
	ServiceCategorySecrets           = "secrets"            // Vault
	ServiceCategoryContainerPlatform = "container_platform" // Docker, Kubernetes, registries
	ServiceCategoryCI                = "ci"                 // Jenkins, GitLab, Gitea
	ServiceCategoryOther             = "other"
)

// Tag keys through which structured facts travel inside Machine.Tags. Tags
// are the one channel that every source writes, the deduper merges by key,
// the store persists, and MaterialFingerprint covers — so anything placed
// here survives a re-scan of an existing machine and flips the lifecycle
// event to MachineUpdated when it changes.
const (
	// TagServices holds a JSON array of MachineService.
	TagServices = "services"
	// TagContainerID holds the full (64-hex) container id; the legacy
	// "container_id" tag keeps the 12-char short form for display.
	TagContainerID = "container_id_full"
	// TagImageID is the engine-local image id ("sha256:<hex>") — the digest
	// of the image config, which changes whenever the image is rebuilt.
	TagImageID = "image_id"
	// TagImageDigest is the registry content digest ("sha256:<hex>") of the
	// image manifest as pulled — the key a vulnerability database matches
	// on. Empty for locally built, never-pushed images.
	TagImageDigest = "image_digest"
	// TagImageRepoDigests lists every repo@digest reference the engine knows
	// for the image (JSON array of strings).
	TagImageRepoDigests = "image_repo_digests"
)

// maxServicesPerMachine bounds the services list on the wire: a host with
// hundreds of listeners still produces a sane attribute.
const maxServicesPerMachine = 64

// MachineService is one service a machine offers: a directory, a database,
// a queue, a web server. Name is the canonical product/protocol id
// ("postgresql", "active_directory"), Category one of the ServiceCategory*
// constants. Port/Protocol/Version/Exposure are filled when the observing
// source knows them and left empty otherwise. Source names how it was
// learned: "image" (container image reference), "port" (well-known port
// number), "banner" (protocol handshake), "listener" (local LISTEN socket),
// "directory" (LDAP computer object role).
type MachineService struct {
	Name     string `json:"name"`
	Category string `json:"category"`
	Version  string `json:"version,omitempty"`
	Protocol string `json:"protocol,omitempty"`
	Exposure string `json:"exposure,omitempty"`
	Source   string `json:"source,omitempty"`
	Port     int    `json:"port,omitempty"`
}

// serviceDef is one row of the protocol/product → (name, category) table.
type serviceDef struct {
	name     string
	category string
}

// protocolServices maps fingerprintx protocol ids (and a few common aliases
// seen in banners, osquery and listener process names) onto the service
// vocabulary. Keys are lower-case.
var protocolServices = map[string]serviceDef{
	// directory
	"ldap":             {"ldap", ServiceCategoryDirectory},
	"ldaps":            {"ldap", ServiceCategoryDirectory},
	"kerberos":         {"kerberos", ServiceCategoryDirectory},
	"active_directory": {"active_directory", ServiceCategoryDirectory},
	"freeipa":          {"freeipa", ServiceCategoryDirectory},
	// databases
	"mysql":       {"mysql", ServiceCategoryDatabase},
	"mariadb":     {"mariadb", ServiceCategoryDatabase},
	"postgresql":  {"postgresql", ServiceCategoryDatabase},
	"postgres":    {"postgresql", ServiceCategoryDatabase},
	"mssql":       {"mssql", ServiceCategoryDatabase},
	"oracle":      {"oracle", ServiceCategoryDatabase},
	"oracledb":    {"oracle", ServiceCategoryDatabase},
	"mongodb":     {"mongodb", ServiceCategoryDatabase},
	"cassandra":   {"cassandra", ServiceCategoryDatabase},
	"clickhouse":  {"clickhouse", ServiceCategoryDatabase},
	"couchdb":     {"couchdb", ServiceCategoryDatabase},
	"cockroachdb": {"cockroachdb", ServiceCategoryDatabase},
	"neo4j":       {"neo4j", ServiceCategoryDatabase},
	"influxdb":    {"influxdb", ServiceCategoryDatabase},
	"db2":         {"db2", ServiceCategoryDatabase},
	// cache
	"redis":     {"redis", ServiceCategoryCache},
	"valkey":    {"valkey", ServiceCategoryCache},
	"memcached": {"memcached", ServiceCategoryCache},
	// search
	"elasticsearch": {"elasticsearch", ServiceCategorySearch},
	"opensearch":    {"opensearch", ServiceCategorySearch},
	"solr":          {"solr", ServiceCategorySearch},
	// queues
	"rabbitmq":  {"rabbitmq", ServiceCategoryMessageQueue},
	"amqp":      {"rabbitmq", ServiceCategoryMessageQueue},
	"kafka":     {"kafka", ServiceCategoryMessageQueue},
	"mqtt":      {"mqtt", ServiceCategoryMessageQueue},
	"nats":      {"nats", ServiceCategoryMessageQueue},
	"activemq":  {"activemq", ServiceCategoryMessageQueue},
	"zookeeper": {"zookeeper", ServiceCategoryMessageQueue},
	// web
	"http":  {"http", ServiceCategoryWeb},
	"https": {"https", ServiceCategoryWeb},
	// remote access
	"ssh":    {"ssh", ServiceCategoryRemoteAccess},
	"rdp":    {"rdp", ServiceCategoryRemoteAccess},
	"vnc":    {"vnc", ServiceCategoryRemoteAccess},
	"telnet": {"telnet", ServiceCategoryRemoteAccess},
	"winrm":  {"winrm", ServiceCategoryRemoteAccess},
	// file sharing
	"smb":  {"smb", ServiceCategoryFileSharing},
	"ftp":  {"ftp", ServiceCategoryFileSharing},
	"sftp": {"sftp", ServiceCategoryFileSharing},
	"nfs":  {"nfs", ServiceCategoryFileSharing},
	// mail
	"smtp":  {"smtp", ServiceCategoryMail},
	"smtps": {"smtp", ServiceCategoryMail},
	"imap":  {"imap", ServiceCategoryMail},
	"imaps": {"imap", ServiceCategoryMail},
	"pop3":  {"pop3", ServiceCategoryMail},
	"pop3s": {"pop3", ServiceCategoryMail},
	// dns
	"dns": {"dns", ServiceCategoryDNS},
	// container platforms
	"docker":     {"docker", ServiceCategoryContainerPlatform},
	"kubernetes": {"kubernetes", ServiceCategoryContainerPlatform},
}

// portServices maps well-known TCP ports onto services for the cases where
// only the port number is known (unfingerprinted listener, container
// exposed port). Ambiguous ports (3000, 8000, 9000, …) are deliberately
// absent: a wrong "database" label is worse than none.
var portServices = map[int]serviceDef{
	21:    {"ftp", ServiceCategoryFileSharing},
	22:    {"ssh", ServiceCategoryRemoteAccess},
	23:    {"telnet", ServiceCategoryRemoteAccess},
	25:    {"smtp", ServiceCategoryMail},
	53:    {"dns", ServiceCategoryDNS},
	80:    {"http", ServiceCategoryWeb},
	88:    {"kerberos", ServiceCategoryDirectory},
	110:   {"pop3", ServiceCategoryMail},
	143:   {"imap", ServiceCategoryMail},
	389:   {"ldap", ServiceCategoryDirectory},
	443:   {"https", ServiceCategoryWeb},
	445:   {"smb", ServiceCategoryFileSharing},
	464:   {"kerberos", ServiceCategoryDirectory},
	465:   {"smtp", ServiceCategoryMail},
	587:   {"smtp", ServiceCategoryMail},
	636:   {"ldap", ServiceCategoryDirectory},
	993:   {"imap", ServiceCategoryMail},
	995:   {"pop3", ServiceCategoryMail},
	1433:  {"mssql", ServiceCategoryDatabase},
	1521:  {"oracle", ServiceCategoryDatabase},
	1883:  {"mqtt", ServiceCategoryMessageQueue},
	2049:  {"nfs", ServiceCategoryFileSharing},
	2181:  {"zookeeper", ServiceCategoryMessageQueue},
	2375:  {"docker", ServiceCategoryContainerPlatform},
	2376:  {"docker", ServiceCategoryContainerPlatform},
	3268:  {"active_directory", ServiceCategoryDirectory}, // global catalog
	3269:  {"active_directory", ServiceCategoryDirectory},
	3306:  {"mysql", ServiceCategoryDatabase},
	3389:  {"rdp", ServiceCategoryRemoteAccess},
	4222:  {"nats", ServiceCategoryMessageQueue},
	5432:  {"postgresql", ServiceCategoryDatabase},
	5672:  {"rabbitmq", ServiceCategoryMessageQueue},
	5900:  {"vnc", ServiceCategoryRemoteAccess},
	5985:  {"winrm", ServiceCategoryRemoteAccess},
	5986:  {"winrm", ServiceCategoryRemoteAccess},
	6379:  {"redis", ServiceCategoryCache},
	6443:  {"kubernetes", ServiceCategoryContainerPlatform},
	7474:  {"neo4j", ServiceCategoryDatabase},
	7687:  {"neo4j", ServiceCategoryDatabase},
	8080:  {"http", ServiceCategoryWeb},
	8086:  {"influxdb", ServiceCategoryDatabase},
	8123:  {"clickhouse", ServiceCategoryDatabase},
	8200:  {"vault", ServiceCategorySecrets},
	8443:  {"https", ServiceCategoryWeb},
	8883:  {"mqtt", ServiceCategoryMessageQueue},
	9042:  {"cassandra", ServiceCategoryDatabase},
	9090:  {"prometheus", ServiceCategoryMonitoring},
	9092:  {"kafka", ServiceCategoryMessageQueue},
	9200:  {"elasticsearch", ServiceCategorySearch},
	11211: {"memcached", ServiceCategoryCache},
	15672: {"rabbitmq", ServiceCategoryMessageQueue},
	26257: {"cockroachdb", ServiceCategoryDatabase},
	27017: {"mongodb", ServiceCategoryDatabase},
}

// imageRule matches a container image repository (registry and tag
// stripped, lower-case) by substring. Rules are ordered: the first hit
// wins, so more specific needles ("pgadmin", "mysql-exporter") precede the
// products they would otherwise shadow ("postgres", "mysql").
type imageRule struct {
	needle   string
	name     string
	category string
}

var imageRules = []imageRule{
	// admin / exporter tooling first so it does not masquerade as the store
	{"pgadmin", "pgadmin", ServiceCategoryOther},
	{"phpmyadmin", "phpmyadmin", ServiceCategoryOther},
	{"adminer", "adminer", ServiceCategoryOther},
	{"exporter", "exporter", ServiceCategoryMonitoring},
	// directory
	{"samba-ad", "active_directory", ServiceCategoryDirectory},
	{"samba-dc", "active_directory", ServiceCategoryDirectory},
	{"samba-domain", "active_directory", ServiceCategoryDirectory},
	{"sambadc", "active_directory", ServiceCategoryDirectory},
	{"freeipa", "freeipa", ServiceCategoryDirectory},
	{"openldap", "ldap", ServiceCategoryDirectory},
	{"389ds", "ldap", ServiceCategoryDirectory},
	{"389-ds", "ldap", ServiceCategoryDirectory},
	{"glauth", "ldap", ServiceCategoryDirectory},
	{"lldap", "ldap", ServiceCategoryDirectory},
	{"kerberos", "kerberos", ServiceCategoryDirectory},
	// databases
	{"timescale", "postgresql", ServiceCategoryDatabase},
	{"pgvector", "postgresql", ServiceCategoryDatabase},
	{"postgis", "postgresql", ServiceCategoryDatabase},
	{"postgres", "postgresql", ServiceCategoryDatabase},
	{"mariadb", "mariadb", ServiceCategoryDatabase},
	{"percona", "mysql", ServiceCategoryDatabase},
	{"mysql", "mysql", ServiceCategoryDatabase},
	{"mssql", "mssql", ServiceCategoryDatabase},
	{"sql-server", "mssql", ServiceCategoryDatabase},
	{"oracle/database", "oracle", ServiceCategoryDatabase},
	{"oracle-xe", "oracle", ServiceCategoryDatabase},
	{"oracle-free", "oracle", ServiceCategoryDatabase},
	{"mongo", "mongodb", ServiceCategoryDatabase},
	{"cassandra", "cassandra", ServiceCategoryDatabase},
	{"scylla", "cassandra", ServiceCategoryDatabase},
	{"clickhouse", "clickhouse", ServiceCategoryDatabase},
	{"couchdb", "couchdb", ServiceCategoryDatabase},
	{"cockroach", "cockroachdb", ServiceCategoryDatabase},
	{"neo4j", "neo4j", ServiceCategoryDatabase},
	{"influxdb", "influxdb", ServiceCategoryDatabase},
	{"db2", "db2", ServiceCategoryDatabase},
	{"surrealdb", "surrealdb", ServiceCategoryDatabase},
	{"questdb", "questdb", ServiceCategoryDatabase},
	// cache
	{"redis", "redis", ServiceCategoryCache},
	{"valkey", "valkey", ServiceCategoryCache},
	{"keydb", "redis", ServiceCategoryCache},
	{"memcached", "memcached", ServiceCategoryCache},
	// search
	{"elasticsearch", "elasticsearch", ServiceCategorySearch},
	{"opensearch", "opensearch", ServiceCategorySearch},
	{"solr", "solr", ServiceCategorySearch},
	{"meilisearch", "meilisearch", ServiceCategorySearch},
	// queues
	{"rabbitmq", "rabbitmq", ServiceCategoryMessageQueue},
	{"kafka", "kafka", ServiceCategoryMessageQueue},
	{"redpanda", "kafka", ServiceCategoryMessageQueue},
	{"mosquitto", "mqtt", ServiceCategoryMessageQueue},
	{"emqx", "mqtt", ServiceCategoryMessageQueue},
	{"nats", "nats", ServiceCategoryMessageQueue},
	{"activemq", "activemq", ServiceCategoryMessageQueue},
	{"zookeeper", "zookeeper", ServiceCategoryMessageQueue},
	// identity / secrets
	{"keycloak", "keycloak", ServiceCategoryIdentity},
	{"authentik", "authentik", ServiceCategoryIdentity},
	{"authelia", "authelia", ServiceCategoryIdentity},
	{"vault", "vault", ServiceCategorySecrets},
	// monitoring
	{"prometheus", "prometheus", ServiceCategoryMonitoring},
	{"grafana", "grafana", ServiceCategoryMonitoring},
	{"zabbix", "zabbix", ServiceCategoryMonitoring},
	{"opentelemetry-collector", "otel_collector", ServiceCategoryMonitoring},
	{"kibana", "kibana", ServiceCategoryMonitoring},
	{"loki", "loki", ServiceCategoryMonitoring},
	// object storage
	{"minio", "minio", ServiceCategoryObjectStorage},
	{"ceph", "ceph", ServiceCategoryObjectStorage},
	// file sharing
	{"samba", "smb", ServiceCategoryFileSharing},
	{"vsftpd", "ftp", ServiceCategoryFileSharing},
	{"proftpd", "ftp", ServiceCategoryFileSharing},
	{"sftp", "sftp", ServiceCategoryFileSharing},
	{"nfs-server", "nfs", ServiceCategoryFileSharing},
	// mail
	{"postfix", "smtp", ServiceCategoryMail},
	{"mailhog", "smtp", ServiceCategoryMail},
	{"mailpit", "smtp", ServiceCategoryMail},
	{"dovecot", "imap", ServiceCategoryMail},
	// dns
	{"coredns", "dns", ServiceCategoryDNS},
	{"pihole", "dns", ServiceCategoryDNS},
	{"pi-hole", "dns", ServiceCategoryDNS},
	{"bind9", "dns", ServiceCategoryDNS},
	{"unbound", "dns", ServiceCategoryDNS},
	{"adguard", "dns", ServiceCategoryDNS},
	// ci / scm
	{"jenkins", "jenkins", ServiceCategoryCI},
	{"gitlab", "gitlab", ServiceCategoryCI},
	{"gitea", "gitea", ServiceCategoryCI},
	{"forgejo", "gitea", ServiceCategoryCI},
	{"drone", "drone", ServiceCategoryCI},
	// container platform
	{"portainer", "portainer", ServiceCategoryContainerPlatform},
	{"registry", "registry", ServiceCategoryContainerPlatform},
	{"harbor", "harbor", ServiceCategoryContainerPlatform},
	{"docker:dind", "docker", ServiceCategoryContainerPlatform},
	{"rancher", "kubernetes", ServiceCategoryContainerPlatform},
	// web servers / proxies (last: many app images embed "nginx" in the name)
	{"nginx", "nginx", ServiceCategoryWeb},
	{"httpd", "apache_httpd", ServiceCategoryWeb},
	{"apache2", "apache_httpd", ServiceCategoryWeb},
	{"caddy", "caddy", ServiceCategoryWeb},
	{"traefik", "traefik", ServiceCategoryWeb},
	{"haproxy", "haproxy", ServiceCategoryWeb},
	{"envoy", "envoy", ServiceCategoryWeb},
	{"tomcat", "tomcat", ServiceCategoryWeb},
}

// ServiceFromProtocol classifies a fingerprintx protocol id / banner product
// name. Unknown protocols still yield a service (name = the lower-cased
// input, category "other") so an observed-but-unclassified port is not
// silently dropped from the inventory.
func ServiceFromProtocol(protocol string) (MachineService, bool) {
	p := strings.ToLower(strings.TrimSpace(protocol))
	if p == "" {
		return MachineService{}, false
	}
	if def, ok := protocolServices[p]; ok {
		return MachineService{Name: def.name, Category: def.category}, true
	}
	return MachineService{Name: p, Category: ServiceCategoryOther}, true
}

// ServiceFromPort classifies a well-known TCP port. Unknown ports return
// false: a bare port number is not evidence of anything.
func ServiceFromPort(port int) (MachineService, bool) {
	def, ok := portServices[port]
	if !ok {
		return MachineService{}, false
	}
	return MachineService{Name: def.name, Category: def.category, Port: port, Protocol: "tcp"}, true
}

// ServiceFromImage classifies a container image reference such as
// "postgres:16", "docker.io/bitnami/postgresql:16.3", or
// "mcr.microsoft.com/mssql/server:2022-latest@sha256:…". The version is
// taken from the tag when it looks like one (starts with a digit).
func ServiceFromImage(ref string) (MachineService, bool) {
	repo, tag := SplitImageRef(ref)
	if repo == "" {
		return MachineService{}, false
	}
	needle := strings.ToLower(repo)
	for _, r := range imageRules {
		if strings.Contains(needle, r.needle) {
			svc := MachineService{Name: r.name, Category: r.category, Source: "image"}
			if isVersionTag(tag) {
				svc.Version = tag
			}
			return svc, true
		}
	}
	return MachineService{}, false
}

// SplitImageRef separates an image reference into its repository path
// (registry + namespace + name) and tag. A trailing @digest is dropped; a
// missing tag yields "". The registry's ":port" is not mistaken for a tag.
func SplitImageRef(ref string) (repo, tag string) {
	ref = strings.TrimSpace(ref)
	if at := strings.Index(ref, "@"); at >= 0 {
		ref = ref[:at]
	}
	if ref == "" {
		return "", ""
	}
	lastColon := strings.LastIndex(ref, ":")
	if lastColon < 0 {
		return ref, ""
	}
	if strings.Contains(ref[lastColon:], "/") {
		// The colon belongs to a registry host:port, not a tag.
		return ref, ""
	}
	return ref[:lastColon], ref[lastColon+1:]
}

// isVersionTag reports whether an image tag reads as a version ("16",
// "7.2-alpine", "2022-CU12") rather than a channel ("latest", "stable").
func isVersionTag(tag string) bool {
	if tag == "" {
		return false
	}
	c := tag[0]
	if c >= '0' && c <= '9' {
		return true
	}
	return (c == 'v' || c == 'V') && len(tag) > 1 && tag[1] >= '0' && tag[1] <= '9'
}

// MergeServices unions service lists, dropping exact (name, port)
// duplicates and, for the same name, preferring the entry that carries a
// version. The result is sorted by category, name, port so the encoded
// tag — and therefore MaterialFingerprint — is deterministic across scans.
func MergeServices(lists ...[]MachineService) []MachineService {
	type key struct {
		name string
		port int
	}
	byKey := make(map[key]MachineService)
	for _, list := range lists {
		for _, svc := range list {
			if svc.Name == "" {
				continue
			}
			if svc.Category == "" {
				svc.Category = ServiceCategoryOther
			}
			k := key{svc.Name, svc.Port}
			if prev, ok := byKey[k]; ok {
				byKey[k] = preferRicher(prev, svc)
				continue
			}
			byKey[k] = svc
		}
	}
	// A port-less entry ("postgresql" from the image) is redundant once a
	// ported entry of the same name exists ("postgresql" on 5432): fold its
	// version and source into every ported row of that name and drop it.
	hasPorted := make(map[string]bool, len(byKey))
	for k := range byKey {
		if k.port != 0 {
			hasPorted[k.name] = true
		}
	}
	for k, bare := range byKey {
		if k.port != 0 || !hasPorted[k.name] {
			continue
		}
		for pk, ported := range byKey {
			if pk.port != 0 && pk.name == k.name {
				byKey[pk] = preferRicher(bare, ported)
			}
		}
		delete(byKey, k)
	}
	out := make([]MachineService, 0, len(byKey))
	for _, svc := range byKey {
		out = append(out, svc)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Category != out[j].Category {
			return out[i].Category < out[j].Category
		}
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		return out[i].Port < out[j].Port
	})
	if len(out) > maxServicesPerMachine {
		out = out[:maxServicesPerMachine]
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// preferRicher merges two observations of the same service, keeping every
// non-empty field and letting the newer (b) win on conflicts.
func preferRicher(a, b MachineService) MachineService {
	out := b
	if out.Version == "" {
		out.Version = a.Version
	}
	if out.Protocol == "" {
		out.Protocol = a.Protocol
	}
	if out.Exposure == "" {
		out.Exposure = a.Exposure
	}
	if out.Port == 0 {
		out.Port = a.Port
	}
	if out.Source == "" {
		out.Source = a.Source
	} else if a.Source != "" && a.Source != out.Source && !strings.Contains(out.Source, a.Source) {
		out.Source = a.Source + "+" + out.Source
	}
	return out
}

// ServiceCategories returns the sorted, de-duplicated categories present in
// a service list — the low-cardinality summary a backend filters on.
func ServiceCategories(services []MachineService) []string {
	seen := make(map[string]struct{}, len(services))
	for _, s := range services {
		if s.Category == "" {
			continue
		}
		seen[s.Category] = struct{}{}
	}
	out := make([]string, 0, len(seen))
	for c := range seen {
		out = append(out, c)
	}
	sort.Strings(out)
	return out
}

// EncodeServices renders a service list as compact JSON for a tag value or
// a wire attribute. Nil/empty yields "".
func EncodeServices(services []MachineService) string {
	if len(services) == 0 {
		return ""
	}
	b, err := json.Marshal(services)
	if err != nil {
		return ""
	}
	return string(b)
}

// ParseTagObject decodes a Machine.Tags string into a generic object. It
// accepts both the plain JSON-object form every discovery source writes
// and the canonical [[k,v],…] pair form of MarshalTags. Empty, "null" or
// unparseable input yields nil, never an error — tags are best-effort.
func ParseTagObject(tags string) map[string]any {
	tags = strings.TrimSpace(tags)
	if tags == "" || tags == "null" {
		return nil
	}
	var obj map[string]any
	if err := json.Unmarshal([]byte(tags), &obj); err == nil {
		return obj
	}
	pairs, err := UnmarshalTags(tags)
	if err != nil || len(pairs) == 0 {
		return nil
	}
	obj = make(map[string]any, len(pairs))
	for k, v := range pairs {
		obj[k] = v
	}
	return obj
}

// ServicesFromTags extracts the structured service list carried under
// TagServices. It tolerates the two encodings a tag value can arrive in —
// a native JSON array (from a Go source) or a JSON string containing the
// array (from a store or a pair-form tag) — and returns nil when absent.
func ServicesFromTags(tags string) []MachineService {
	obj := ParseTagObject(tags)
	if obj == nil {
		return nil
	}
	raw, ok := obj[TagServices]
	if !ok || raw == nil {
		return nil
	}
	var encoded []byte
	switch v := raw.(type) {
	case string:
		encoded = []byte(v)
	default:
		b, err := json.Marshal(v)
		if err != nil {
			return nil
		}
		encoded = b
	}
	var out []MachineService
	if err := json.Unmarshal(encoded, &out); err != nil {
		return nil
	}
	return MergeServices(out)
}

// WithServicesInTags stores services under TagServices in the machine's
// tags JSON (object form), creating the object when tags is empty and
// removing the key when the list is empty. The input is returned untouched
// on an encode failure.
func WithServicesInTags(tags string, services []MachineService) string {
	obj := ParseTagObject(tags)
	if obj == nil {
		obj = map[string]any{}
	}
	merged := MergeServices(services)
	if len(merged) == 0 {
		delete(obj, TagServices)
	} else {
		obj[TagServices] = merged
	}
	if len(obj) == 0 {
		return ""
	}
	b, err := json.Marshal(obj)
	if err != nil {
		return tags
	}
	return string(b)
}

// TagString returns a string-valued tag, or "" when the key is absent or
// not a string.
func TagString(obj map[string]any, key string) string {
	if obj == nil {
		return ""
	}
	s, _ := obj[key].(string)
	return s
}

// ServicesFromListeners derives a machine's services from its observed
// LISTEN sockets: a fingerprinted listener classifies by protocol (with the
// banner version); an unfingerprinted one falls back to the well-known port
// table. Listeners the tables cannot name are omitted.
func ServicesFromListeners(listeners []HostListener) []MachineService {
	out := make([]MachineService, 0, len(listeners))
	for _, l := range listeners {
		port := int(l.Port)
		var svc MachineService
		var ok bool
		if l.Service != "" {
			svc, ok = ServiceFromProtocol(l.Service)
			if ok {
				svc.Version = l.ServiceVersion
			}
		} else {
			svc, ok = ServiceFromPort(port)
		}
		if !ok {
			continue
		}
		svc.Port = port
		svc.Protocol = normalizeProtocol(l.Protocol)
		svc.Exposure = l.Exposure
		svc.Source = "listener"
		out = append(out, svc)
	}
	return MergeServices(out)
}

// normalizeProtocol folds tcp6/udp6 onto tcp/udp for the service record.
func normalizeProtocol(p string) string {
	switch strings.ToLower(p) {
	case "tcp", "tcp6":
		return "tcp"
	case "udp", "udp6":
		return "udp"
	default:
		return strings.ToLower(p)
	}
}
