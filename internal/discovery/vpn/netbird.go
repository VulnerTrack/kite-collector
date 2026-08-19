package vpn

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/vulnertrack/kite-collector/internal/safenet"
)

// netbirdEnumerator discovers NetBird mesh hosts. Like Tailscale it has two
// paths: the management REST API (whole network, with the owning user's
// email) when KITE_NETBIRD_MGMT_URL + KITE_NETBIRD_TOKEN are set, otherwise
// the local `netbird status --json` (this node's peers).
type netbirdEnumerator struct {
	run        runner
	lookPath   lookPather
	getenv     func(string) string
	httpClient *http.Client
	tlsConfig  func() (*tls.Config, error)
	binary     string
	timeout    time.Duration
}

func newNetBirdEnumerator() *netbirdEnumerator {
	return &netbirdEnumerator{
		run:      defaultRunner,
		lookPath: defaultLookPath,
		getenv:   defaultGetenv,
		tlsConfig: func() (*tls.Config, error) {
			return safenet.TLSConfig("KITE_NETBIRD_INSECURE", "KITE_NETBIRD_CA_CERT")
		},
		binary:  "netbird",
		timeout: 30 * time.Second,
	}
}

func (e *netbirdEnumerator) vpnType() string { return "netbird" }

func (e *netbirdEnumerator) enumerate(ctx context.Context, _ map[string]any) ([]Peer, error) {
	mgmt := e.getenv("KITE_NETBIRD_MGMT_URL")
	token := e.getenv("KITE_NETBIRD_TOKEN")
	if mgmt != "" && token != "" {
		return e.enumerateAPI(ctx, mgmt, token)
	}
	return e.enumerateCLI(ctx)
}

// ---------------------------------------------------------------------------
// Local CLI path
// ---------------------------------------------------------------------------

func (e *netbirdEnumerator) enumerateCLI(ctx context.Context) ([]Peer, error) {
	bin, err := e.lookPath(e.binary)
	if err != nil {
		return nil, nil // netbird not installed
	}
	cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	raw, err := e.run(cctx, bin, "status", "--json")
	if err != nil || len(raw) == 0 {
		slog.Debug("vpn: netbird status failed",
			"code", string(LogCodeNetBirdCLIFailed), "error", err)
		return nil, nil
	}
	return peersFromNBStatus(raw)
}

type nbStatus struct {
	Peers nbPeers `json:"peers"`
}

type nbPeers struct {
	Details []nbPeerDetail `json:"details"`
}

type nbPeerDetail struct {
	FQDN             string `json:"fqdn"`
	NetbirdIP        string `json:"netbirdIp"`
	PublicKey        string `json:"publicKey"`
	Status           string `json:"status"`
	LastStatusUpdate string `json:"lastStatusUpdate"`
	ConnectionType   string `json:"connectionType"`
	OS               string `json:"os"`
	Version          string `json:"version"`
	Relayed          bool   `json:"relayed"`
}

// peersFromNBStatus projects `netbird status --json` onto Peers.
func peersFromNBStatus(raw []byte) ([]Peer, error) {
	var st nbStatus
	if err := json.Unmarshal(raw, &st); err != nil {
		return nil, fmt.Errorf("netbird: decode status json: %w", err)
	}
	out := make([]Peer, 0, len(st.Peers.Details))
	for _, d := range st.Peers.Details {
		osFamily, arch := splitNetbirdOS(d.OS)
		p := Peer{
			VPNType:   "netbird",
			Hostname:  firstLabel(d.FQDN),
			DNSName:   d.FQDN,
			OS:        osFamily,
			OSVersion: d.Version,
			PublicKey: d.PublicKey,
			Addresses: sortAddrs([]string{d.NetbirdIP}),
			Online:    strings.EqualFold(d.Status, "Connected"),
			LastSeen:  parseTSTime(d.LastStatusUpdate),
			Tags:      map[string]any{},
		}
		if d.ConnectionType != "" {
			p.Tags["connection_type"] = d.ConnectionType
		}
		if arch != "" {
			p.Tags["arch"] = arch
		}
		if d.Relayed {
			p.Tags["relayed"] = true
		}
		out = append(out, p)
	}
	return out, nil
}

// ---------------------------------------------------------------------------
// Management REST API path
// ---------------------------------------------------------------------------

func (e *netbirdEnumerator) enumerateAPI(ctx context.Context, mgmt, token string) ([]Peer, error) {
	base, err := safenet.ValidateEndpoint(mgmt, safenet.AllowPrivate(), safenet.AllowHTTP())
	if err != nil {
		return nil, fmt.Errorf("netbird: invalid management url: %w", err)
	}
	client := e.httpClient
	if client == nil {
		tlsCfg, terr := e.tlsConfig()
		if terr != nil {
			return nil, fmt.Errorf("netbird: %w", terr)
		}
		client = &http.Client{Timeout: e.timeout, Transport: &http.Transport{TLSClientConfig: tlsCfg}}
	}
	baseURL := strings.TrimRight(base.String(), "/")

	peersRaw, err := netbirdGet(ctx, client, baseURL+"/api/peers", token)
	if err != nil {
		return nil, fmt.Errorf("netbird: list peers: %w", err)
	}
	// User directory is best-effort enrichment; a token scoped to peers-only
	// still yields hosts, just without owner emails.
	owners := map[string]string{}
	if usersRaw, uerr := netbirdGet(ctx, client, baseURL+"/api/users", token); uerr == nil {
		owners = netbirdUserEmails(usersRaw)
	} else {
		slog.Debug("vpn: netbird users fetch failed (owner enrichment skipped)",
			"code", string(LogCodeNetBirdAPIFailed), "error", uerr)
	}
	return peersFromNBAPI(peersRaw, owners)
}

func netbirdGet(ctx context.Context, client *http.Client, url, token string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Token "+token)
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == http.StatusUnauthorized {
		return nil, fmt.Errorf("HTTP 401 — invalid NetBird API token")
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, truncate(string(body), 200))
	}
	return body, nil
}

type nbAPIPeer struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	IP        string `json:"ip"`
	DNSLabel  string `json:"dns_label"`
	UserID    string `json:"user_id"`
	Hostname  string `json:"hostname"`
	OS        string `json:"os"`
	Version   string `json:"version"`
	LastSeen  string `json:"last_seen"`
	Connected bool   `json:"connected"`
}

type nbAPIUser struct {
	ID    string `json:"id"`
	Email string `json:"email"`
	Name  string `json:"name"`
}

func netbirdUserEmails(raw []byte) map[string]string {
	var users []nbAPIUser
	if err := json.Unmarshal(raw, &users); err != nil {
		return map[string]string{}
	}
	out := make(map[string]string, len(users))
	for _, u := range users {
		if u.Email != "" {
			out[u.ID] = u.Email
		} else if u.Name != "" {
			out[u.ID] = u.Name
		}
	}
	return out
}

// peersFromNBAPI projects the /api/peers list onto Peers, resolving each
// peer's owner from the user directory when available.
func peersFromNBAPI(raw []byte, owners map[string]string) ([]Peer, error) {
	var peers []nbAPIPeer
	if err := json.Unmarshal(raw, &peers); err != nil {
		return nil, fmt.Errorf("netbird: decode peers json: %w", err)
	}
	out := make([]Peer, 0, len(peers))
	for _, d := range peers {
		osFamily, arch := splitNetbirdOS(d.OS)
		hostname := d.Hostname
		if hostname == "" {
			hostname = d.Name
		}
		p := Peer{
			VPNType:   "netbird",
			Hostname:  hostname,
			DNSName:   d.DNSLabel,
			OS:        osFamily,
			OSVersion: d.Version,
			Owner:     owners[d.UserID],
			Addresses: sortAddrs([]string{d.IP}),
			Online:    d.Connected,
			LastSeen:  parseTSTime(d.LastSeen),
			Tags:      map[string]any{"source": "netbird_api"},
		}
		if d.UserID != "" {
			p.Tags["user_id"] = d.UserID
		}
		if arch != "" {
			p.Tags["arch"] = arch
		}
		out = append(out, p)
	}
	return out, nil
}

// splitNetbirdOS splits NetBird's "linux/amd64" or "Darwin 14.5" style OS
// string into a family and (when present) an architecture.
func splitNetbirdOS(s string) (family, arch string) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", ""
	}
	if i := strings.IndexByte(s, '/'); i > 0 {
		return strings.TrimSpace(s[:i]), strings.TrimSpace(s[i+1:])
	}
	// "Darwin 14.5" → family "Darwin".
	if fields := strings.Fields(s); len(fields) > 0 {
		return fields[0], ""
	}
	return s, ""
}

// firstLabel returns the leftmost DNS label of an FQDN ("host.example.com"
// → "host"); a bare name is returned unchanged.
func firstLabel(fqdn string) string {
	fqdn = strings.TrimSuffix(strings.TrimSpace(fqdn), ".")
	if i := strings.IndexByte(fqdn, '.'); i > 0 {
		return fqdn[:i]
	}
	return fqdn
}
