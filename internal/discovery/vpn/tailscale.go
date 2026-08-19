package vpn

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// tailscaleEnumerator discovers tailnet hosts two ways, preferring the one
// that sees the most of the fleet:
//
//   - REST API (when KITE_TAILSCALE_API_KEY + KITE_TAILSCALE_TAILNET are
//     set): lists EVERY device in the tailnet, including ones this node has
//     never talked to. This is true fleet discovery.
//   - Local CLI (`tailscale status --json`, no root needed over the control
//     socket): lists the peers in this node's netmap plus the tailnet user
//     directory, so each host is attributed to its owning user.
//
// Only remote peers are emitted; Self is this collector's own host and is
// already covered by the agent source.
type tailscaleEnumerator struct {
	run        runner
	lookPath   lookPather
	getenv     func(string) string
	httpClient *http.Client
	binary     string
	apiBaseURL string
	timeout    time.Duration
}

func newTailscaleEnumerator() *tailscaleEnumerator {
	return &tailscaleEnumerator{
		run:        defaultRunner,
		lookPath:   defaultLookPath,
		getenv:     defaultGetenv,
		httpClient: &http.Client{Timeout: 30 * time.Second},
		binary:     "tailscale",
		apiBaseURL: "https://api.tailscale.com",
		timeout:    5 * time.Second,
	}
}

func (e *tailscaleEnumerator) vpnType() string { return "tailscale" }

func (e *tailscaleEnumerator) enumerate(ctx context.Context, cfg map[string]any) ([]Peer, error) {
	apiKey := e.getenv("KITE_TAILSCALE_API_KEY")
	tailnet := firstNonEmpty(e.getenv("KITE_TAILSCALE_TAILNET"), toStr(cfg["tailscale_tailnet"]))
	if apiKey != "" && tailnet != "" {
		return e.enumerateAPI(ctx, apiKey, tailnet)
	}
	return e.enumerateCLI(ctx)
}

// ---------------------------------------------------------------------------
// Local CLI path
// ---------------------------------------------------------------------------

func (e *tailscaleEnumerator) enumerateCLI(ctx context.Context) ([]Peer, error) {
	bin, err := e.lookPath(e.binary)
	if err != nil {
		return nil, nil // tailscale not installed — not an error
	}
	cctx, cancel := context.WithTimeout(ctx, e.timeout)
	defer cancel()

	raw, err := e.run(cctx, bin, "status", "--json")
	if err != nil || len(raw) == 0 {
		// Daemon down / logged out — no peers to report, but surface it so a
		// silent-zero is distinguishable from "tailscale absent".
		slog.Debug("vpn: tailscale CLI returned no data",
			"code", string(LogCodeTailscaleCLIFailed), "error", err)
		return nil, nil
	}
	return peersFromStatus(raw)
}

// tsStatus mirrors the subset of `tailscale status --json` we read. The
// upstream struct has many more fields; decoding a subset keeps an
// upstream addition from breaking the parser.
type tsStatus struct {
	Peer           map[string]tsPeer `json:"Peer"`
	User           map[string]tsUser `json:"User"`
	Self           tsPeer            `json:"Self"`
	CurrentTailnet *tsCurrentTailnet `json:"CurrentTailnet"`
}

type tsCurrentTailnet struct {
	Name           string `json:"Name"`
	MagicDNSSuffix string `json:"MagicDNSSuffix"`
}

type tsPeer struct {
	HostName     string   `json:"HostName"`
	DNSName      string   `json:"DNSName"`
	OS           string   `json:"OS"`
	Relay        string   `json:"Relay"`
	CurAddr      string   `json:"CurAddr"`
	PublicKey    string   `json:"PublicKey"`
	LastSeen     string   `json:"LastSeen"`
	TailscaleIPs []string `json:"TailscaleIPs"`
	Tags         []string `json:"Tags"`
	UserID       int64    `json:"UserID"`
	Online       bool     `json:"Online"`
	Expired      bool     `json:"Expired"`
	ExitNode     bool     `json:"ExitNode"`
	ExitNodeOpt  bool     `json:"ExitNodeOption"`
}

type tsUser struct {
	LoginName   string `json:"LoginName"`
	DisplayName string `json:"DisplayName"`
}

// peersFromStatus is the pure projection of the tailscaled JSON onto our
// Peer shape. Exercised directly by unit tests against fixtures.
func peersFromStatus(raw []byte) ([]Peer, error) {
	var st tsStatus
	if err := json.Unmarshal(raw, &st); err != nil {
		return nil, fmt.Errorf("tailscale: decode status json: %w", err)
	}

	tailnet := ""
	if st.CurrentTailnet != nil {
		tailnet = st.CurrentTailnet.Name
	}

	out := make([]Peer, 0, len(st.Peer))
	for _, tp := range st.Peer {
		p := Peer{
			VPNType:    "tailscale",
			Hostname:   tp.HostName,
			DNSName:    strings.TrimSuffix(tp.DNSName, "."),
			OS:         tp.OS,
			PublicKey:  tp.PublicKey,
			Addresses:  sortAddrs(tp.TailscaleIPs),
			Online:     tp.Online,
			Expired:    tp.Expired,
			IsExitNode: tp.ExitNode || tp.ExitNodeOpt,
			LastSeen:   parseTSTime(tp.LastSeen),
			Owner:      ownerFor(tp.UserID, st.User),
			Tags:       map[string]any{},
		}
		if tp.CurAddr != "" {
			p.Endpoint = tp.CurAddr
		} else if tp.Relay != "" {
			p.Endpoint = "derp:" + tp.Relay
		}
		if tailnet != "" {
			p.Tags["tailnet"] = tailnet
		}
		if len(tp.Tags) > 0 {
			p.Tags["acl_tags"] = tp.Tags
		}
		if dn := displayNameFor(tp.UserID, st.User); dn != "" {
			p.Tags["owner_display_name"] = dn
		}
		out = append(out, p)
	}
	return out, nil
}

// ownerFor resolves a peer's UserID against the tailnet user directory
// returned inline in the status JSON, yielding the login (email) of the
// user who owns the host. ACL-tagged nodes resolve to the synthetic
// "tagged-devices" login, which we surface unchanged — a tagged host has
// no human owner and that is itself worth recording.
func ownerFor(uid int64, users map[string]tsUser) string {
	if u, ok := users[strconv.FormatInt(uid, 10)]; ok {
		return u.LoginName
	}
	return ""
}

func displayNameFor(uid int64, users map[string]tsUser) string {
	if u, ok := users[strconv.FormatInt(uid, 10)]; ok {
		return u.DisplayName
	}
	return ""
}

// parseTSTime parses a tailscale RFC3339 timestamp, treating the Go zero
// time ("0001-01-01T00:00:00Z", emitted for never-seen peers) as unknown.
func parseTSTime(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil || t.Year() <= 1 {
		return time.Time{}
	}
	return t.UTC()
}

// ---------------------------------------------------------------------------
// REST API path (fleet-wide)
// ---------------------------------------------------------------------------

func (e *tailscaleEnumerator) enumerateAPI(ctx context.Context, apiKey, tailnet string) ([]Peer, error) {
	// The tailnet path segment is operator-supplied; reject anything that
	// could escape the /tailnet/<name>/devices path.
	if strings.ContainsAny(tailnet, "/?#") {
		return nil, fmt.Errorf("tailscale: invalid tailnet name %q", tailnet)
	}
	url := fmt.Sprintf("%s/api/v2/tailnet/%s/devices", strings.TrimRight(e.apiBaseURL, "/"), tailnet)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("tailscale: build api request: %w", err)
	}
	// Tailscale accepts the API key as HTTP basic-auth username.
	req.SetBasicAuth(apiKey, "")
	req.Header.Set("Accept", "application/json")

	resp, err := e.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("tailscale: api request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if err != nil {
		return nil, fmt.Errorf("tailscale: read api body: %w", err)
	}
	if resp.StatusCode == http.StatusUnauthorized {
		return nil, fmt.Errorf("tailscale: HTTP 401 — invalid API key")
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("tailscale: HTTP %d: %s", resp.StatusCode, truncate(string(body), 200))
	}
	return peersFromDevices(body)
}

type tsDevicesResponse struct {
	Devices []tsDevice `json:"devices"`
}

type tsDevice struct {
	Hostname  string   `json:"hostname"`
	Name      string   `json:"name"` // FQDN
	OS        string   `json:"os"`
	User      string   `json:"user"`
	LastSeen  string   `json:"lastSeen"`
	ClientVer string   `json:"clientVersion"`
	Addresses []string `json:"addresses"`
	Tags      []string `json:"tags"`
	Expires   string   `json:"expires"`
	Blocked   bool     `json:"blocked"`
}

// peersFromDevices projects the v2 API device list onto Peer. Pure; tested
// via an httptest fixture.
func peersFromDevices(raw []byte) ([]Peer, error) {
	var resp tsDevicesResponse
	if err := json.Unmarshal(raw, &resp); err != nil {
		return nil, fmt.Errorf("tailscale: decode devices json: %w", err)
	}
	out := make([]Peer, 0, len(resp.Devices))
	for _, d := range resp.Devices {
		p := Peer{
			VPNType:   "tailscale",
			Hostname:  d.Hostname,
			DNSName:   strings.TrimSuffix(d.Name, "."),
			OS:        d.OS,
			OSVersion: d.ClientVer,
			Owner:     d.User,
			Addresses: sortAddrs(d.Addresses),
			LastSeen:  parseTSTime(d.LastSeen),
			// The API reports last-seen but not live presence; treat a
			// recent contact as the best available liveness proxy downstream
			// via LastSeenAt rather than asserting Online here.
			Tags: map[string]any{"source": "tailscale_api"},
		}
		if len(d.Tags) > 0 {
			p.Tags["acl_tags"] = d.Tags
		}
		if d.Blocked {
			p.Tags["blocked"] = true
		}
		out = append(out, p)
	}
	return out, nil
}
