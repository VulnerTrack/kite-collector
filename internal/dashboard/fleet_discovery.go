package dashboard

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	mdnsdisc "github.com/vulnertrack/kite-collector/internal/discovery/lan/mdns"
	netbiosdisc "github.com/vulnertrack/kite-collector/internal/discovery/lan/netbios"
	ssdpdisc "github.com/vulnertrack/kite-collector/internal/discovery/lan/ssdp"
	wsddisc "github.com/vulnertrack/kite-collector/internal/discovery/lan/wsdiscovery"
	"github.com/vulnertrack/kite-collector/internal/discovery/network"
	"github.com/vulnertrack/kite-collector/internal/model"
	"github.com/vulnertrack/kite-collector/internal/store"
)

var errFleetDiscoveryRunning = errors.New("network discovery is already running")

type fleetLocalNetwork struct {
	InterfaceName string
	LocalIP       string
	CIDR          string
	GatewayIP     string
	score         int
}

type fleetDiscoveryStatus struct {
	Network      string
	CompletedAt  string
	Error        string
	Found        int
	Inserted     int
	Updated      int
	TCPFound     int
	MDNSFound    int
	NetBIOSFound int
	SSDPFound    int
	WSDFound     int
	Running      bool
	HasRun       bool
}

type fleetDiscoveryController struct {
	detect          func() (fleetLocalNetwork, error)
	discover        func(context.Context, map[string]any) ([]model.Machine, error)
	discoverMDNS    func(context.Context, map[string]any) ([]model.Machine, error)
	discoverNetBIOS func(context.Context, map[string]any) ([]model.Machine, error)
	discoverSSDP    func(context.Context, map[string]any) ([]model.Machine, error)
	discoverWSD     func(context.Context, map[string]any) ([]model.Machine, error)
	localMachine    func(fleetLocalNetwork) (model.Machine, error)
	mu              sync.Mutex
	status          fleetDiscoveryStatus
}

func newFleetDiscoveryController() *fleetDiscoveryController {
	scanner := network.New()
	mdnsScanner := mdnsdisc.New()
	netbiosScanner := netbiosdisc.New()
	ssdpScanner := ssdpdisc.New()
	wsdScanner := wsddisc.New()
	return &fleetDiscoveryController{
		detect:          detectFleetLocalNetwork,
		discover:        scanner.Discover,
		discoverMDNS:    mdnsScanner.Discover,
		discoverNetBIOS: netbiosScanner.Discover,
		discoverSSDP:    ssdpScanner.Discover,
		discoverWSD:     wsdScanner.Discover,
		localMachine:    discoverFleetControllerMachine,
	}
}

func (c *fleetDiscoveryController) snapshot() fleetDiscoveryStatus {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.status
}

func (c *fleetDiscoveryController) run(ctx context.Context, st store.Store) error {
	c.mu.Lock()
	if c.status.Running {
		c.mu.Unlock()
		return errFleetDiscoveryRunning
	}
	c.status = fleetDiscoveryStatus{Running: true}
	c.mu.Unlock()

	localNetwork, err := c.detect()
	if err != nil {
		c.finish(fleetDiscoveryStatus{Error: err.Error()})
		return err
	}
	status := fleetDiscoveryStatus{Network: localNetwork.CIDR}
	type discoveryResult struct {
		kind     string
		machines []model.Machine
		err      error
	}
	results := make(chan discoveryResult, 5)
	jobs := 0
	run := func(kind string, discover func(context.Context, map[string]any) ([]model.Machine, error), cfg map[string]any) {
		if discover == nil {
			return
		}
		jobs++
		go func() {
			machines, discoverErr := discover(ctx, cfg)
			results <- discoveryResult{kind: kind, machines: machines, err: discoverErr}
		}()
	}
	run("tcp", c.discover, map[string]any{
		"scope": []string{localNetwork.CIDR},
		"tcp_ports": []int{
			21, 22, 23, 53, 80, 88, 135, 139, 443, 445, 548, 631,
			3389, 5900, 5985, 5986, 8080, 9100,
		},
		"timeout":        "400ms",
		"max_concurrent": 64,
		"scan_timeout":   "45s",
		"infer_os":       true,
	})
	run("mdns", c.discoverMDNS, map[string]any{
		"interfaces":    []string{localNetwork.InterfaceName},
		"listen_window": "4s",
		"disable_ipv6":  true,
	})
	run("netbios", c.discoverNetBIOS, map[string]any{
		"interfaces":    []string{localNetwork.InterfaceName},
		"targets":       fleetIPv4Targets(localNetwork.CIDR, localNetwork.LocalIP),
		"listen_window": "4s",
	})
	multicastConfig := map[string]any{
		"interfaces":    []string{localNetwork.InterfaceName},
		"listen_window": "4s",
		"disable_ipv6":  true,
	}
	run("ssdp", c.discoverSSDP, multicastConfig)
	run("wsdiscovery", c.discoverWSD, multicastConfig)

	var machines []model.Machine
	var tcpErr error
	for range jobs {
		result := <-results
		if result.err != nil {
			if result.kind == "tcp" {
				tcpErr = result.err
			}
			continue
		}
		filtered := result.machines[:0]
		for _, machine := range result.machines {
			host := strings.TrimSpace(machine.Hostname)
			if host == localNetwork.LocalIP || (localNetwork.GatewayIP != "" && host == localNetwork.GatewayIP) {
				continue
			}
			filtered = append(filtered, machine)
		}
		result.machines = filtered
		switch result.kind {
		case "tcp":
			status.TCPFound = len(result.machines)
		case "mdns":
			status.MDNSFound = len(result.machines)
		case "netbios":
			status.NetBIOSFound = len(result.machines)
		case "ssdp":
			status.SSDPFound = len(result.machines)
		case "wsdiscovery":
			status.WSDFound = len(result.machines)
		}
		for i := range result.machines {
			inferFleetProtocolOS(&result.machines[i])
		}
		machines = append(machines, result.machines...)
	}
	if tcpErr != nil {
		status.Error = tcpErr.Error()
		c.finish(status)
		return tcpErr
	}
	// Network scanners intentionally skip the address they run from. Add the
	// controller back using local OS facts so the operator sees the current
	// computer with its real hostname, OS and architecture rather than an IP.
	if c.localMachine != nil {
		local, localErr := c.localMachine(localNetwork)
		if localErr == nil {
			machines = append(machines, local)
		}
	}
	status.Found = len(machines)
	for i := range machines {
		machines[i].ID = uuid.Must(uuid.NewV7())
	}
	if len(machines) > 0 {
		status.Inserted, status.Updated, err = st.UpsertMachines(ctx, machines)
		if err != nil {
			status.Error = err.Error()
			c.finish(status)
			return fmt.Errorf("store discovered machines: %w", err)
		}
	}
	c.finish(status)
	return nil
}

func discoverFleetControllerMachine(network fleetLocalNetwork) (model.Machine, error) {
	hostname, err := os.Hostname()
	if err != nil || strings.TrimSpace(hostname) == "" {
		return model.Machine{}, fmt.Errorf("resolve local hostname: %w", err)
	}
	osFamily := runtime.GOOS
	if osFamily == "darwin" {
		osFamily = "macos"
	}
	tags := fmt.Sprintf(`{"local_ip":%q,"deployment_os_confidence":"high","deployment_os_evidence":"local operating system"}`, network.LocalIP)
	now := time.Now().UTC()
	return model.Machine{
		Hostname:        hostname,
		MachineType:     model.MachineTypeWorkstation,
		OSFamily:        osFamily,
		Architecture:    runtime.GOARCH,
		DiscoverySource: "local_controller",
		IsAuthorized:    model.AuthorizationUnknown,
		IsManaged:       model.ManagedUnknown,
		Tags:            tags,
		FirstSeenAt:     now,
		LastSeenAt:      now,
	}, nil
}

func inferFleetProtocolOS(machine *model.Machine) {
	if machine == nil || strings.TrimSpace(machine.OSFamily) != "" {
		return
	}
	lowerTags := strings.ToLower(machine.Tags)
	switch strings.ToLower(strings.TrimSpace(machine.DiscoverySource)) {
	case "wsdiscovery":
		if strings.Contains(lowerTags, "microsoft.com/windows") ||
			strings.Contains(lowerTags, "pkitypes.microsoft.com") {
			machine.OSFamily = "windows"
			machine.Architecture = "amd64"
		}
	case "ssdp":
		if strings.Contains(lowerTags, `"ssdp_server":"linux`) {
			machine.OSFamily = "linux"
			machine.Architecture = "amd64"
		}
	}
}

func fleetIPv4Targets(cidr, localIP string) []string {
	prefix, err := netip.ParsePrefix(cidr)
	if err != nil || !prefix.Addr().Is4() {
		return nil
	}
	targets := make([]string, 0, 254)
	for addr := prefix.Masked().Addr(); prefix.Contains(addr); addr = addr.Next() {
		isBroadcast := prefix.Bits() < 31 && !prefix.Contains(addr.Next())
		if addr.String() == localIP || addr == prefix.Masked().Addr() || isBroadcast {
			continue
		}
		targets = append(targets, addr.String())
		if len(targets) >= 254 {
			break
		}
	}
	return targets
}

func (c *fleetDiscoveryController) finish(status fleetDiscoveryStatus) {
	status.Running = false
	status.HasRun = true
	status.CompletedAt = time.Now().UTC().Format("2006-01-02 15:04 UTC")
	c.mu.Lock()
	c.status = status
	c.mu.Unlock()
}

func handleFleetDiscovery(
	w http.ResponseWriter,
	r *http.Request,
	st store.Store,
	logger *slog.Logger,
	controller *fleetDiscoveryController,
) {
	if !fleetDiscoverySameOrigin(r) {
		http.Error(w, "cross-site network discovery is not allowed", http.StatusForbidden)
		return
	}
	if err := controller.run(r.Context(), st); err != nil {
		logger.Error("dashboard: fleet network discovery failed",
			"code", string(LogCodeFleetDiscovery),
			"error", err)
	}
	http.Redirect(w, r, "/fleet", http.StatusSeeOther)
}

func fleetDiscoverySameOrigin(r *http.Request) bool {
	if strings.EqualFold(strings.TrimSpace(r.Header.Get("Sec-Fetch-Site")), "cross-site") {
		return false
	}
	origin := strings.TrimSpace(r.Header.Get("Origin"))
	if origin == "" {
		return true
	}
	parsed, err := url.Parse(origin)
	return err == nil && strings.EqualFold(parsed.Host, r.Host)
}

func detectFleetLocalNetwork() (fleetLocalNetwork, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return fleetLocalNetwork{}, fmt.Errorf("list local network interfaces: %w", err)
	}
	candidates := make([]fleetLocalNetwork, 0)
	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 || isFleetVirtualInterface(iface.Name) {
			continue
		}
		addresses, addrErr := iface.Addrs()
		if addrErr != nil {
			continue
		}
		for _, address := range addresses {
			prefix, parseErr := netip.ParsePrefix(address.String())
			if parseErr != nil {
				continue
			}
			ip := prefix.Addr().Unmap()
			if !ip.Is4() || !ip.IsPrivate() {
				continue
			}
			scanPrefix := fleetScanPrefix(ip, prefix.Bits())
			candidates = append(candidates, fleetLocalNetwork{
				InterfaceName: iface.Name,
				LocalIP:       ip.String(),
				CIDR:          scanPrefix.String(),
				GatewayIP:     defaultGatewayIPv4(iface.Name, ip.String()),
				score:         fleetInterfaceScore(iface.Name),
			})
		}
	}
	return selectFleetLocalNetwork(candidates)
}

func fleetScanPrefix(ip netip.Addr, interfaceBits int) netip.Prefix {
	// Never sweep more than the local /24 from a single click. This keeps a
	// broad corporate /16 from turning a convenience action into a large scan.
	if interfaceBits < 24 {
		interfaceBits = 24
	}
	return netip.PrefixFrom(ip, interfaceBits).Masked()
}

func selectFleetLocalNetwork(candidates []fleetLocalNetwork) (fleetLocalNetwork, error) {
	if len(candidates) == 0 {
		return fleetLocalNetwork{}, fmt.Errorf("no active private IPv4 network was detected")
	}
	sort.SliceStable(candidates, func(i, j int) bool {
		if candidates[i].score != candidates[j].score {
			return candidates[i].score > candidates[j].score
		}
		return candidates[i].InterfaceName < candidates[j].InterfaceName
	})
	return candidates[0], nil
}

func isFleetVirtualInterface(name string) bool {
	lower := strings.ToLower(name)
	for _, prefix := range []string{
		"br-", "cni", "docker", "flannel", "lo", "podman", "tap", "tailscale", "tun", "veth", "virbr", "vmnet", "wg",
	} {
		if strings.HasPrefix(lower, prefix) {
			return true
		}
	}
	return false
}

func fleetInterfaceScore(name string) int {
	lower := strings.ToLower(name)
	for _, prefix := range []string{"en", "eth", "wl", "wlan"} {
		if strings.HasPrefix(lower, prefix) {
			return 100
		}
	}
	return 10
}
