package main

import (
	"fmt"
	"net"
	"sort"
	"strings"
)

// Reachability scopes, ordered from nearest to furthest. The label is what
// an operator reads next to a URL: it answers "who can open this?" without
// needing to recognise an address range on sight.
const (
	scopeLoopback = "this machine"
	scopePrivate  = "local network"
	scopePublic   = "public"
)

// reachableURL is one address a browser can actually open to reach a
// listener. Iface names the interface the address is assigned to, empty
// for names (localhost) that are not tied to one.
type reachableURL struct {
	URL   string
	Scope string
	Iface string
}

// listenReachability answers "where can I open this?" for a listen
// address. URLs is ordered nearest-first, so the first entry is the one to
// hand a local browser.
//
// Notes carry things that are true but surprising — a loopback address
// that `localhost` will not reach, a bind that cannot succeed on this
// host. They exist because the alternative is an operator staring at a
// URL that times out with no explanation.
type listenReachability struct {
	URLs  []reachableURL
	Notes []string
	// Suppressed holds addresses that are genuinely listening but that
	// nobody browses to — container and VM bridge gateways. A Docker host
	// can own two dozen of them, and printing them all buries the one
	// address a colleague actually needs. They are counted, not hidden:
	// the banner says how many and on which interfaces.
	Suppressed []reachableURL
}

// Primary is the URL to open locally, or "" when the address is
// unreachable as configured.
func (r listenReachability) Primary() string {
	if len(r.URLs) == 0 {
		return ""
	}
	return r.URLs[0].URL
}

// interfaceAddr is one address assigned to an interface on this host.
type interfaceAddr struct {
	IP    net.IP
	Iface string
}

// interfaceLister enumerates the addresses of up interfaces. Injected so
// tests can describe a host — a laptop on wifi, a cloud VM with a public
// IP, a machine with nothing but loopback — instead of depending on
// whatever NICs the machine running them happens to have.
type interfaceLister func() ([]interfaceAddr, error)

// systemInterfaceAddrs is the production lister. Down interfaces are
// skipped: an address on a link that is not up cannot serve anyone.
func systemInterfaceAddrs() ([]interfaceAddr, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("enumerate interfaces: %w", err)
	}
	var out []interfaceAddr
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, addrErr := iface.Addrs()
		if addrErr != nil {
			continue
		}
		for _, a := range addrs {
			var ip net.IP
			switch v := a.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip != nil {
				out = append(out, interfaceAddr{IP: ip, Iface: iface.Name})
			}
		}
	}
	return out, nil
}

// dashboardReachability is listenReachabilityFor against the real host.
func dashboardReachability(addr string) listenReachability {
	return listenReachabilityFor(addr, systemInterfaceAddrs)
}

// listenReachabilityFor turns a listen address into the set of URLs that
// actually reach it from somewhere.
//
// The rule that shapes every branch: advertise an address only if a
// connection to it lands on this listener. A wildcard bind answers on
// every interface, so every interface address is offered. A specific bind
// answers on exactly one address, so exactly one is offered — and if that
// address is not assigned to this host, the bind will fail and nothing is
// offered at all.
func listenReachabilityFor(addr string, list interfaceLister) listenReachability {
	host, port := splitListenAddr(addr)
	switch {
	case addr == "":
		return listenReachability{Notes: []string{"listener is disabled (empty address)"}}
	case isWildcardHost(host):
		return wildcardReachability(port, list)
	case net.ParseIP(host) != nil:
		return literalReachability(net.ParseIP(host), port, list)
	default:
		return nameReachability(host, port)
	}
}

// wildcardReachability enumerates every address the host answers on.
// localhost stands in for the loopback interface — it is what an operator
// will actually type — and each non-loopback address is offered so the
// same banner tells a colleague on the LAN, or the internet, where to go.
func wildcardReachability(port string, list interfaceLister) listenReachability {
	out := listenReachability{
		URLs: []reachableURL{{URL: httpURL("localhost", port), Scope: scopeLoopback}},
	}
	addrs, err := list()
	if err != nil {
		out.Notes = append(out.Notes, "could not enumerate network interfaces: "+err.Error())
		return out
	}

	var others []reachableURL
	for _, a := range addrs {
		// Loopback is already covered by localhost above. Link-local is
		// omitted deliberately: IPv4 link-local means DHCP failed, and an
		// IPv6 link-local URL needs a zone index no browser will accept.
		if a.IP.IsLoopback() || a.IP.IsLinkLocalUnicast() || a.IP.IsLinkLocalMulticast() {
			continue
		}
		scope := scopeOf(a.IP)
		if scope == "" {
			continue
		}
		u := reachableURL{URL: httpURL(a.IP.String(), port), Scope: scope, Iface: a.Iface}
		if ifaceTier(a.Iface) == tierBridge {
			out.Suppressed = append(out.Suppressed, u)
			continue
		}
		others = append(others, u)
	}
	sortURLs(others)
	sortURLs(out.Suppressed)
	out.URLs = append(out.URLs, others...)
	if len(others) == 0 && len(out.Suppressed) == 0 {
		out.Notes = append(out.Notes,
			"no non-loopback address on this host, so nothing outside this machine can reach it yet")
	}
	return out
}

// Interface tiers, ordered by how likely an operator is to want the
// address. Names are the only portable signal Go gives us here, and they
// are reliable enough for the three cases that matter.
const (
	tierOrdinary = iota // physical NICs: the LAN address someone wants
	tierOverlay         // VPN / mesh: how a remote colleague gets in
	tierBridge          // container and VM bridges: reachable, never browsed
)

// ifaceTier classifies an interface by name. A tailnet or WireGuard
// address is kept visible because reaching the dashboard over the VPN is
// a real workflow; a docker bridge gateway is not.
func ifaceTier(name string) int {
	n := strings.ToLower(name)
	for _, p := range []string{"docker", "br-", "veth", "virbr", "vmnet", "vboxnet", "cni", "flannel", "kube", "cali", "podman", "lxcbr", "lxdbr"} {
		if strings.HasPrefix(n, p) {
			return tierBridge
		}
	}
	for _, p := range []string{"tailscale", "wg", "tun", "tap", "zt", "nebula", "utun", "ppp"} {
		if strings.HasPrefix(n, p) {
			return tierOverlay
		}
	}
	return tierOrdinary
}

// literalReachability handles a bind to one specific IP. This is where
// "only if the binding IP is available" bites: an address that no
// interface owns cannot be bound, so the honest answer is a warning, not
// a URL.
func literalReachability(ip net.IP, port string, list interfaceLister) listenReachability {
	var out listenReachability

	if ip.IsLoopback() {
		// Every 127.0.0.0/8 address is local, so the bind succeeds — but
		// only the exact address answers. localhost resolves to 127.0.0.1
		// (or ::1), so it reaches the listener only when that is what was
		// bound.
		if ip.Equal(net.IPv4(127, 0, 0, 1)) || ip.Equal(net.IPv6loopback) {
			out.URLs = append(out.URLs, reachableURL{URL: httpURL("localhost", port), Scope: scopeLoopback})
		} else {
			out.Notes = append(out.Notes, fmt.Sprintf(
				"http://localhost:%s will NOT reach this listener: localhost resolves to 127.0.0.1, "+
					"and only %s answers", portOrEmpty(port), ip))
		}
		out.URLs = append(out.URLs, reachableURL{URL: httpURL(ip.String(), port), Scope: scopeLoopback})
		return out
	}

	addrs, err := list()
	if err != nil {
		// Without an interface list we cannot prove the address is absent,
		// and refusing to print the URL the operator asked for would be
		// worse than printing it unverified.
		out.Notes = append(out.Notes, "could not verify the address against local interfaces: "+err.Error())
		out.URLs = append(out.URLs, reachableURL{URL: httpURL(ip.String(), port), Scope: scopeOf(ip)})
		return out
	}
	for _, a := range addrs {
		if a.IP.Equal(ip) {
			out.URLs = append(out.URLs, reachableURL{URL: httpURL(ip.String(), port), Scope: scopeOf(ip), Iface: a.Iface})
			return out
		}
	}
	out.Notes = append(out.Notes, fmt.Sprintf(
		"%s is not assigned to any interface on this host — the listener will fail to bind. "+
			"Use 0.0.0.0 to listen on every interface, or one of this host's own addresses", ip))
	return out
}

// nameReachability handles a bind to a hostname. The name is what the
// operator configured and what a browser should be given, so it is
// offered as-is; whether DNS points it back here is between the operator
// and their resolver.
func nameReachability(host, port string) listenReachability {
	scope := scopePrivate
	if strings.EqualFold(host, "localhost") || strings.HasSuffix(strings.ToLower(host), ".localhost") {
		scope = scopeLoopback
	}
	out := listenReachability{URLs: []reachableURL{{URL: httpURL(host, port), Scope: scope}}}
	if scope != scopeLoopback {
		out.Notes = append(out.Notes, fmt.Sprintf(
			"%q is a name, not an address: it reaches this listener only from hosts whose DNS resolves it here", host))
	}
	return out
}

// scopeOf classifies an address by who can reach it.
func scopeOf(ip net.IP) string {
	switch {
	case ip.IsLoopback():
		return scopeLoopback
	case ip.IsPrivate(), ip.IsLinkLocalUnicast(), isCGNAT(ip):
		return scopePrivate
	case ip.IsGlobalUnicast():
		return scopePublic
	default:
		return ""
	}
}

// isCGNAT reports whether ip is in 100.64.0.0/10 (RFC 6598). Go's
// IsPrivate covers RFC 1918 and ULA but not carrier-grade NAT, which is
// also what a tailnet address looks like — and a tailnet address is very
// much "local network", not "public".
func isCGNAT(ip net.IP) bool {
	v4 := ip.To4()
	return v4 != nil && v4[0] == 100 && v4[1] >= 64 && v4[1] <= 127
}

// splitListenAddr accepts every shape a listen address comes in: ":9090",
// "0.0.0.0:9090", "[::]:9090", "localhost:9090", and a bare host with no
// port at all.
func splitListenAddr(addr string) (host, port string) {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return "", ""
	}
	if h, p, err := net.SplitHostPort(addr); err == nil {
		return strings.Trim(h, "[]"), p
	}
	return strings.Trim(addr, "[]"), ""
}

func isWildcardHost(host string) bool {
	switch host {
	case "", "0.0.0.0", "::", "0:0:0:0:0:0:0:0":
		return true
	default:
		return false
	}
}

func httpURL(host, port string) string {
	if port == "" {
		if strings.Contains(host, ":") {
			return "http://[" + host + "]"
		}
		return "http://" + host
	}
	return "http://" + net.JoinHostPort(host, port)
}

func portOrEmpty(port string) string {
	if port == "" {
		return "<port>"
	}
	return port
}

// sortURLs orders addresses the way an operator scans them: nearest scope
// first, IPv4 before IPv6 (shorter to type, and what most people expect),
// then lexically so repeated runs print the same order.
func sortURLs(urls []reachableURL) {
	rank := map[string]int{scopeLoopback: 0, scopePrivate: 1, scopePublic: 2}
	sort.SliceStable(urls, func(i, j int) bool {
		a, b := urls[i], urls[j]
		if rank[a.Scope] != rank[b.Scope] {
			return rank[a.Scope] < rank[b.Scope]
		}
		if ta, tb := ifaceTier(a.Iface), ifaceTier(b.Iface); ta != tb {
			return ta < tb
		}
		aV6, bV6 := strings.Contains(a.URL, "["), strings.Contains(b.URL, "[")
		if aV6 != bV6 {
			return !aV6
		}
		return a.URL < b.URL
	})
}

// formatReachability renders the "Reachable at" block for the launch
// banner. The arrow marks the URL the browser opens; the rest are for
// whoever else needs to get in.
func formatReachability(r listenReachability, indent string) []string {
	var lines []string
	width := 0
	for _, u := range r.URLs {
		if len(u.URL) > width {
			width = len(u.URL)
		}
	}
	for i, u := range r.URLs {
		marker := "  "
		if i == 0 {
			marker = "→ "
		}
		detail := u.Scope
		if u.Iface != "" {
			detail += " (" + u.Iface + ")"
		}
		lines = append(lines, fmt.Sprintf("%s%s%-*s  %s", indent, marker, width, u.URL, detail))
	}
	if n := len(r.Suppressed); n > 0 {
		lines = append(lines, fmt.Sprintf("%s  (+%d on container/VM bridges: %s)",
			indent, n, suppressedIfaceSummary(r.Suppressed)))
	}
	for _, n := range r.Notes {
		lines = append(lines, indent+"! "+n)
	}
	return lines
}

// suppressedIfaceSummary names the first few bridge interfaces so the
// count is recognisable rather than mysterious.
func suppressedIfaceSummary(urls []reachableURL) string {
	seen := make(map[string]bool, len(urls))
	names := make([]string, 0, len(urls))
	for _, u := range urls {
		if u.Iface != "" && !seen[u.Iface] {
			seen[u.Iface] = true
			names = append(names, u.Iface)
		}
	}
	sort.Strings(names)
	if len(names) > 3 {
		return strings.Join(names[:3], ", ") + ", …"
	}
	return strings.Join(names, ", ")
}

// reachableURLList flattens the reachable set for a structured log field.
func reachableURLList(r listenReachability) []string {
	out := make([]string, 0, len(r.URLs))
	for _, u := range r.URLs {
		out = append(out, u.URL)
	}
	return out
}

// reachabilityNoteAttrs surfaces the notes as a log attribute, so a bind
// that cannot work says so in the same line that announces it.
func reachabilityNoteAttrs(r listenReachability) []any {
	if len(r.Notes) == 0 {
		return nil
	}
	return []any{"hint", strings.Join(r.Notes, "; ")}
}
