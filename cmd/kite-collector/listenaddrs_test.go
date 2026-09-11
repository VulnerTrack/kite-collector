package main

import (
	"errors"
	"net"
	"strings"
	"testing"
)

// hostWith describes a machine's interfaces so a test can say "a laptop on
// wifi" or "a cloud VM" instead of depending on the NICs of whatever
// machine runs the suite.
func hostWith(addrs ...interfaceAddr) interfaceLister {
	return func() ([]interfaceAddr, error) { return addrs, nil }
}

func ifaceAddr(ip, name string) interfaceAddr {
	return interfaceAddr{IP: net.ParseIP(ip), Iface: name}
}

// typicalHost: loopback, a LAN address on wifi, and a tailnet address.
func typicalHost() interfaceLister {
	return hostWith(
		ifaceAddr("127.0.0.1", "lo"),
		ifaceAddr("::1", "lo"),
		ifaceAddr("192.168.0.100", "wlan0"),
		ifaceAddr("fe80::1", "wlan0"),
		ifaceAddr("100.101.102.103", "tailscale0"),
	)
}

func urls(r listenReachability) []string { return reachableURLList(r) }

func requireURLs(t *testing.T, r listenReachability, want ...string) {
	t.Helper()
	got := urls(r)
	if len(got) != len(want) {
		t.Fatalf("urls = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("urls = %v, want %v", got, want)
		}
	}
}

// 0.0.0.0 answers on every interface, so every interface address is worth
// printing — and the bind address itself never is, because no browser can
// open http://0.0.0.0.
func TestReachability_Wildcard_ListsEveryInterface(t *testing.T) {
	r := listenReachabilityFor("0.0.0.0:9090", typicalHost())

	// Ordered by how likely the operator wants it: this machine, then the
	// LAN NIC, then the mesh address.
	requireURLs(t, r,
		"http://localhost:9090",
		"http://192.168.0.100:9090",
		"http://100.101.102.103:9090",
	)
	if strings.Contains(strings.Join(urls(r), " "), "0.0.0.0") {
		t.Fatalf("0.0.0.0 is a bind address, not a URL: %v", urls(r))
	}
	// Link-local is omitted: an IPv6 link-local URL needs a zone index no
	// browser accepts.
	if strings.Contains(strings.Join(urls(r), " "), "fe80") {
		t.Fatalf("link-local must not be advertised: %v", urls(r))
	}
	// A tailnet address (100.64.0.0/10) is local network, not public.
	for _, u := range r.URLs {
		if u.URL == "http://100.101.102.103:9090" && u.Scope != scopePrivate {
			t.Fatalf("CGNAT address scope = %q, want %q", u.Scope, scopePrivate)
		}
		if u.URL == "http://192.168.0.100:9090" && u.Iface != "wlan0" {
			t.Fatalf("iface = %q, want wlan0", u.Iface)
		}
	}
	if r.Primary() != "http://localhost:9090" {
		t.Fatalf("primary = %q, want the loopback URL", r.Primary())
	}
}

// ":9090" and "[::]:9090" are the same wildcard bind in different clothes.
func TestReachability_WildcardSpellings(t *testing.T) {
	// The unbracketed "0:0:0:0:0:0:0:0:9090" is deliberately absent: it is
	// not a valid listen address (net.Listen rejects it), so treating it
	// as a wildcard would advertise a URL for a bind that cannot happen.
	for _, addr := range []string{":9090", "0.0.0.0:9090", "[::]:9090", "[0:0:0:0:0:0:0:0]:9090"} {
		r := listenReachabilityFor(addr, typicalHost())
		if r.Primary() != "http://localhost:9090" {
			t.Fatalf("%s: primary = %q", addr, r.Primary())
		}
		if len(r.URLs) != 3 {
			t.Fatalf("%s: urls = %v", addr, urls(r))
		}
	}
}

// A cloud VM with a routable address on the NIC: the public URL is
// discoverable without asking any external service.
func TestReachability_Wildcard_PublicAddressIsLabelled(t *testing.T) {
	r := listenReachabilityFor("0.0.0.0:9090", hostWith(
		ifaceAddr("127.0.0.1", "lo"),
		ifaceAddr("10.0.0.4", "eth0"),
		ifaceAddr("203.0.113.7", "eth0"),
		ifaceAddr("2001:db8::1", "eth0"),
	))

	requireURLs(t, r,
		"http://localhost:9090",
		"http://10.0.0.4:9090",
		"http://203.0.113.7:9090",
		"http://[2001:db8::1]:9090",
	)
	for _, u := range r.URLs {
		want := map[string]string{
			"http://localhost:9090":     scopeLoopback,
			"http://10.0.0.4:9090":      scopePrivate,
			"http://203.0.113.7:9090":   scopePublic,
			"http://[2001:db8::1]:9090": scopePublic,
		}[u.URL]
		if u.Scope != want {
			t.Fatalf("%s scope = %q, want %q", u.URL, u.Scope, want)
		}
	}
}

// A host with nothing but loopback binds fine but serves nobody else, and
// saying so beats printing a LAN URL that does not exist.
func TestReachability_Wildcard_LoopbackOnlyHostSaysSo(t *testing.T) {
	r := listenReachabilityFor("0.0.0.0:9090", hostWith(ifaceAddr("127.0.0.1", "lo")))
	requireURLs(t, r, "http://localhost:9090")
	if len(r.Notes) != 1 || !strings.Contains(r.Notes[0], "no non-loopback address") {
		t.Fatalf("notes = %v", r.Notes)
	}
}

// 127.0.0.1 is reachable as both localhost and the literal, and by nobody
// else.
func TestReachability_Loopback_ThisMachineOnly(t *testing.T) {
	r := listenReachabilityFor("127.0.0.1:9090", typicalHost())
	requireURLs(t, r, "http://localhost:9090", "http://127.0.0.1:9090")
	for _, u := range r.URLs {
		if u.Scope != scopeLoopback {
			t.Fatalf("%s scope = %q, want %q", u.URL, u.Scope, scopeLoopback)
		}
	}
	if strings.Contains(strings.Join(urls(r), " "), "192.168") {
		t.Fatalf("a loopback bind must not advertise LAN addresses: %v", urls(r))
	}
}

// 127.0.0.0 is the trap: the bind succeeds (all of 127/8 is local) but
// localhost resolves to 127.0.0.1, so the URL everyone reaches for does
// NOT hit this listener. Say that rather than printing a URL that hangs.
func TestReachability_Loopback_NetworkAddressDoesNotAnswerAsLocalhost(t *testing.T) {
	r := listenReachabilityFor("127.0.0.0:9090", typicalHost())

	requireURLs(t, r, "http://127.0.0.0:9090")
	if len(r.Notes) != 1 {
		t.Fatalf("notes = %v", r.Notes)
	}
	note := r.Notes[0]
	for _, must := range []string{"localhost", "will NOT reach", "127.0.0.1", "127.0.0.0"} {
		if !strings.Contains(note, must) {
			t.Fatalf("note missing %q: %s", must, note)
		}
	}
}

// ::1 behaves like 127.0.0.1, bracketed.
func TestReachability_IPv6Loopback(t *testing.T) {
	r := listenReachabilityFor("[::1]:9090", typicalHost())
	requireURLs(t, r, "http://localhost:9090", "http://[::1]:9090")
}

// "localhost" is a name, and a name is what the operator should be given
// back — no note, because it is unambiguously this machine.
func TestReachability_LocalhostName(t *testing.T) {
	r := listenReachabilityFor("localhost:9090", typicalHost())
	requireURLs(t, r, "http://localhost:9090")
	if r.URLs[0].Scope != scopeLoopback {
		t.Fatalf("scope = %q", r.URLs[0].Scope)
	}
	if len(r.Notes) != 0 {
		t.Fatalf("localhost needs no caveat, got %v", r.Notes)
	}
}

// Binding one LAN address advertises exactly that address — not localhost,
// which will not answer, and not the host's other interfaces.
func TestReachability_SpecificAddress_OnlyThatAddress(t *testing.T) {
	r := listenReachabilityFor("192.168.0.100:9090", typicalHost())

	requireURLs(t, r, "http://192.168.0.100:9090")
	if r.URLs[0].Scope != scopePrivate || r.URLs[0].Iface != "wlan0" {
		t.Fatalf("url = %+v, want local-network on wlan0", r.URLs[0])
	}
	if len(r.Notes) != 0 {
		t.Fatalf("an assigned address needs no caveat, got %v", r.Notes)
	}
}

// "Only if the binding IP is available": an address this host does not own
// cannot be bound, so there is no URL to print — just the reason.
func TestReachability_SpecificAddress_NotOnThisHostIsRefused(t *testing.T) {
	r := listenReachabilityFor("192.168.0.100:9090", hostWith(
		ifaceAddr("127.0.0.1", "lo"),
		ifaceAddr("10.0.0.4", "eth0"),
	))

	if len(r.URLs) != 0 {
		t.Fatalf("an unbindable address must advertise nothing, got %v", urls(r))
	}
	if r.Primary() != "" {
		t.Fatalf("primary = %q, want empty", r.Primary())
	}
	if len(r.Notes) != 1 {
		t.Fatalf("notes = %v", r.Notes)
	}
	for _, must := range []string{"192.168.0.100", "not assigned", "fail to bind", "0.0.0.0"} {
		if !strings.Contains(r.Notes[0], must) {
			t.Fatalf("note missing %q: %s", must, r.Notes[0])
		}
	}
}

// A public address the host actually owns is advertised as public.
func TestReachability_SpecificPublicAddress(t *testing.T) {
	r := listenReachabilityFor("203.0.113.7:9090", hostWith(ifaceAddr("203.0.113.7", "eth0")))
	requireURLs(t, r, "http://203.0.113.7:9090")
	if r.URLs[0].Scope != scopePublic {
		t.Fatalf("scope = %q, want %q", r.URLs[0].Scope, scopePublic)
	}
}

// A non-localhost name cannot be checked against interfaces, so it is
// passed through with the caveat that DNS has to agree.
func TestReachability_Hostname(t *testing.T) {
	r := listenReachabilityFor("kite.internal:9090", typicalHost())
	requireURLs(t, r, "http://kite.internal:9090")
	if len(r.Notes) != 1 || !strings.Contains(r.Notes[0], "DNS") {
		t.Fatalf("notes = %v", r.Notes)
	}
}

// An empty address is how both listeners are disabled; it must not
// produce a URL.
func TestReachability_EmptyAddressIsDisabled(t *testing.T) {
	r := listenReachabilityFor("", typicalHost())
	if len(r.URLs) != 0 || r.Primary() != "" {
		t.Fatalf("urls = %v", urls(r))
	}
	if len(r.Notes) != 1 || !strings.Contains(r.Notes[0], "disabled") {
		t.Fatalf("notes = %v", r.Notes)
	}
}

// A bare host with no port still yields an openable URL.
func TestReachability_NoPort(t *testing.T) {
	r := listenReachabilityFor("192.168.0.100", typicalHost())
	requireURLs(t, r, "http://192.168.0.100")
}

// Interface enumeration can fail (containers, locked-down hosts). A
// wildcard bind still offers localhost; a specific bind still offers what
// was asked for, because refusing to print it would be worse than
// printing it unverified.
func TestReachability_InterfaceErrorDegradesGracefully(t *testing.T) {
	boom := func() ([]interfaceAddr, error) { return nil, errors.New("no permission") }

	wild := listenReachabilityFor("0.0.0.0:9090", boom)
	requireURLs(t, wild, "http://localhost:9090")
	if len(wild.Notes) != 1 || !strings.Contains(wild.Notes[0], "no permission") {
		t.Fatalf("notes = %v", wild.Notes)
	}

	specific := listenReachabilityFor("192.168.0.100:9090", boom)
	requireURLs(t, specific, "http://192.168.0.100:9090")
	if len(specific.Notes) != 1 || !strings.Contains(specific.Notes[0], "could not verify") {
		t.Fatalf("notes = %v", specific.Notes)
	}
}

// Down interfaces are skipped by the production lister, so it never
// advertises an address on a dead link.
func TestSystemInterfaceAddrs_ReturnsSomethingSane(t *testing.T) {
	addrs, err := systemInterfaceAddrs()
	if err != nil {
		t.Skipf("interfaces unavailable in this environment: %v", err)
	}
	for _, a := range addrs {
		if a.IP == nil {
			t.Fatal("nil IP in interface list")
		}
		if a.Iface == "" {
			t.Fatalf("address %s has no interface name", a.IP)
		}
	}
}

// The rendered block marks the browser target and explains each row.
func TestFormatReachability(t *testing.T) {
	r := listenReachabilityFor("0.0.0.0:9090", typicalHost())
	lines := formatReachability(r, "    ")
	if len(lines) != 3 {
		t.Fatalf("lines = %v", lines)
	}
	if !strings.HasPrefix(lines[0], "    → http://localhost:9090") {
		t.Fatalf("first line must be the browser target: %q", lines[0])
	}
	if !strings.Contains(lines[0], scopeLoopback) {
		t.Fatalf("missing scope: %q", lines[0])
	}
	if !strings.Contains(lines[1], "local network (wlan0)") {
		t.Fatalf("missing scope/iface detail: %q", lines[1])
	}

	// Notes render as their own flagged lines.
	noted := formatReachability(listenReachabilityFor("127.0.0.0:9090", typicalHost()), "  ")
	if len(noted) != 2 || !strings.HasPrefix(noted[1], "  ! ") {
		t.Fatalf("lines = %v", noted)
	}
}

// A Docker host owns a bridge gateway per network. Listing all of them
// buries the one address a colleague needs, so they are counted instead —
// and the LAN NIC stays at the top.
func TestReachability_Wildcard_BridgeAddressesAreCountedNotListed(t *testing.T) {
	addrs := make([]interfaceAddr, 0, 9)
	addrs = append(addrs,
		ifaceAddr("127.0.0.1", "lo"),
		ifaceAddr("192.168.0.100", "enp4s0"),
		ifaceAddr("100.113.100.56", "tailscale0"),
		ifaceAddr("172.17.0.1", "docker0"),
		ifaceAddr("172.29.0.1", "docker_gwbridge"),
	)
	for _, br := range []string{"br-e29fa738756a", "br-b813e6d16b0a", "br-eb4534787be7", "virbr0"} {
		addrs = append(addrs, ifaceAddr("172.18.0.1", br))
	}
	r := listenReachabilityFor("0.0.0.0:9090", hostWith(addrs...))

	requireURLs(t, r,
		"http://localhost:9090",
		"http://192.168.0.100:9090",
		"http://100.113.100.56:9090",
	)
	if len(r.Suppressed) != 6 {
		t.Fatalf("suppressed = %d, want the 6 bridge addresses", len(r.Suppressed))
	}

	line := strings.Join(formatReachability(r, ""), "\n")
	if !strings.Contains(line, "(+6 on container/VM bridges: br-b813e6d16b0a, br-e29fa738756a, br-eb4534787be7, …)") {
		t.Fatalf("summary line missing or malformed:\n%s", line)
	}
	if strings.Contains(line, "172.17.0.1") {
		t.Fatalf("bridge addresses must not be listed individually:\n%s", line)
	}
}

// Interface tiering is name-based; the classes it must never confuse are
// "the VPN a colleague comes in over" and "a container bridge".
func TestIfaceTier(t *testing.T) {
	for name, want := range map[string]int{
		"enp4s0":          tierOrdinary,
		"eth0":            tierOrdinary,
		"wlan0":           tierOrdinary,
		"en0":             tierOrdinary,
		"tailscale0":      tierOverlay,
		"wg0":             tierOverlay,
		"utun3":           tierOverlay,
		"docker0":         tierBridge,
		"docker_gwbridge": tierBridge,
		"br-abc123":       tierBridge,
		"virbr0":          tierBridge,
		"veth9f2a":        tierBridge,
		"vboxnet0":        tierBridge,
	} {
		if got := ifaceTier(name); got != want {
			t.Fatalf("ifaceTier(%q) = %d, want %d", name, got, want)
		}
	}
}

// A host whose only non-loopback addresses are bridges still says
// something true: those addresses exist, they are just not worth typing.
func TestReachability_Wildcard_OnlyBridges(t *testing.T) {
	r := listenReachabilityFor("0.0.0.0:9090", hostWith(
		ifaceAddr("127.0.0.1", "lo"),
		ifaceAddr("172.17.0.1", "docker0"),
	))
	requireURLs(t, r, "http://localhost:9090")
	if len(r.Suppressed) != 1 {
		t.Fatalf("suppressed = %v", r.Suppressed)
	}
	if len(r.Notes) != 0 {
		t.Fatalf("bridges are addresses, so the no-address note must not fire: %v", r.Notes)
	}
}

// Binding a bridge address explicitly is an explicit choice; honour it.
func TestReachability_SpecificBridgeAddressIsHonoured(t *testing.T) {
	r := listenReachabilityFor("172.17.0.1:9090", hostWith(ifaceAddr("172.17.0.1", "docker0")))
	requireURLs(t, r, "http://172.17.0.1:9090")
	if len(r.Suppressed) != 0 {
		t.Fatalf("an explicit bind is never suppressed: %v", r.Suppressed)
	}
}
