package intranetweb

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"strings"
)

// HostsFileResolver parses /etc/hosts (or its Windows equivalent) and
// emits a Target for every entry that looks like a private/loopback
// LAN address. We never include public IPs — the audit is about
// intranet exposure.
type HostsFileResolver struct {
	ReadFile func(string) ([]byte, error)
	Path     string
	Ports    []int
}

// DefaultHostsPath returns the OS-conventional path. Callers can
// override for tests.
func DefaultHostsPath() string {
	// On Windows the file lives at C:\Windows\System32\drivers\etc\hosts;
	// we let the caller plumb in the right path because resolving the
	// system root from Go without depending on syscall packages is
	// uglier than the value it adds.
	return "/etc/hosts"
}

// NewHostsFileResolver constructs a HostsFileResolver with sane defaults.
func NewHostsFileResolver() *HostsFileResolver {
	return &HostsFileResolver{
		Path:     DefaultHostsPath(),
		Ports:    DefaultPorts(),
		ReadFile: func(p string) ([]byte, error) { return os.ReadFile(p) }, //#nosec G304 -- fixed system path
	}
}

func (r *HostsFileResolver) Resolve(ctx context.Context) ([]Target, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("context cancelled: %w", err)
	}
	data, err := r.ReadFile(r.Path)
	if err != nil {
		// Missing hosts file is not fatal — return empty.
		return nil, nil //nolint:nilerr // intentional: empty source on unreadable file
	}
	return parseHostsFile(data, r.Ports), nil
}

// parseHostsFile walks an /etc/hosts body and emits a Target per
// (ip, port) pair for every private-LAN address it finds.
func parseHostsFile(data []byte, ports []int) []Target {
	scan := bufio.NewScanner(bytes.NewReader(data))
	// Bump the line buffer — some sysadmins build very wide aliases.
	scan.Buffer(make([]byte, 0, 1024), 1<<20)

	var out []Target
	for scan.Scan() {
		line := scan.Text()
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		ip := fields[0]
		if !isPrivateOrLoopback(ip) {
			continue
		}
		// First non-IP field is the canonical hostname; subsequent are aliases.
		host := fields[1]
		for _, port := range ports {
			out = append(out, Target{
				IP:     ip,
				Host:   host,
				Port:   port,
				Source: SourceHostsFile,
			})
		}
	}
	return out
}

// isPrivateOrLoopback reports whether the IP belongs to RFC1918,
// loopback, link-local, or IPv6 ULA. Public-IP entries in /etc/hosts
// usually pin auth endpoints (github.com, package mirrors) and have
// no business in an intranet-web audit.
func isPrivateOrLoopback(s string) bool {
	ip := net.ParseIP(s)
	if ip == nil {
		return false
	}
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsPrivate() {
		return true
	}
	return false
}

// StaticResolver is the test-friendly resolver — pass it a fixed
// Target list and it just returns it. Also used in production to wire
// in targets that come from the LAN discovery output.
type StaticResolver struct {
	Targets []Target
}

func (r *StaticResolver) Resolve(_ context.Context) ([]Target, error) {
	out := make([]Target, len(r.Targets))
	copy(out, r.Targets)
	return out, nil
}

// ChainResolver concatenates several resolvers and dedupes the result.
// Failures from any single resolver are logged-and-skipped, mirroring
// the chain-collector pattern used elsewhere in the agent.
type ChainResolver struct {
	Resolvers []TargetResolver
}

func (c *ChainResolver) Resolve(ctx context.Context) ([]Target, error) {
	var all []Target
	for _, r := range c.Resolvers {
		if err := ctx.Err(); err != nil {
			return nil, fmt.Errorf("context cancelled mid-chain: %w", err)
		}
		ts, err := r.Resolve(ctx)
		if err != nil {
			// Intentionally swallow: one bad source shouldn't sink the chain.
			continue
		}
		all = append(all, ts...)
	}
	return DedupeTargets(all), nil
}
