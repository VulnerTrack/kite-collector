package safenet

import (
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"strconv"
)

const (
	// DefaultMaxScanIPs is the hard cap on IP enumeration before any goroutine
	// is spawned (RFC-0124 R1). Operators can override via KITE_MAX_SCAN_IPS.
	DefaultMaxScanIPs = 100_000

	// DefaultMaxScanConcurrency is the hard upper bound for the scanner
	// semaphore (RFC-0124 R3). Values above this are silently clamped.
	DefaultMaxScanConcurrency = 512

	// MinPort is the lowest valid TCP/UDP port (RFC-0124 R2).
	MinPort = 1

	// MaxPort is the highest valid TCP/UDP port (RFC-0124 R2).
	MaxPort = 65535

	// DefaultMaxPortsPerScan caps the number of ports any single scan may
	// probe so that operators cannot accidentally configure full-port sweeps.
	DefaultMaxPortsPerScan = 1024
)

// linkLocalPrefix is RFC-3927 IPv4 link-local (covers AWS/GCP/Azure metadata).
var linkLocalPrefix = netip.MustParsePrefix("169.254.0.0/16")

// linkLocalV6Prefix is RFC-4291 IPv6 link-local.
var linkLocalV6Prefix = netip.MustParsePrefix("fe80::/10")

// loopbackPrefix is RFC-1122 IPv4 loopback.
var loopbackPrefix = netip.MustParsePrefix("127.0.0.0/8")

// NetworkScopeGuard validates and bounds the TCP scan scope.
type NetworkScopeGuard struct {
	MaxIPs         int
	BlockLinkLocal bool
}

// NewNetworkScopeGuard returns a guard with production-safe defaults: 100K IP
// cap and link-local/loopback blocking enabled.
func NewNetworkScopeGuard() *NetworkScopeGuard {
	return &NetworkScopeGuard{
		MaxIPs:         MaxScanIPsFromEnv(),
		BlockLinkLocal: !AllowLinkLocalFromEnv(),
	}
}

// Validate parses each CIDR, totals the IP count across all ranges, and
// returns an error if either the IP count cap or the link-local block is
// violated. It returns the total enumerable IP count (excluding network and
// broadcast addresses for /31-or-narrower IPv4 prefixes) on success.
//
// The check is purely arithmetic; no addresses are materialized into memory
// during validation.
func (g *NetworkScopeGuard) Validate(cidrs []string) (int, error) {
	if len(cidrs) == 0 {
		return 0, fmt.Errorf("scope is required: at least one CIDR must be provided")
	}

	total := 0
	for _, cidr := range cidrs {
		prefix, err := netip.ParsePrefix(cidr)
		if err != nil {
			return 0, fmt.Errorf("invalid CIDR %q: %w", cidr, err)
		}

		if g.BlockLinkLocal {
			if linkLocalPrefix.Overlaps(prefix) ||
				linkLocalV6Prefix.Overlaps(prefix) ||
				loopbackPrefix.Overlaps(prefix) ||
				prefix.Addr().IsLoopback() {
				return 0, fmt.Errorf(
					"CIDR %q intersects RFC-3927 link-local or loopback range "+
						"(set KITE_ALLOW_LINK_LOCAL=true to override)", cidr)
			}
		}

		count := cidrIPCount(prefix)
		total += count
		if total > g.MaxIPs {
			return total, fmt.Errorf(
				"scope exceeds maximum %d IPs (expanded so far: %d) — "+
					"split into smaller CIDRs or raise KITE_MAX_SCAN_IPS",
				g.MaxIPs, total)
		}
	}

	return total, nil
}

// cidrIPCount returns the number of probe-eligible addresses inside prefix.
// For IPv4 prefixes wider than /31 it excludes the network and broadcast
// addresses, matching the scanner's enumeration loop behavior. Values
// larger than int32 are saturated to (1<<30) to keep arithmetic within the
// integer range on 32-bit platforms; the scope cap is much smaller anyway.
func cidrIPCount(prefix netip.Prefix) int {
	bits := prefix.Bits()
	addrBits := 128
	if prefix.Addr().Is4() {
		addrBits = 32
	}
	hostBits := addrBits - bits
	if hostBits <= 0 {
		return 1
	}
	if hostBits >= 30 {
		return 1 << 30
	}
	count := 1 << hostBits
	if prefix.Addr().Is4() && bits < 31 {
		count -= 2
		if count < 0 {
			count = 0
		}
	}
	return count
}

// ValidatePorts checks each port number is in [1, 65535] and that the count
// does not exceed maxPorts. Pass maxPorts <= 0 to use DefaultMaxPortsPerScan.
func ValidatePorts(ports []int, maxPorts int) error {
	if len(ports) == 0 {
		return fmt.Errorf("port list is empty: at least one port must be configured")
	}
	if maxPorts <= 0 {
		maxPorts = DefaultMaxPortsPerScan
	}
	if len(ports) > maxPorts {
		return fmt.Errorf("too many ports: %d > max %d", len(ports), maxPorts)
	}
	for _, p := range ports {
		if p < MinPort || p > MaxPort {
			return fmt.Errorf("port %d out of valid range [%d, %d]", p, MinPort, MaxPort)
		}
	}
	return nil
}

// ClampConcurrency returns min(requested, hardCap). Values <= 0 fall back to
// a reasonable default of 32. Values above the cap are clamped silently with
// a structured warning so existing operator configs do not hard-fail.
func ClampConcurrency(requested int) int {
	hardCap := MaxScanConcurrencyFromEnv()
	if requested <= 0 {
		return 32
	}
	if requested > hardCap {
		slog.Warn("network scanner: max_concurrent clamped",
			"requested", requested,
			"effective", hardCap,
			"reason", "exceeds KITE_MAX_SCAN_CONCURRENCY hard cap")
		return hardCap
	}
	return requested
}

// MaxScanIPsFromEnv returns the IP cap, honoring KITE_MAX_SCAN_IPS when set
// to a positive integer; otherwise DefaultMaxScanIPs.
func MaxScanIPsFromEnv() int {
	return positiveIntEnv("KITE_MAX_SCAN_IPS", DefaultMaxScanIPs)
}

// MaxScanConcurrencyFromEnv returns the concurrency cap, honoring
// KITE_MAX_SCAN_CONCURRENCY when set to a positive integer; otherwise
// DefaultMaxScanConcurrency.
func MaxScanConcurrencyFromEnv() int {
	return positiveIntEnv("KITE_MAX_SCAN_CONCURRENCY", DefaultMaxScanConcurrency)
}

// AllowLinkLocalFromEnv reports whether KITE_ALLOW_LINK_LOCAL=true is set.
func AllowLinkLocalFromEnv() bool {
	return ParseBoolEnv("KITE_ALLOW_LINK_LOCAL")
}

func positiveIntEnv(key string, fallback int) int {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	n, err := strconv.Atoi(v)
	if err != nil || n <= 0 {
		slog.Warn("invalid integer env var, using default",
			"key", key, "value", sanitizeLog(v), "default", fallback)
		return fallback
	}
	return n
}
