package safenet

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNetworkScopeGuard_Validate(t *testing.T) {
	t.Run("accepts a small /24 with default cap", func(t *testing.T) {
		g := &NetworkScopeGuard{MaxIPs: 100_000, BlockLinkLocal: true}
		count, err := g.Validate([]string{"192.168.1.0/24"})
		require.NoError(t, err)
		// /24 = 256 - 2 (network + broadcast) = 254
		assert.Equal(t, 254, count)
	})

	t.Run("rejects empty scope", func(t *testing.T) {
		g := &NetworkScopeGuard{MaxIPs: 100_000}
		_, err := g.Validate(nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "scope is required")
	})

	t.Run("rejects malformed CIDR", func(t *testing.T) {
		g := &NetworkScopeGuard{MaxIPs: 100_000}
		_, err := g.Validate([]string{"not-a-cidr"})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid CIDR")
	})

	t.Run("rejects scope exceeding cap", func(t *testing.T) {
		g := &NetworkScopeGuard{MaxIPs: 100_000, BlockLinkLocal: true}
		// /14 = 262144 hosts > 100K cap
		_, err := g.Validate([]string{"10.0.0.0/14"})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "scope exceeds maximum")
	})

	t.Run("rejects link-local 169.254.0.0/16 by default", func(t *testing.T) {
		g := &NetworkScopeGuard{MaxIPs: 100_000, BlockLinkLocal: true}
		_, err := g.Validate([]string{"169.254.0.0/16"})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "link-local")
	})

	t.Run("rejects AWS metadata /32 by default", func(t *testing.T) {
		g := &NetworkScopeGuard{MaxIPs: 100_000, BlockLinkLocal: true}
		_, err := g.Validate([]string{"169.254.169.254/32"})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "link-local")
	})

	t.Run("rejects loopback 127.0.0.0/8 by default", func(t *testing.T) {
		g := &NetworkScopeGuard{MaxIPs: 100_000, BlockLinkLocal: true}
		_, err := g.Validate([]string{"127.0.0.0/8"})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "link-local")
	})

	t.Run("rejects IPv6 link-local fe80::/10 by default", func(t *testing.T) {
		g := &NetworkScopeGuard{MaxIPs: 100_000, BlockLinkLocal: true}
		_, err := g.Validate([]string{"fe80::/120"})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "link-local")
	})

	t.Run("accepts link-local when BlockLinkLocal is false", func(t *testing.T) {
		g := &NetworkScopeGuard{MaxIPs: 100_000, BlockLinkLocal: false}
		count, err := g.Validate([]string{"169.254.169.254/32"})
		require.NoError(t, err)
		assert.Equal(t, 1, count)
	})

	t.Run("rejects /0 either via cap or link-local overlap", func(t *testing.T) {
		g := &NetworkScopeGuard{MaxIPs: 100_000, BlockLinkLocal: true}
		_, err := g.Validate([]string{"0.0.0.0/0"})
		require.Error(t, err)
		msg := err.Error()
		assert.True(t,
			strings.Contains(msg, "scope exceeds maximum") ||
				strings.Contains(msg, "link-local"),
			"expected /0 to be rejected by either guard, got: %s", msg)
	})

	t.Run("rejects /8 catastrophic scope (no link-local overlap)", func(t *testing.T) {
		g := &NetworkScopeGuard{MaxIPs: 100_000, BlockLinkLocal: true}
		_, err := g.Validate([]string{"10.0.0.0/8"})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "scope exceeds maximum")
	})

	t.Run("totals across multiple CIDRs", func(t *testing.T) {
		g := &NetworkScopeGuard{MaxIPs: 100_000, BlockLinkLocal: true}
		count, err := g.Validate([]string{
			"192.168.1.0/24",
			"10.0.0.0/24",
		})
		require.NoError(t, err)
		assert.Equal(t, 254*2, count)
	})
}

func TestValidatePorts(t *testing.T) {
	t.Run("accepts valid ports", func(t *testing.T) {
		require.NoError(t, ValidatePorts([]int{22, 80, 443}, 0))
	})

	t.Run("rejects port 0", func(t *testing.T) {
		err := ValidatePorts([]int{0}, 0)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "out of valid range")
	})

	t.Run("rejects port 65536", func(t *testing.T) {
		err := ValidatePorts([]int{65536}, 0)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "out of valid range")
	})

	t.Run("rejects negative ports", func(t *testing.T) {
		err := ValidatePorts([]int{-1}, 0)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "out of valid range")
	})

	t.Run("rejects empty list", func(t *testing.T) {
		err := ValidatePorts(nil, 0)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "empty")
	})

	t.Run("rejects too many ports", func(t *testing.T) {
		ports := make([]int, DefaultMaxPortsPerScan+1)
		for i := range ports {
			ports[i] = i + 1
		}
		err := ValidatePorts(ports, 0)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "too many ports")
	})

	t.Run("respects custom maxPorts", func(t *testing.T) {
		err := ValidatePorts([]int{22, 80, 443}, 2)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "too many ports")
	})

	t.Run("accepts edge ports 1 and 65535", func(t *testing.T) {
		require.NoError(t, ValidatePorts([]int{1, 65535}, 0))
	})
}

func TestClampConcurrency(t *testing.T) {
	t.Run("returns requested when within cap", func(t *testing.T) {
		assert.Equal(t, 64, ClampConcurrency(64))
	})

	t.Run("clamps when exceeding cap", func(t *testing.T) {
		t.Setenv("KITE_MAX_SCAN_CONCURRENCY", "")
		assert.Equal(t, DefaultMaxScanConcurrency, ClampConcurrency(10_000))
	})

	t.Run("falls back to default for non-positive", func(t *testing.T) {
		assert.Equal(t, 32, ClampConcurrency(0))
		assert.Equal(t, 32, ClampConcurrency(-5))
	})

	t.Run("honors KITE_MAX_SCAN_CONCURRENCY env var", func(t *testing.T) {
		t.Setenv("KITE_MAX_SCAN_CONCURRENCY", "128")
		assert.Equal(t, 128, ClampConcurrency(1000))
	})
}

func TestMaxScanIPsFromEnv(t *testing.T) {
	t.Run("default when unset", func(t *testing.T) {
		t.Setenv("KITE_MAX_SCAN_IPS", "")
		assert.Equal(t, DefaultMaxScanIPs, MaxScanIPsFromEnv())
	})

	t.Run("override when valid", func(t *testing.T) {
		t.Setenv("KITE_MAX_SCAN_IPS", "250000")
		assert.Equal(t, 250000, MaxScanIPsFromEnv())
	})

	t.Run("default when invalid", func(t *testing.T) {
		t.Setenv("KITE_MAX_SCAN_IPS", "garbage")
		assert.Equal(t, DefaultMaxScanIPs, MaxScanIPsFromEnv())
	})

	t.Run("default when zero", func(t *testing.T) {
		t.Setenv("KITE_MAX_SCAN_IPS", "0")
		assert.Equal(t, DefaultMaxScanIPs, MaxScanIPsFromEnv())
	})
}

func TestAllowLinkLocalFromEnv(t *testing.T) {
	t.Run("default false", func(t *testing.T) {
		t.Setenv("KITE_ALLOW_LINK_LOCAL", "")
		assert.False(t, AllowLinkLocalFromEnv())
	})

	t.Run("true when KITE_ALLOW_LINK_LOCAL=true", func(t *testing.T) {
		t.Setenv("KITE_ALLOW_LINK_LOCAL", "true")
		assert.True(t, AllowLinkLocalFromEnv())
	})
}
