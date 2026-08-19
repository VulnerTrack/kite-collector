package vpn

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Two IKE SAs: one with a bare-FQDN identity, one with a certificate DN
// identity (which must NOT be used as a hostname) plus child subnets.
const swanctlFixture = `gw-remote: #1, ESTABLISHED, IKEv2, 8f3a2b:2a1b3c
  local  'moon.example.org' @ 192.0.2.1[500]
  remote 'sun.example.org' @ 203.0.113.9[500]
  AES_GCM_16-256/PRF_HMAC_SHA2_256/ECP_256
  established 3600s ago, rekeying in 10000s
  child: net-net, INSTALLED, TUNNEL
    local  10.1.0.0/16
    remote 10.2.0.0/16 10.3.0.0/16

road-warrior: #2, ESTABLISHED, IKEv2, aa11:bb22
  local  '192.0.2.1' @ 192.0.2.1[4500]
  remote 'C=CH, O=Example, CN=laptop.example.org' @ 198.51.100.44[4500]
`

func TestParseSwanctlSAs(t *testing.T) {
	peers := parseSwanctlSAs(swanctlFixture)
	require.Len(t, peers, 2)

	gw, ok := findPeer(peers, byHostname("sun.example.org"))
	require.True(t, ok, "bare-FQDN identity used as hostname")
	assert.Equal(t, "ipsec", gw.VPNType)
	assert.True(t, gw.Online, "ESTABLISHED ⇒ online")
	assert.Equal(t, "203.0.113.9:500", gw.Endpoint)
	assert.Equal(t, []string{"203.0.113.9"}, gw.Addresses)
	assert.Equal(t, "gw-remote", gw.Tags["connection"])
	assert.Equal(t, "IKEv2", gw.Tags["ike_version"])
	assert.Equal(t, "sun.example.org", gw.Tags["remote_id"])
	assert.Equal(t, []string{"10.2.0.0/16", "10.3.0.0/16"}, gw.Tags["remote_subnets"])

	// The DN-identity SA: hostname must fall back to the address.
	rw, ok := findPeer(peers, byHostname("198.51.100.44"))
	require.True(t, ok, "certificate-DN identity is NOT used as a hostname")
	assert.Equal(t, "198.51.100.44:4500", rw.Endpoint)
	assert.Equal(t, "C=CH, O=Example, CN=laptop.example.org", rw.Tags["remote_id"])
}

func TestParseSwanctlSAs_Empty(t *testing.T) {
	assert.Empty(t, parseSwanctlSAs(""))
	assert.Empty(t, parseSwanctlSAs("no security associations found\n"))
}

func TestIPSecHostname(t *testing.T) {
	assert.Equal(t, "sun.example.org", ipsecHostname("sun.example.org", "203.0.113.9"))
	assert.Equal(t, "203.0.113.9", ipsecHostname("C=CH, CN=x", "203.0.113.9"), "DN → address")
	assert.Equal(t, "203.0.113.9", ipsecHostname("has space", "203.0.113.9"))
	assert.Equal(t, "203.0.113.9", ipsecHostname("", "203.0.113.9"))
}

func TestIPSecEnumerate(t *testing.T) {
	e := newIPSecEnumerator()
	e.lookPath = func(string) (string, error) { return "", errors.New("nope") }
	peers, err := e.enumerate(context.Background(), nil)
	require.NoError(t, err)
	assert.Nil(t, peers)

	e.lookPath = func(string) (string, error) { return "/usr/sbin/swanctl", nil }
	e.run = func(_ context.Context, _ string, args ...string) ([]byte, error) {
		assert.Equal(t, []string{"--list-sas"}, args)
		return []byte(swanctlFixture), nil
	}
	peers, err = e.enumerate(context.Background(), nil)
	require.NoError(t, err)
	assert.Len(t, peers, 2)
}
