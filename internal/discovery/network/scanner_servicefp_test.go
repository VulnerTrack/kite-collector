package network

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vulnertrack/kite-collector/internal/discovery/network/servicefp"
)

func TestFingerprintServices_RecognisesHTTP(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	host, portStr, err := net.SplitHostPort(srv.Listener.Addr().String())
	require.NoError(t, err)
	ap := netip.MustParseAddrPort(net.JoinHostPort(host, portStr))

	results := fingerprintServiceResults(context.Background(), servicefp.New(2*time.Second), ap.Addr(), []int{int(ap.Port())})
	require.Len(t, results, 1, "the live HTTP port is recognised")
	labels := servicesTagLabels(results)
	require.Len(t, labels, 1, "one label per recognised service")
	assert.Contains(t, labels[0], "/http", "label is <port>/<service>")
}

func TestFingerprintServices_NilOrEmptyIsNil(t *testing.T) {
	assert.Nil(t, fingerprintServiceResults(context.Background(), nil, netip.MustParseAddr("127.0.0.1"), []int{22}))
	assert.Nil(t, fingerprintServiceResults(context.Background(), servicefp.New(time.Second), netip.MustParseAddr("127.0.0.1"), nil))
	assert.Nil(t, servicesTagLabels(nil))
}

func TestWithServicesTag(t *testing.T) {
	// Empty tags -> a fresh object with the services.
	got := withServicesTag("", []string{"22/ssh OpenSSH_8.9"})
	var m map[string]any
	require.NoError(t, json.Unmarshal([]byte(got), &m))
	assert.Contains(t, m, "network_scan_services")

	// Existing tags are preserved and the services added alongside.
	got2 := withServicesTag(`{"deployment_os_inferred":true,"network_scan_open_ports":[22]}`, []string{"22/ssh"})
	require.NoError(t, json.Unmarshal([]byte(got2), &m))
	assert.Equal(t, true, m["deployment_os_inferred"], "existing keys survive the merge")
	assert.Contains(t, m, "network_scan_services")

	// Malformed input doesn't panic; services still land.
	got3 := withServicesTag("not json", []string{"80/http"})
	require.NoError(t, json.Unmarshal([]byte(got3), &m))
	assert.Contains(t, m, "network_scan_services")
}
