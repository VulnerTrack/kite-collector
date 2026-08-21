package tunnel

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

// fakeBinDir builds a directory of fake tunnel binaries and pins PATH to
// exactly that directory, so Detect sees only what the test scripted —
// a host with the real tailscale installed must not leak into results.
func fakeBinDir(t *testing.T, bins map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, script := range bins {
		require.NoError(t, os.WriteFile(
			filepath.Join(dir, name),
			[]byte("#!/bin/sh\n"+script),
			0o755)) //#nosec G306 -- fake executable for tests
	}
	t.Setenv("PATH", dir)
	return dir
}

// --- providers.go: pure command builders ---------------------------------

func TestBuildCommand_ExactArgsPerProvider(t *testing.T) {
	t.Setenv("KITE_TUNNEL_AUTH_TOKEN", "")

	assert.Equal(t,
		[]string{"ngrok", "tcp", "4317", "--remote-addr=ingest.example.com:443", "--log=stdout", "--log-format=json"},
		BuildCommand(ProviderNgrok, "ingest.example.com:443", 4317, "KITE_TUNNEL_AUTH_TOKEN", nil))

	assert.Equal(t,
		[]string{"cloudflared", "access", "tcp", "--hostname", "ingest.example.com", "--url", "localhost:4317"},
		BuildCommand(ProviderCloudflared, "ingest.example.com", 4317, "", nil))

	assert.Equal(t,
		[]string{"bore", "local", "4317", "--to", "bore.example.com", "--port", "7835"},
		BuildCommand(ProviderBore, "bore.example.com:7835", 4317, "", nil))

	assert.Equal(t,
		[]string{"bore", "local", "4317", "--to", "bore.example.com", "--port", "443"},
		BuildCommand(ProviderBore, "bore.example.com", 4317, "", nil),
		"portless bore target defaults to 443")

	assert.Equal(t,
		[]string{"tailscale", "funnel", "--bg", "4317"},
		BuildCommand(ProviderTailscale, "ignored", 4317, "", nil))

	assert.Equal(t,
		[]string{"frpc", "tcp", "--server_addr=frp.example.com:7000", "--local_port=4317"},
		BuildCommand(ProviderFRP, "frp.example.com:7000", 4317, "", nil))

	assert.Equal(t,
		[]string{"rathole", "client", "--server", "rat.example.com:2333", "--local", "4317"},
		BuildCommand(ProviderRathole, "rat.example.com:2333", 4317, "", nil))

	assert.Nil(t, BuildCommand(ProviderName("warp"), "x", 1, "", nil),
		"unknown providers build nothing")
}

func TestBuildCommand_AuthTokenAndExtraArgs(t *testing.T) {
	t.Setenv("KITE_TUNNEL_AUTH_TOKEN", "sekrit")

	ngrok := BuildCommand(ProviderNgrok, "t:443", 1, "KITE_TUNNEL_AUTH_TOKEN", []string{"--region=us"})
	assert.Contains(t, ngrok, "--authtoken=sekrit")
	assert.Equal(t, "--region=us", ngrok[len(ngrok)-1], "extra args append last")

	frp := BuildCommand(ProviderFRP, "t:7000", 1, "KITE_TUNNEL_AUTH_TOKEN", nil)
	assert.Contains(t, frp, "--token=sekrit")

	// Empty env var name reads no token at all.
	assert.NotContains(t,
		strings.Join(BuildCommand(ProviderNgrok, "t:443", 1, "", nil), " "),
		"authtoken")
}

func TestSplitHostPort(t *testing.T) {
	h, p := splitHostPort("example.com:443")
	assert.Equal(t, "example.com", h)
	assert.Equal(t, "443", p)

	h, p = splitHostPort("example.com")
	assert.Equal(t, "example.com", h)
	assert.Empty(t, p, "portless address yields empty port, not an error")

	h, p = splitHostPort("host:with:colons:99")
	assert.Equal(t, "host:with:colons", h, "the LAST colon splits")
	assert.Equal(t, "99", p)
}

func TestEnvToken(t *testing.T) {
	assert.Empty(t, envToken(""), "empty name never reads the environment")
	t.Setenv("KITE_TUNNEL_TEST_TOKEN", "tok")
	assert.Equal(t, "tok", envToken("KITE_TUNNEL_TEST_TOKEN"))
	assert.Empty(t, envToken("KITE_TUNNEL_TEST_TOKEN_UNSET"))
}

// --- detect.go ------------------------------------------------------------

func TestSanitizeVersion_Boundary(t *testing.T) {
	assert.Equal(t, "v1.2.3", sanitizeVersion("  v1.2.3  "))
	long := strings.Repeat("x", 300)
	assert.Len(t, sanitizeVersion(long), 128, "hard cap at 128 chars")
	assert.Equal(t, strings.Repeat("x", 128), sanitizeVersion(long))
	assert.Empty(t, sanitizeVersion("   "))
}

func TestDetect_FindsOnlyPresentBinaries(t *testing.T) {
	fakeBinDir(t, map[string]string{
		"bore": `echo "bore 0.5.1"`,
		"frpc": `echo ""; echo "0.58.0"`, // first non-empty line wins
	})

	found := Detect(context.Background(), testLogger())
	require.Len(t, found, 2, "exactly the two scripted binaries are detected")

	byName := map[ProviderName]TunnelProvider{}
	for _, p := range found {
		byName[p.Name] = p
	}
	bore := byName[ProviderBore]
	assert.Equal(t, "bore 0.5.1", bore.Version)
	assert.False(t, bore.AuthRequired)
	assert.True(t, bore.SupportsTCP)
	assert.False(t, bore.SupportsHTTP, "bore is TCP-only")
	assert.NotEmpty(t, bore.BinaryPath)
	assert.False(t, bore.DetectedAt.IsZero())

	frp := byName[ProviderFRP]
	assert.Equal(t, "0.58.0", frp.Version, "leading blank line is skipped")
	assert.Equal(t, "KITE_TUNNEL_AUTH_TOKEN", frp.AuthEnvVar)
}

func TestDetect_VersionFailureIsNonFatal(t *testing.T) {
	fakeBinDir(t, map[string]string{"bore": "exit 3"})
	found := Detect(context.Background(), testLogger())
	require.Len(t, found, 1)
	assert.Empty(t, found[0].Version, "a broken --version leaves Version empty, not an error")
}

func TestDetect_EmptyPathFindsNothing(t *testing.T) {
	fakeBinDir(t, nil)
	assert.Empty(t, Detect(context.Background(), testLogger()))
}

func TestDetectProvider(t *testing.T) {
	fakeBinDir(t, map[string]string{"bore": `echo "bore 0.5.1"`})
	p := DetectProvider(context.Background(), ProviderBore, testLogger())
	require.NotNil(t, p)
	assert.Equal(t, ProviderBore, p.Name)
	assert.Nil(t, DetectProvider(context.Background(), ProviderNgrok, testLogger()),
		"absent providers resolve to nil, not an error")
}

// --- manager.go -----------------------------------------------------------

func TestManagerStart_DisabledIsNoOp(t *testing.T) {
	m := NewManager(ManagerConfig{Enabled: false, Provider: ProviderBore}, testLogger())
	addr, err := m.Start(context.Background())
	require.NoError(t, err)
	assert.Empty(t, addr, "disabled tunnel yields no address and no process")
	m.Stop() // must be safe without a Start
}

func TestManagerInstance_BeforeStart(t *testing.T) {
	m := NewManager(ManagerConfig{}, testLogger())
	assert.Nil(t, m.Instance(), "no instance exists before Start")
}

func TestManagerStart_HealthyWithListener(t *testing.T) {
	// A long-running fake bore stands in for the tunnel process, and a
	// local listener satisfies the health probe on the tunnel port.
	fakeBinDir(t, map[string]string{"bore": "sleep 60"})

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = ln.Close() }()
	port := uint16(ln.Addr().(*net.TCPAddr).Port) //#nosec G115 -- TCP ports fit uint16

	m := NewManager(ManagerConfig{
		Enabled:   true,
		Provider:  ProviderBore,
		Target:    "bore.example.com:7835",
		LocalPort: port,
	}, testLogger())

	addr, err := m.Start(context.Background())
	require.NoError(t, err)
	assert.Equal(t, fmt.Sprintf("localhost:%d", port), addr)

	inst := m.Instance()
	require.NotNil(t, inst)
	assert.Equal(t, StatusConnected, inst.Status)
	assert.Equal(t, ProviderBore, inst.Provider)
	assert.NotZero(t, inst.PID, "the subprocess pid is recorded")
	assert.False(t, inst.LastConnectedAt.IsZero())

	m.Stop()
	assert.Equal(t, StatusDisconnected, m.Instance().Status)
}

func TestManagerStart_UnhealthyPortReportsError(t *testing.T) {
	fakeBinDir(t, map[string]string{"bore": "sleep 60"})

	// Reserve a port then close it so nothing is listening.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := uint16(ln.Addr().(*net.TCPAddr).Port) //#nosec G115 -- TCP ports fit uint16
	require.NoError(t, ln.Close())

	m := NewManager(ManagerConfig{
		Enabled:   true,
		Provider:  ProviderBore,
		Target:    "bore.example.com:7835",
		LocalPort: port,
	}, testLogger())

	addr, err := m.Start(context.Background())
	require.Error(t, err, "no listener on the tunnel port must fail the health check")
	assert.Empty(t, addr)
	assert.Contains(t, err.Error(), "not healthy")
	assert.Equal(t, StatusDisconnected, m.Instance().Status,
		"unhealthy start degrades, the monitor keeps retrying")
	m.Stop()
}

func TestManagerStart_MissingBinaryFails(t *testing.T) {
	fakeBinDir(t, nil)
	m := NewManager(ManagerConfig{
		Enabled: true, Provider: ProviderBore, Target: "t:1", LocalPort: 1,
	}, testLogger())
	_, err := m.Start(context.Background())
	require.Error(t, err)
	assert.Equal(t, StatusFailed, m.Instance().Status)
}

func TestWaitHealthy_CancelledContext(t *testing.T) {
	m := NewManager(ManagerConfig{}, testLogger())
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := m.waitHealthy(ctx, "127.0.0.1:1")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cancelled")
}

func TestBackoff_ExponentialWithCap(t *testing.T) {
	m := NewManager(ManagerConfig{
		BackoffBase: 2 * time.Second,
		BackoffMax:  10 * time.Second,
	}, testLogger())
	assert.Equal(t, 2*time.Second, m.backoff(1), "first restart waits the base")
	assert.Equal(t, 4*time.Second, m.backoff(2))
	assert.Equal(t, 8*time.Second, m.backoff(3))
	assert.Equal(t, 10*time.Second, m.backoff(4), "capped exactly at max")
	assert.Equal(t, 10*time.Second, m.backoff(30), "large counts stay capped")
}

func TestBackoff_Defaults(t *testing.T) {
	m := NewManager(ManagerConfig{}, testLogger())
	assert.Equal(t, 5*time.Second, m.backoff(1), "zero base defaults to 5s")
	assert.Equal(t, 5*time.Minute, m.backoff(20), "zero max defaults to 5m")
}
