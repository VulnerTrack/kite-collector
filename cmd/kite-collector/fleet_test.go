package main

import (
	"archive/zip"
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRunFleetDiscoverPrintsComputers(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "/api/v1/fleet/discover", r.URL.Path)
		assert.Equal(t, "application/json", r.Header.Get("Accept"))
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
          "network":"192.168.1.0/24","completed_at":"2026-08-15 06:00 UTC",
          "found":2,"inserted":1,"updated":1,
          "computers":[{"hostname":"ROBERTO-PC","address":"192.168.1.75",
          "os":"windows","arch":"amd64","discovery_source":"wsdiscovery","compatible":true}]
        }`))
	}))
	t.Cleanup(server.Close)

	cmd := &cobra.Command{}
	output := &strings.Builder{}
	cmd.SetOut(output)
	require.NoError(t, runFleetDiscover(cmd, server.URL, time.Second, false))
	assert.Contains(t, output.String(), "ROBERTO-PC")
	assert.Contains(t, output.String(), "192.168.1.75")
	assert.Contains(t, output.String(), "windows/amd64")
	assert.Contains(t, output.String(), "ready")
}

func TestRunFleetDiscoverSurfacesDashboardError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusConflict)
		_, _ = w.Write([]byte(`{"error":"network discovery is already running"}`))
	}))
	t.Cleanup(server.Close)

	cmd := &cobra.Command{}
	cmd.SetOut(&strings.Builder{})
	err := runFleetDiscover(cmd, server.URL, time.Second, false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "already running")
}

func TestFleetDiscoverCommandIsRegistered(t *testing.T) {
	cmd, _, err := newRootCmd().Find([]string{"fleet", "discover"})
	require.NoError(t, err)
	assert.Equal(t, "discover", cmd.Name())
	assert.NoError(t, cmd.ValidateArgs([]string{}))
}

func TestFleetHelpShowsDiscoverBeforeDeploy(t *testing.T) {
	cmd := newFleetCmd()
	output := &strings.Builder{}
	cmd.SetOut(output)
	cmd.SetArgs([]string{"--help"})
	require.NoError(t, cmd.Execute())

	help := output.String()
	discover := strings.Index(help, "Step 1 — Discover computers:")
	deploy := strings.Index(help, "Step 2 — Deploy collectors:")
	require.NotEqual(t, -1, discover)
	require.NotEqual(t, -1, deploy)
	assert.Less(t, discover, deploy)
}

func TestRunFleetEnrollGeneratesPackageForNamedComputer(t *testing.T) {
	bundle := testFleetBundle(t, "#!/usr/bin/env bash\necho deployed\n")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/fleet/discover":
			assert.Equal(t, http.MethodGet, r.Method)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"computers":[
                  {"hostname":"192.168.1.75","address":"192.168.1.75","os":"windows","arch":"amd64","discovery_source":"network_scan","target":"192.168.1.75,windows,amd64,192.168.1.75","compatible":true},
                  {"hostname":"ROBERTO-PC","address":"192.168.1.75","os":"windows","arch":"amd64","discovery_source":"network_scan","target":"ROBERTO-PC,windows,amd64,192.168.1.75","compatible":true}
                ]}`))
		case "/api/v1/fleet/package":
			require.NoError(t, r.ParseForm())
			assert.Equal(t, []string{"ROBERTO-PC,windows,amd64,192.168.1.75"}, r.Form["discovered_target"])
			w.Header().Set("Content-Type", "application/zip")
			_, _ = w.Write(bundle)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)

	cmd := &cobra.Command{}
	output := &strings.Builder{}
	cmd.SetOut(output)
	cmd.SetErr(output)
	require.NoError(t, runFleetDeploy(cmd, server.URL, time.Second, "roberto-pc", false, ""))
	assert.Contains(t, output.String(), "ROBERTO-PC")
	assert.Contains(t, output.String(), "deployed")
	assert.Contains(t, output.String(), "Deployment completed for 1 computer")
}

func TestRunFleetEnrollPackageOnlyWritesPrivateZIP(t *testing.T) {
	bundle := testFleetBundle(t, "#!/usr/bin/env bash\nexit 0\n")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/fleet/discover" {
			assert.Equal(t, http.MethodGet, r.Method)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"computers":[{"hostname":"ROBERTO-PC","address":"192.168.1.75","os":"windows","arch":"amd64","discovery_source":"network_scan","target":"ROBERTO-PC,windows,amd64,192.168.1.75","compatible":true}]}`))
			return
		}
		w.Header().Set("Content-Type", "application/zip")
		_, _ = w.Write(bundle)
	}))
	t.Cleanup(server.Close)

	path := filepath.Join(t.TempDir(), "deployment.zip")
	cmd := &cobra.Command{}
	cmd.SetOut(&strings.Builder{})
	require.NoError(t, runFleetDeploy(cmd, server.URL, time.Second, "ROBERTO-PC", true, path))
	info, err := os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())
}

func TestRunFleetEnrollWithoutArgumentPackagesLocalAndRemoteComputers(t *testing.T) {
	bundle := testFleetBundle(t, "#!/usr/bin/env bash\nexit 0\n")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/fleet/discover" {
			assert.Equal(t, http.MethodGet, r.Method)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"computers":[
                  {"hostname":"controller","address":"192.168.1.81","os":"linux","arch":"amd64","discovery_source":"local_controller","target":"controller,linux,amd64,local","compatible":true},
                  {"hostname":"192.168.1.75","address":"192.168.1.75","os":"windows","arch":"amd64","discovery_source":"network_scan","target":"192.168.1.75,windows,amd64,192.168.1.75","compatible":true},
                  {"hostname":"DESKTOP-A","address":"192.168.1.75","os":"windows","arch":"amd64","discovery_source":"network_scan","target":"DESKTOP-A,windows,amd64,192.168.1.75","compatible":true},
                  {"hostname":"SERVER-B","address":"192.168.1.90","os":"linux","arch":"amd64","discovery_source":"network_scan","target":"SERVER-B,linux,amd64,192.168.1.90","compatible":true}
                ]}`))
			return
		}
		require.NoError(t, r.ParseForm())
		assert.Equal(t, []string{
			"controller,linux,amd64,local",
			"DESKTOP-A,windows,amd64,192.168.1.75",
			"SERVER-B,linux,amd64,192.168.1.90",
		}, r.Form["discovered_target"])
		w.Header().Set("Content-Type", "application/zip")
		_, _ = w.Write(bundle)
	}))
	t.Cleanup(server.Close)

	cmd := &cobra.Command{}
	output := &strings.Builder{}
	cmd.SetOut(output)
	path := filepath.Join(t.TempDir(), "deployment.zip")
	require.NoError(t, runFleetDeploy(cmd, server.URL, time.Second, "", true, path))
	assert.Contains(t, output.String(), "Computers selected for deployment: 3")
	assert.Contains(t, output.String(), "DESKTOP-A")
	assert.Contains(t, output.String(), "SERVER-B")
	assert.Contains(t, output.String(), "controller")
}

func TestSelectFleetComputerPrefersExactHostnameOverDuplicateAddress(t *testing.T) {
	computers := []fleetDiscoverComputer{
		{Hostname: "192.168.1.75", Address: "192.168.1.75", DiscoverySource: "network_scan", Compatible: true, Target: "first"},
		{Hostname: "ROBERTO-PC", Address: "192.168.1.75", DiscoverySource: "network_scan", Compatible: true, Target: "second"},
	}
	target, err := selectFleetComputer(computers, "192.168.1.75")
	require.NoError(t, err)
	assert.Equal(t, "first", target.Target)
}

func TestRequestFleetPackageReportsSignInURL(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Location", "/kite-login?dashboard=%2Ffleet")
		w.WriteHeader(http.StatusSeeOther)
	}))
	t.Cleanup(server.Close)

	_, err := requestFleetPackage(t.Context(), server.URL, []string{"ROBERTO-PC,windows,amd64,192.168.1.75"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), server.URL+"/kite-login?dashboard=%2Ffleet")
	var signIn *fleetSignInRequiredError
	require.ErrorAs(t, err, &signIn)
}

func TestRunFleetDeployOpensLoginWaitsAndRetriesPackage(t *testing.T) {
	bundle := testFleetBundle(t, "#!/usr/bin/env bash\nexit 0\n")
	packageRequests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/fleet/discover":
			_, _ = w.Write([]byte(`{"computers":[{"hostname":"DESKTOP-A","address":"192.168.1.75","os":"windows","arch":"amd64","discovery_source":"network_scan","target":"DESKTOP-A,windows,amd64,192.168.1.75","compatible":true}]}`))
		case "/api/v1/fleet/package":
			packageRequests++
			if packageRequests == 1 {
				w.Header().Set("Location", "/kite-login?dashboard=%2Ffleet&wait_id=test-wait")
				w.WriteHeader(http.StatusSeeOther)
				return
			}
			w.Header().Set("Content-Type", "application/zip")
			_, _ = w.Write(bundle)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)

	previousOpen, previousWait := openFleetLogin, waitFleetLogin
	t.Cleanup(func() {
		openFleetLogin, waitFleetLogin = previousOpen, previousWait
	})
	openedURL := ""
	openFleetLogin = func(rawURL string) { openedURL = rawURL }
	waitFleetLogin = func(_ context.Context, baseURL, waitID string) error {
		assert.Equal(t, server.URL, baseURL)
		assert.Equal(t, "test-wait", waitID)
		return nil
	}

	cmd := &cobra.Command{}
	output := &strings.Builder{}
	cmd.SetOut(output)
	path := filepath.Join(t.TempDir(), "deployment.zip")
	require.NoError(t, runFleetDeploy(cmd, server.URL, time.Second, "", true, path))
	assert.Equal(t, 2, packageRequests)
	assert.Contains(t, openedURL, "/kite-login?")
	assert.Contains(t, output.String(), "Waiting for sign-in")
	assert.Contains(t, output.String(), "Sign-in completed")
}

func TestFleetDeployCommandIsRegistered(t *testing.T) {
	cmd, _, err := newRootCmd().Find([]string{"fleet", "deploy"})
	require.NoError(t, err)
	assert.Equal(t, "deploy", cmd.Name())
	assert.NoError(t, cmd.ValidateArgs([]string{}))
	assert.NoError(t, cmd.ValidateArgs([]string{"ROBERTO-PC"}))
}

func TestFleetEnrollmentComputersReturnsAllRemoteComputersAndDeduplicates(t *testing.T) {
	computers := []fleetDiscoverComputer{
		{Hostname: "controller", DiscoverySource: "local_controller", Compatible: true, Target: "local"},
		{Hostname: "192.168.1.75", Address: "192.168.1.75", OS: "windows", Arch: "amd64", DiscoverySource: "network_scan", Compatible: true, Target: "duplicate"},
		{Hostname: "ROBERTO-PC", Address: "192.168.1.75", OS: "windows", Arch: "amd64", DiscoverySource: "network_scan", Compatible: true, Target: "remote"},
		{Hostname: "SERVER-01", Address: "192.168.1.90", OS: "linux", Arch: "amd64", DiscoverySource: "network_scan", Compatible: true, Target: "server"},
	}
	targets := fleetEnrollmentComputers(computers)
	require.Len(t, targets, 3)
	assert.Equal(t, "controller", targets[0].Hostname)
	assert.Equal(t, "ROBERTO-PC", targets[1].Hostname)
	assert.Equal(t, "SERVER-01", targets[2].Hostname)
}

func TestFleetEnrollmentComputersAcceptsLocalControllerOnly(t *testing.T) {
	computers := []fleetDiscoverComputer{
		{Hostname: "controller", DiscoverySource: "local_controller", Compatible: true, Target: "local"},
	}
	targets := fleetEnrollmentComputers(computers)
	require.Len(t, targets, 1)
	assert.Equal(t, "controller", targets[0].Hostname)
}

func TestFleetEnrollmentComputersRejectsStaleIdentityAddress(t *testing.T) {
	computers := []fleetDiscoverComputer{
		{Hostname: "DESKTOP-OLD", Address: "192.168.1.110", OS: "windows", Arch: "amd64", DiscoverySource: "wsdiscovery", Compatible: true, Target: "stale"},
		{Hostname: "192.168.100.115", Address: "192.168.100.115", OS: "windows", Arch: "amd64", DiscoverySource: "network_scan", Compatible: true, Target: "current"},
	}
	targets := fleetEnrollmentComputers(computers)
	require.Len(t, targets, 1)
	assert.Equal(t, "192.168.100.115", targets[0].Address)
}

func testFleetBundle(t *testing.T, deployScript string) []byte {
	t.Helper()
	var buffer bytes.Buffer
	zw := zip.NewWriter(&buffer)
	header := &zip.FileHeader{Name: "deploy.sh", Method: zip.Deflate}
	header.SetMode(0o700)
	entry, err := zw.CreateHeader(header)
	require.NoError(t, err)
	_, err = entry.Write([]byte(deployScript))
	require.NoError(t, err)
	require.NoError(t, zw.Close())
	return buffer.Bytes()
}
