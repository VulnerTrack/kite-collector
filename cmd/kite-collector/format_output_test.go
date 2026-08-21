package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/csv"
	"encoding/json"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vulnertrack/kite-collector/internal/autodiscovery"
	"github.com/vulnertrack/kite-collector/internal/config"
	"github.com/vulnertrack/kite-collector/internal/dashboard"
	"github.com/vulnertrack/kite-collector/internal/model"
)

func TestFormatJSON_IndentedObject(t *testing.T) {
	out := captureStdout(t, func() {
		require.NoError(t, formatJSON(map[string]int{"total": 3}))
	})
	assert.Equal(t, "{\n  \"total\": 3\n}\n", out)
}

func TestFormatTable_PrefersOSVersionOverFamily(t *testing.T) {
	withVersion := diffFixtureMachine("tbl-a", model.MachineTypeServer)
	withoutVersion := diffFixtureMachine("tbl-b", model.MachineTypeServer)
	withoutVersion.OSVersion = ""

	out := captureStdout(t, func() {
		formatTable([]model.Machine{withVersion, withoutVersion})
	})

	assert.Contains(t, out, "HOSTNAME")
	assert.Contains(t, out, "LAST SEEN")
	assert.Contains(t, out, "ubuntu-24.04", "OSVersion wins when present")
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	require.Len(t, lines, 3, "header + one row per machine")
	assert.Contains(t, lines[2], "linux", "OSFamily used when OSVersion empty")
	assert.Contains(t, lines[1], "2026-08-01T12:00:00Z")
}

func TestFormatCSV_ExactColumns(t *testing.T) {
	m := diffFixtureMachine("csv-host", model.MachineTypeServer)
	m.FirstSeenAt = time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)

	out := captureStdout(t, func() { formatCSV([]model.Machine{m}) })

	records, err := csv.NewReader(strings.NewReader(out)).ReadAll()
	require.NoError(t, err)
	require.Len(t, records, 2)
	assert.Equal(t, []string{
		"id", "hostname", "machine_type", "os_family", "os_version",
		"is_authorized", "is_managed", "environment", "owner",
		"discovery_source", "first_seen_at", "last_seen_at",
	}, records[0])
	assert.Equal(t, []string{
		m.ID.String(), "csv-host", "server", "linux", "ubuntu-24.04",
		"authorized", "managed", "prod", "infra", "network",
		"2026-07-01T00:00:00Z", "2026-08-01T12:00:00Z",
	}, records[1])
}

func TestAssessCompliance_EmptyInventoryIsNotAligned(t *testing.T) {
	frameworks := assessCompliance(&htmlReportData{})

	require.Len(t, frameworks, 3)
	assert.Equal(t, "CIS Control 1", frameworks[0].Name)
	assert.Equal(t, "NIST SP 1800-5", frameworks[1].Name)
	assert.Equal(t, "ISO 27001 A.8", frameworks[2].Name)
	for _, f := range frameworks {
		assert.Equal(t, "Not Aligned", f.Status, "%s must be Not Aligned on empty inventory", f.Name)
	}
}

func TestAssessCompliance_FullCoverageAligns(t *testing.T) {
	// 9/10 classified and managed is exactly the 0.9 boundary; zero
	// unauthorized machines also satisfies ISO.
	frameworks := assessCompliance(&htmlReportData{
		TotalMachines:   10,
		AuthorizedCount: 9,
		ManagedCount:    9,
	})
	assert.Equal(t, "Aligned", frameworks[0].Status)
	assert.Equal(t, "Aligned", frameworks[1].Status)
	assert.Equal(t, "Aligned", frameworks[2].Status)
}

func TestAssessCompliance_UnauthorizedMachineBreaksISOOnly(t *testing.T) {
	frameworks := assessCompliance(&htmlReportData{
		TotalMachines:     10,
		AuthorizedCount:   8,
		UnauthorizedCount: 1,
		ManagedCount:      9,
	})
	assert.Equal(t, "Aligned", frameworks[0].Status, "CIS looks at classification only")
	assert.Equal(t, "Aligned", frameworks[1].Status)
	assert.Equal(t, "Partial", frameworks[2].Status, "one unauthorized machine blocks ISO alignment")
}

func TestAssessCompliance_PartialCoverage(t *testing.T) {
	frameworks := assessCompliance(&htmlReportData{
		TotalMachines:   10,
		AuthorizedCount: 1,
	})
	assert.Equal(t, "Partial", frameworks[0].Status)
	assert.Equal(t, "Partial", frameworks[1].Status)
	assert.Equal(t, "Partial", frameworks[2].Status)
}

func TestFormatHTMLReport_SelfContainedDocument(t *testing.T) {
	dbPath := seedDiffDB(t, t.TempDir()) // empty, migrated store for ListEvents
	encStore, err := openSQLiteStore(dbPath, config.IdentityConfig{})
	require.NoError(t, err)
	t.Cleanup(func() { _ = encStore.Close() })

	machines := []model.Machine{
		diffFixtureMachine("html-a", model.MachineTypeServer),
	}
	out := captureStdout(t, func() {
		require.NoError(t, formatHTMLReport(context.Background(), encStore.Store, machines, nil))
	})

	assert.Contains(t, out, "<!DOCTYPE html>")
	assert.Contains(t, out, "Kite Collector - Machine Compliance Report")
	assert.Contains(t, out, "html-a")
	assert.Contains(t, out, "CIS Control 1")
	assert.NotContains(t, out, "src=\"http", "report must not reference external resources")
}

func TestFormatDiscoveredServices_CountsAndCredentialHints(t *testing.T) {
	services := []autodiscovery.DiscoveredService{
		{Name: "docker", DisplayName: "Docker", Endpoint: "unix:///var/run/docker.sock", Status: "ready"},
		{
			Name: "wazuh", DisplayName: "Wazuh", Endpoint: "https://127.0.0.1:55000", Status: "needs_credentials",
			Credentials: []string{"WAZUH_USER", "WAZUH_PASSWORD"},
		},
		{Name: "clickhouse", DisplayName: "ClickHouse", Endpoint: "127.0.0.1:8123", Status: "detected"},
	}

	out := captureStdout(t, func() { formatDiscoveredServices(services) })

	assert.Contains(t, out, "Infrastructure Auto-Discovery")
	assert.Contains(t, out, "SERVICE")
	assert.Contains(t, out, "unix:///var/run/docker.sock")
	assert.Contains(t, out, "Ready: 1 | Need credentials: 1")
	assert.Contains(t, out, "# Wazuh")
	assert.Contains(t, out, "export WAZUH_USER=...")
	assert.Contains(t, out, "export WAZUH_PASSWORD=...")
	assert.Contains(t, out, "Then run: kite-collector scan --auto")
}

func TestFormatDiscoveredServices_NothingReadyOmitsScanHint(t *testing.T) {
	out := captureStdout(t, func() {
		formatDiscoveredServices([]autodiscovery.DiscoveredService{
			{Name: "clickhouse", Endpoint: "127.0.0.1:8123", Status: "detected"},
		})
	})
	assert.Contains(t, out, "Ready: 0 | Need credentials: 0")
	assert.NotContains(t, out, "scan --auto")
	assert.NotContains(t, out, "To enable all discovered services")
}

func TestPrintOTLPResults_TableMarksFailuresAndErrors(t *testing.T) {
	stages := []otlpCheckStage{
		{Name: "tcp-dial", OK: true, DurMS: 12},
		{Name: "tls-handshake", OK: false, DurMS: 40, Error: "handshake refused"},
	}

	var err error
	out := captureStdout(t, func() { err = printOTLPResults(stages, false) })

	require.Error(t, err)
	assert.Equal(t, "one or more connectivity checks failed", err.Error())
	assert.Contains(t, out, "STAGE")
	assert.Contains(t, out, "✓")
	assert.Contains(t, out, "✗")
	assert.Contains(t, out, "handshake refused")
	assert.Contains(t, out, "-", "empty detail renders as a dash")
}

func TestPrintOTLPResults_JSONAllOK(t *testing.T) {
	stages := []otlpCheckStage{{Name: "tcp-dial", OK: true, DurMS: 3}}

	var err error
	out := captureStdout(t, func() { err = printOTLPResults(stages, true) })

	require.NoError(t, err)
	var got []otlpCheckStage
	require.NoError(t, json.Unmarshal([]byte(out), &got))
	assert.Equal(t, stages, got)
}

func TestDashboardOAuthOptions(t *testing.T) {
	assert.Equal(t, dashboard.OAuthOptions{}, dashboardOAuthOptions(nil))

	cfg := &config.Config{}
	cfg.OAuth.SupabaseURL = "https://x.supabase.co"
	cfg.OAuth.SupabaseAnonKey = "anon"
	cfg.OAuth.TurnstileSiteKey = "ts"
	cfg.OAuth.AuthorizeURL = "https://auth.example/authorize"
	cfg.OAuth.ClientID = "kite-cli"
	cfg.OAuth.Scope = "openid"
	cfg.OAuth.RedirectPath = "/cb"

	assert.Equal(t, dashboard.OAuthOptions{
		SupabaseURL:      "https://x.supabase.co",
		SupabaseAnonKey:  "anon",
		TurnstileSiteKey: "ts",
		AuthorizeURL:     "https://auth.example/authorize",
		ClientID:         "kite-cli",
		Scope:            "openid",
		RedirectPath:     "/cb",
	}, dashboardOAuthOptions(cfg))
}

func TestIsHeadless_LinuxDependsOnDisplayEnv(t *testing.T) {
	t.Setenv("DISPLAY", "")
	t.Setenv("WAYLAND_DISPLAY", "")
	assert.True(t, isHeadless())

	t.Setenv("DISPLAY", ":0")
	assert.False(t, isHeadless())

	t.Setenv("DISPLAY", "")
	t.Setenv("WAYLAND_DISPLAY", "wayland-0")
	assert.False(t, isHeadless())
}

func TestPromptLine_TrimsAndEchoesLabel(t *testing.T) {
	var out bytes.Buffer
	in := bufio.NewReader(strings.NewReader("  value with spaces  \nrest"))

	got := promptLine(&out, in, "Agent code: ")

	assert.Equal(t, "Agent code: ", out.String())
	assert.Equal(t, "value with spaces", got)

	// EOF with no newline still returns the trimmed remainder.
	got = promptLine(&out, bufio.NewReader(strings.NewReader("tail")), "x: ")
	assert.Equal(t, "tail", got)
}

func TestCurrentOSUser_MatchesOSUserPackage(t *testing.T) {
	u, err := user.Current()
	require.NoError(t, err, "test environment must resolve the current user")
	assert.Equal(t, u.Username, currentOSUser())
}

func TestPrintFakePrompt_EndsWithCwdPrompt(t *testing.T) {
	cwd, err := os.Getwd()
	require.NoError(t, err)

	out := captureStdout(t, func() { printFakePrompt() })

	// Non-PowerShell (linux test env) shape: "\n<cwd>> ".
	assert.Equal(t, "\n"+cwd+"> ", out)
}

func TestLoadEnvFile_ParsesQuotesCommentsAndPrecedence(t *testing.T) {
	envFile := filepath.Join(t.TempDir(), ".env")
	require.NoError(t, os.WriteFile(envFile, []byte(strings.Join([]string{
		"# a comment",
		"",
		"KITE_TEST_PLAIN=plain-value",
		`KITE_TEST_DQ="double quoted"`,
		"KITE_TEST_SQ='single quoted'",
		"KITE_TEST_KEEP=from-file",
		"not-a-pair",
		"  KITE_TEST_SPACED  =  padded  ",
	}, "\n")), 0o600))

	// Register cleanup and pin the pre-existing value for the precedence check.
	for _, k := range []string{"KITE_TEST_PLAIN", "KITE_TEST_DQ", "KITE_TEST_SQ", "KITE_TEST_SPACED"} {
		t.Setenv(k, "")
	}
	t.Setenv("KITE_TEST_KEEP", "from-env")

	loadEnvFile(envFile, filepath.Join(t.TempDir(), "missing.env"))

	assert.Equal(t, "plain-value", os.Getenv("KITE_TEST_PLAIN"))
	assert.Equal(t, "double quoted", os.Getenv("KITE_TEST_DQ"))
	assert.Equal(t, "single quoted", os.Getenv("KITE_TEST_SQ"))
	assert.Equal(t, "padded", os.Getenv("KITE_TEST_SPACED"))
	assert.Equal(t, "from-env", os.Getenv("KITE_TEST_KEEP"),
		"a variable already set in the environment must win over the file")
}

func TestEnvOrDefault(t *testing.T) {
	t.Setenv("KITE_TEST_ENVOR", "")
	assert.Equal(t, "fallback", envOrDefault("KITE_TEST_ENVOR", "fallback"))
	t.Setenv("KITE_TEST_ENVOR", "set")
	assert.Equal(t, "set", envOrDefault("KITE_TEST_ENVOR", "fallback"))
}

func TestCurrentStateSummary_ReportsAllRows(t *testing.T) {
	out := currentStateSummary()

	assert.True(t, strings.HasPrefix(out, "Current state:\n"))
	assert.Contains(t, out, "version:         "+version)
	assert.Contains(t, out, "build:           commit "+commit+", built "+date)
	assert.Contains(t, out, "config file:     kite-collector.yaml (override with --config)")
	assert.Contains(t, out, "data directory:")
	assert.Contains(t, out, "database:")
	assert.Contains(t, out, "enrollment:")
	// Whatever the machine's state, the row is one of the two known shapes.
	enrolledRow := strings.Contains(out, "enrollment:      enrolled")
	notEnrolledRow := strings.Contains(out, "not enrolled — run: kite-collector enroll --certs-dir ")
	assert.True(t, enrolledRow || notEnrolledRow, "enrollment row must be a known shape:\n%s", out)
}

func TestOtlpBuildTLSConfig_MissingCAFails(t *testing.T) {
	_, err := otlpBuildTLSConfig("", "", filepath.Join(t.TempDir(), "absent-ca.pem"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "read CA")
}

func TestOtlpBuildTLSConfig_LoadsClientPairAndPinsTLS12(t *testing.T) {
	dir := t.TempDir()
	writeTestEnrollmentPEMs(t, dir, time.Now().Add(24*time.Hour))
	certFile := filepath.Join(dir, "agent.pem")
	keyFile := filepath.Join(dir, "agent-key.pem")
	caFile := filepath.Join(dir, "ca.pem")

	cfg, err := otlpBuildTLSConfig(certFile, keyFile, caFile)
	require.NoError(t, err)
	assert.Equal(t, uint16(tls.VersionTLS12), cfg.MinVersion)
	require.Len(t, cfg.Certificates, 1)
	assert.NotNil(t, cfg.RootCAs)
	assert.NotNil(t, cfg.VerifyConnection)

	// No client pair → mTLS certificate omitted, config still built.
	cfg, err = otlpBuildTLSConfig("", "", caFile)
	require.NoError(t, err)
	assert.Empty(t, cfg.Certificates)

	// Mismatched pair fails loudly.
	_, err = otlpBuildTLSConfig(caFile, caFile, caFile)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "load client certificate")
}

func TestOtlpBuildTLSConfig_VerifyConnectionRejectsNoPeerCert(t *testing.T) {
	cfg, err := otlpBuildTLSConfig("", "", "")
	require.NoError(t, err)
	err = cfg.VerifyConnection(tls.ConnectionState{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "server presented no certificate")
}

func TestPortOf_AddressWithoutColonIsReturnedAsIs(t *testing.T) {
	assert.Equal(t, ":9090", portOf("127.0.0.1:9090"))
	assert.Equal(t, ":8080", portOf(":8080"))
	assert.Equal(t, "localhost", portOf("localhost"))
}
