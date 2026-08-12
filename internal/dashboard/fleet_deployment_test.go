package dashboard

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/vulnertrack/kite-collector/internal/model"
)

func TestParseFleetTargets_NormalizesAndSortsPlatforms(t *testing.T) {
	targets, err := parseFleetTargets(`hostname,os,arch
pc-002.example.test,win,x86_64
mac-001.example.test,darwin,aarch64
srv-001.example.test,ubuntu,amd64
unix-auto.example.test,auto,auto
`)
	require.NoError(t, err)
	require.Len(t, targets, 4)
	assert.Equal(t, fleetTarget{Hostname: "unix-auto.example.test", OS: "auto", Arch: "auto"}, targets[0])
	assert.Equal(t, fleetTarget{Hostname: "srv-001.example.test", OS: "linux", Arch: "amd64"}, targets[1])
	assert.Equal(t, fleetTarget{Hostname: "mac-001.example.test", OS: "macos", Arch: "arm64"}, targets[2])
	assert.Equal(t, fleetTarget{Hostname: "pc-002.example.test", OS: "windows", Arch: "amd64"}, targets[3])
}

func TestParseFleetTargets_AcceptsGeneratedLocalConnection(t *testing.T) {
	targets, err := parseFleetTargets("controller.example.test,linux,amd64,local\n")
	require.NoError(t, err)
	require.Len(t, targets, 1)
	assert.True(t, targets[0].Local)
	assert.Equal(t, "controller.example.test", targets[0].Hostname)
}

func TestParseFleetTargets_AcceptsWindows7X86(t *testing.T) {
	targets, err := parseFleetTargets("roberto-pc,windows,x86\n")
	require.NoError(t, err)
	require.Len(t, targets, 1)
	assert.Equal(t, fleetTarget{Hostname: "roberto-pc", OS: "windows", Arch: "386"}, targets[0])
}

func TestParseFleetTargets_DeduplicatesRawIPAndDiscoveredHostname(t *testing.T) {
	targets, err := parseFleetTargets("192.168.1.75,windows,amd64\nROBERTO-PC,windows,amd64,192.168.1.75\n")
	require.NoError(t, err)
	require.Len(t, targets, 1)
	assert.Equal(t, "ROBERTO-PC", targets[0].Hostname)
	assert.Equal(t, "192.168.1.75", targets[0].Address)
}

func TestParseFleetTargets_RejectsDuplicateAndUnsupportedTargets(t *testing.T) {
	_, err := parseFleetTargets("pc-001,windows,amd64\nPC-001,windows,amd64\n")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "duplicates hostname")

	_, err = parseFleetTargets("router-001,freebsd,amd64\n")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported OS")

	_, err = parseFleetTargets("pc-arm,windows,arm64\n")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "Windows deployment supports amd64 and legacy 386")
}

func TestFleetCandidatesFromMachines_SelectsOnlyDeployableComputers(t *testing.T) {
	now := time.Date(2026, time.August, 5, 12, 0, 0, 0, time.UTC)
	machines := []model.Machine{
		{Hostname: "asteroid-redis-1", MachineType: model.MachineTypeContainer, OSFamily: "linux", LastSeenAt: now},
		// A container sharing a host name must not hide the deployable computer.
		{Hostname: "pc-01", MachineType: model.MachineTypeContainer, OSFamily: "linux", LastSeenAt: now},
		{Hostname: "router-01", MachineType: model.MachineTypeNetworkDevice, OSFamily: "linux", LastSeenAt: now},
		{Hostname: "pc-01", MachineType: model.MachineTypeWorkstation, OSFamily: "Windows 11", LastSeenAt: now},
		{Hostname: "srv-arm", MachineType: model.MachineTypeServer, OSFamily: "Ubuntu Linux", Architecture: "aarch64", LastSeenAt: now},
		{Hostname: "mac-01", MachineType: model.MachineTypeWorkstation, OSFamily: "macOS", Architecture: "arm64", LastSeenAt: now},
		{Hostname: "mac-unknown", MachineType: model.MachineTypeWorkstation, OSFamily: "macOS", LastSeenAt: now},
		{Hostname: "blocked-01", MachineType: model.MachineTypeWorkstation, OSFamily: "Windows", IsAuthorized: model.AuthorizationUnauthorized, LastSeenAt: now},
		{Hostname: "192.0.2.25", MachineType: model.MachineTypeServer, DiscoverySource: "network_scan", LastSeenAt: now},
		{Hostname: "192.0.2.26", MachineType: model.MachineTypeServer, DiscoverySource: "network_scan", Tags: `{"network_scan_open_ports":[22],"ssh_banner":"SSH-2.0-OpenSSH_9.9"}`, LastSeenAt: now},
		{Hostname: "ROBERTO-PC", MachineType: model.MachineTypeServer, DiscoverySource: "netbios", Tags: `{"nbns_ip":"192.0.2.27"}`, LastSeenAt: now},
		{Hostname: "OFFICE-PC", MachineType: model.MachineTypeWorkstation, DiscoverySource: "wsdiscovery", LastSeenAt: now},
	}

	candidates := fleetCandidatesFromMachines(machines)
	require.Len(t, candidates, 10)
	byHostname := make(map[string]fleetMachineCandidate, len(candidates))
	for _, candidate := range candidates {
		byHostname[candidate.Hostname] = candidate
	}

	assert.True(t, byHostname["pc-01"].Compatible)
	assert.NotContains(t, byHostname, "asteroid-redis-1")
	assert.Equal(t, "windows", byHostname["pc-01"].OS)
	assert.Equal(t, "amd64", byHostname["pc-01"].Arch)
	assert.True(t, byHostname["pc-01"].ArchInferred)
	assert.Equal(t, "linux", byHostname["srv-arm"].OS)
	assert.Equal(t, "arm64", byHostname["srv-arm"].Arch)
	assert.True(t, byHostname["mac-01"].Compatible)
	assert.False(t, byHostname["router-01"].Compatible)
	assert.Contains(t, byHostname["router-01"].Reason, "device type")
	assert.False(t, byHostname["mac-unknown"].Compatible)
	assert.Contains(t, byHostname["mac-unknown"].Reason, "architecture")
	assert.False(t, byHostname["blocked-01"].Compatible)
	assert.Contains(t, byHostname["blocked-01"].Reason, "unauthorized")
	assert.True(t, byHostname["192.0.2.25"].NeedsOSSelection)
	assert.Equal(t, "192.0.2.25,linux,amd64", byHostname["192.0.2.25"].TargetLinuxAMD64)
	assert.False(t, byHostname["192.0.2.26"].Compatible)
	assert.True(t, byHostname["192.0.2.26"].NeedsOSSelection)
	assert.False(t, byHostname["ROBERTO-PC"].Compatible)
	assert.True(t, byHostname["ROBERTO-PC"].NeedsOSSelection)
	assert.Equal(t, "ROBERTO-PC,windows,amd64,192.0.2.27", byHostname["ROBERTO-PC"].TargetWindows)
	assert.Contains(t, byHostname["ROBERTO-PC"].Reason, "Windows probable")
	assert.True(t, byHostname["OFFICE-PC"].NeedsOSSelection)
	assert.Equal(t, "OFFICE-PC,windows,amd64", byHostname["OFFICE-PC"].TargetWindows)
}

func TestFleetMachinesFromLatestDiscovery_ExcludesHistoricalMachines(t *testing.T) {
	machines := []model.Machine{
		{Hostname: "controller", DiscoverySource: "local_controller"},
		{Hostname: "ROBERTO-PC", DiscoverySource: "wsdiscovery", Tags: `{"local_ip":"192.0.2.27"}`},
		{Hostname: "CURRENT-PC", DiscoverySource: "wsdiscovery", Tags: `{"local_ip":"192.0.2.28"}`},
	}

	current := fleetMachinesFromLatestDiscovery(machines, []string{"controller", "192.0.2.28"})
	require.Len(t, current, 2)
	assert.Equal(t, "controller", current[0].Hostname)
	assert.Equal(t, "CURRENT-PC", current[1].Hostname)
}

func TestFleetMachinesFromLatestDiscovery_IsEmptyBeforeFirstScan(t *testing.T) {
	machines := []model.Machine{{Hostname: "ROBERTO-PC", DiscoverySource: "wsdiscovery"}}
	assert.Empty(t, fleetMachinesFromLatestDiscovery(machines, nil))
}

func TestMergeFleetTargetInputs_CombinesSelectionsAndManualTargets(t *testing.T) {
	merged := mergeFleetTargetInputs(
		"manual-01,linux,amd64\n",
		[]string{"pc-01,windows,amd64", "mac-01,macos,arm64"},
	)
	assert.Equal(t,
		"manual-01,linux,amd64\npc-01,windows,amd64\nmac-01,macos,arm64",
		merged)
}

func TestFleetInventory_UsesDiscoveredIPAddressWithoutLosingHostname(t *testing.T) {
	targets, err := parseFleetTargets("ROBERTO-PC,windows,amd64,192.0.2.27\n")
	require.NoError(t, err)
	require.Len(t, targets, 1)
	assert.Equal(t, "ROBERTO-PC", targets[0].Hostname)
	assert.Equal(t, "192.0.2.27", targets[0].Address)

	req := fleetBundleRequest{EnrollmentTokens: map[string]string{"ROBERTO-PC": "token-value"}}
	inventory := fleetInventoryYAML(req, targets)
	assert.Contains(t, inventory, `"ROBERTO-PC":`)
	assert.Contains(t, inventory, `ansible_host: "192.0.2.27"`)
}

func TestFleetCanAutoDetectUnix_UsesOpenSSHAndRejectsApplianceBanners(t *testing.T) {
	assert.False(t, fleetCanAutoDetectUnix("192.0.2.20", `{"network_scan_open_ports":[22],"ssh_banner":"SSH-2.0-OpenSSH_9.9"}`))
	assert.False(t, fleetCanAutoDetectUnix("192.0.2.1", `{"network_scan_open_ports":[22,53,80],"ssh_banner":"SSH-2.0-OpenSSH_9.9"}`))
	assert.True(t, fleetCanAutoDetectUnix("192.0.2.20", `{"network_scan_open_ports":[22],"ssh_banner":"SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13"}`))
	assert.False(t, fleetCanAutoDetectUnix("192.0.2.20", `{"network_scan_open_ports":[22],"ssh_banner":"SSH-2.0-dropbear"}`))
}

func TestFleetDetectionDescription_ShowsConfidenceLevels(t *testing.T) {
	assert.Equal(t,
		"OS inferred with medium confidence · Windows RPC and SMB ports are both reachable",
		fleetDetectionDescription(`{"deployment_os_confidence":"medium","deployment_os_evidence":"Windows RPC and SMB ports are both reachable"}`))
	assert.Equal(t,
		"OS estimate with low confidence · NetBIOS identity only",
		fleetDetectionDescription(`{"deployment_os_confidence":"low","deployment_os_evidence":"NetBIOS identity only"}`))
}

func TestFleetDeployScript_LocalUnixDoesNotRequestSSH(t *testing.T) {
	script := fleetDeployScript(fleetBundleRequest{Version: "0.42.0"}, []fleetTarget{{
		Hostname: "controller.example.test", OS: "linux", Arch: "amd64", Local: true,
	}})
	assert.Contains(t, script, "if false; then\n  read -r -p \"SSH user")
	assert.Contains(t, script, "Enter the sudo password for the Linux/macOS computers")
	assert.Contains(t, script, "Nothing will appear while you type")
	assert.Contains(t, script, "Sudo password:")
	assert.Contains(t, script, "export KITE_BECOME_PASSWORD")
	assert.Contains(t, script, "if false; then args+=(--ask-become-pass)")
	assert.Contains(t, script, "systemctl restart kite-collector")
	assert.Contains(t, script, "docker rm -f kite-collector-local")
	assert.Contains(t, script, "Waiting for the initial machine and software inventory")
	assert.Contains(t, script, "http://127.0.0.1:9090/machines")
}

func TestFleetDeployScript_WindowsCredentialsAreAlwaysRequired(t *testing.T) {
	script := fleetDeployScript(fleetBundleRequest{Version: "0.42.0"}, []fleetTarget{{
		Hostname: "ROBERTO-PC", OS: "windows", Arch: "amd64",
	}})
	assert.Contains(t, script, `windows_targets=("ROBERTO-PC")`)
	assert.Contains(t, script, `KITE_WINDOWS_USER_DEFAULT="${windows_target}\\Administrador"`)
	assert.Contains(t, script, `Windows administrator [${KITE_WINDOWS_USER_DEFAULT}]`)
	assert.Contains(t, script, `artifact_name="kite-collector_0.42.0_amd64.msi"`)
	assert.Contains(t, script, `legacy_name="kite-collector_windows_386_legacy.exe"`)
	assert.Contains(t, script, `legacy_url="https://github.com/VulnerTrack/kite-collector/releases/download/v0.42.0/${legacy_name}"`)
	assert.Contains(t, script, `KITE_WINDOWS_USER="${KITE_WINDOWS_USER:-$KITE_WINDOWS_USER_DEFAULT}"`)
	assert.Contains(t, script, `while [ -z "$KITE_WINDOWS_PASSWORD" ]`)
	assert.Contains(t, script, "Windows password is required")
	assert.Contains(t, script, `--limit "$windows_target"`)
}

func TestFleetDeployScript_MultipleWindowsTargetsPromptPerComputer(t *testing.T) {
	script := fleetDeployScript(fleetBundleRequest{Version: "0.42.0"}, []fleetTarget{
		{Hostname: "ALEJO-PC", OS: "windows", Arch: "amd64"},
		{Hostname: "ROBERTO-PC", OS: "windows", Arch: "amd64"},
	})
	assert.Contains(t, script, `windows_targets=("ALEJO-PC" "ROBERTO-PC")`)
	assert.Contains(t, script, `for windows_target in "${windows_targets[@]}"`)
	assert.Contains(t, script, `Windows password for ${KITE_WINDOWS_USER}:`)
}

func TestFleetInventory_LocalConnectionSurvivesPlayDefaults(t *testing.T) {
	req := fleetBundleRequest{EnrollmentTokens: map[string]string{"controller.example.test": "token-value"}}
	targets := []fleetTarget{{
		Hostname: "controller.example.test", OS: "linux", Arch: "amd64", Local: true,
	}}
	assert.Contains(t, fleetInventoryYAML(req, targets), "kite_connection: local")
	assert.Contains(t, fleetPlaybookYAML, `ansible_connection: "{{ kite_connection | default('ssh') }}"`)
	assert.Contains(t, fleetPlaybookYAML, `ansible_become_password: "{{ lookup('env', 'KITE_BECOME_PASSWORD') }}"`)
}

func TestFleetCandidate_LocalControllerUsesLocalConnection(t *testing.T) {
	candidate := fleetCandidateFromMachine(model.Machine{
		Hostname: "controller.example.test", MachineType: model.MachineTypeWorkstation,
		OSFamily: "linux", Architecture: "amd64", DiscoverySource: "local_controller",
	})
	assert.True(t, candidate.Compatible)
	assert.Equal(t, "controller.example.test,linux,amd64,local", candidate.TargetLine)
}

func TestResolveFleetReleaseVersion_UsesServerConfiguration(t *testing.T) {
	t.Setenv("KITE_FLEET_RELEASE_VERSION", "")
	version, err := resolveFleetReleaseVersion(Options{AppVersion: "v1.2.3"})
	require.NoError(t, err)
	assert.Equal(t, "1.2.3", version)

	_, err = resolveFleetReleaseVersion(Options{AppVersion: "dev"})
	require.Error(t, err)

	t.Setenv("KITE_FLEET_RELEASE_VERSION", "v4.5.6")
	version, err = resolveFleetReleaseVersion(Options{AppVersion: "v1.2.3"})
	require.NoError(t, err)
	assert.Equal(t, "4.5.6", version)
}

func TestWriteFleetBundle_ContainsRunnableUniversalPackage(t *testing.T) {
	legacyPath := t.TempDir() + "/kite-collector_windows_386_legacy.exe"
	require.NoError(t, os.WriteFile(legacyPath, []byte("test-pe32-artifact"), 0o600))
	t.Setenv("KITE_FLEET_LEGACY_ARTIFACT", legacyPath)
	req := fleetBundleRequest{
		Version:     "0.42.0",
		PKIEndpoint: "https://pki.example.test",
		EnrollmentTokens: map[string]string{
			"pc-001.example.test":    "pki_enroll_v1_pc-secret-value",
			"srv-001.example.test":   "pki_enroll_v1_srv-secret-value",
			"mac-001.example.test":   "pki_enroll_v1_mac-secret-value",
			"unix-auto.example.test": "pki_enroll_v1_auto-secret-value",
		},
	}
	targets := []fleetTarget{
		{Hostname: "pc-001.example.test", OS: "windows", Arch: "amd64"},
		{Hostname: "srv-001.example.test", OS: "linux", Arch: "arm64"},
		{Hostname: "mac-001.example.test", OS: "macos", Arch: "arm64"},
		{Hostname: "unix-auto.example.test", OS: "auto", Arch: "auto"},
	}

	var out bytes.Buffer
	require.NoError(t, writeFleetBundle(&out, req, targets))

	zr, err := zip.NewReader(bytes.NewReader(out.Bytes()), int64(out.Len()))
	require.NoError(t, err)
	files := make(map[string]string, len(zr.File))
	for _, file := range zr.File {
		assert.Equal(t, 1980, file.ModTime().UTC().Year(), "portable ZIP timestamp for %s", file.Name)
		rc, openErr := file.Open()
		require.NoError(t, openErr)
		body, readErr := io.ReadAll(rc)
		require.NoError(t, readErr)
		require.NoError(t, rc.Close())
		files[file.Name] = string(body)
	}

	for _, name := range []string{
		"README.md", "ansible.cfg", "deploy.sh", "deployment.json",
		"artifacts/kite-collector_windows_386_legacy.exe",
		"inventory/hosts.yml", "inventory/group_vars/all.yml",
		"playbooks/deploy.yml", "targets.csv",
	} {
		assert.Contains(t, files, name)
	}
	assert.Equal(t, "test-pe32-artifact", files["artifacts/kite-collector_windows_386_legacy.exe"])
	assert.Contains(t, files["inventory/hosts.yml"], `"pc-001.example.test"`)
	assert.Contains(t, files["inventory/hosts.yml"], `"srv-001.example.test"`)
	assert.Contains(t, files["inventory/hosts.yml"], `"mac-001.example.test"`)
	assert.Contains(t, files["inventory/hosts.yml"], `"unix-auto.example.test"`)
	assert.Contains(t, files["inventory/hosts.yml"], "unix_auto:")
	assert.Contains(t, files["inventory/hosts.yml"], "kite_agent_code:")
	assert.NotEqual(t, fleetAgentCode("pc-001.example.test"), fleetAgentCode("srv-001.example.test"))
	assert.Contains(t, files["inventory/hosts.yml"], fleetAgentCode("pc-001.example.test"))
	assert.Contains(t, files["playbooks/deploy.yml"], "Detect Windows version and processor architecture")
	assert.Contains(t, files["playbooks/deploy.yml"], "kite_windows_legacy")
	assert.Contains(t, files["playbooks/deploy.yml"], "kite-collector_windows_386_legacy.exe")
	assert.Contains(t, files["playbooks/deploy.yml"], "ansible_winrm_read_timeout_sec: 120")
	assert.Contains(t, files["playbooks/deploy.yml"], "Read sanitized enrollment diagnostic")
	assert.Contains(t, files["playbooks/deploy.yml"], "[REDACTED]")
	assert.Contains(t, files["playbooks/deploy.yml"], "& $exe install --certs-dir")
	assert.NotContains(t, files["playbooks/deploy.yml"], "& sc.exe create kite-collector-legacy")
	assert.Contains(t, files["playbooks/deploy.yml"], "ansible.builtin.unarchive")
	assert.Contains(t, files["playbooks/deploy.yml"], "uname -s")
	assert.Contains(t, files["playbooks/deploy.yml"], "detected-platforms.csv")
	assert.Contains(t, files["deploy.sh"], "install_python_venv()")
	assert.Contains(t, files["deploy.sh"], "apt-get install -y python3-venv")
	assert.Contains(t, files["deploy.sh"], "python3 -m venv .venv")
	assert.Contains(t, files["inventory/hosts.yml"],
		base64.StdEncoding.EncodeToString([]byte(req.EnrollmentTokens["pc-001.example.test"])))
	for _, token := range req.EnrollmentTokens {
		assert.NotContains(t, files["deployment.json"], token,
			"the non-secret manifest must not duplicate enrollment credentials")
	}

	for _, name := range []string{
		"inventory/hosts.yml", "inventory/group_vars/all.yml", "playbooks/deploy.yml",
	} {
		var document yaml.Node
		require.NoErrorf(t, yaml.Unmarshal([]byte(files[name]), &document), "invalid generated YAML in %s", name)
	}
}

func TestRoute_GET_Fleet_ReturnsFullShellAndActiveNavigation(t *testing.T) {
	handler := newTestHandler(t)
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/fleet", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	body := rec.Body.String()
	assert.Contains(t, body, "<html")
	assert.Contains(t, body, "Mass deployment")
	assert.Contains(t, body, `action="/api/v1/fleet/package"`)
	assert.Contains(t, body, `onsubmit="startFleetDiscovery(this)"`)
	assert.Contains(t, body, `class="fleet-discovery-spinner"`)
	assert.Contains(t, body, `aria-live="polite"`)
	assert.Contains(t, body, `Searching network…`)
	assert.NotContains(t, body, "Released version")
	assert.NotContains(t, body, "Agent code")
	assert.NotContains(t, body, "PKI endpoint")
	assert.NotContains(t, body, "Short-lived fleet enrollment token")
	assert.NotContains(t, body, `name="enrollment_token"`)
	assert.Contains(t, body, "single-use, two-hour credential per computer")
	assert.Contains(t, body, `href="/fleet" hx-get="/fleet" hx-target="#content" hx-push-url="true"`)
	assert.Contains(t, body, `class="btn btn-ghost active"`)
}

func TestRoute_GET_Fleet_ListsCompatibleDiscoveredMachines(t *testing.T) {
	st := testStore(t)
	_, _, err := st.UpsertMachines(context.Background(), []model.Machine{{
		ID:              uuid.Must(uuid.NewV7()),
		Hostname:        "pc-discovered.example.test",
		MachineType:     model.MachineTypeWorkstation,
		OSFamily:        "Windows 11 Pro",
		DiscoverySource: "ldap",
		IsAuthorized:    model.AuthorizationUnknown,
		IsManaged:       model.ManagedUnknown,
		FirstSeenAt:     time.Now().UTC(),
		LastSeenAt:      time.Now().UTC(),
	}})
	require.NoError(t, err)
	handler := Serve(":0", st, testContext(), nil, Options{}).Handler
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/fleet", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	body := rec.Body.String()
	assert.Contains(t, body, "Computers discovered by Kite")
	assert.Contains(t, body, `value="pc-discovered.example.test,windows,amd64"`)
	assert.Contains(t, body, "1 compatible")
	assert.Contains(t, body, "ldap")
}

func TestRoute_POST_FleetPackage_ReturnsZip(t *testing.T) {
	configureFleetTestEnvironment(t)
	handler := newFleetPackageTestHandler(t)
	form := url.Values{
		"enrollment_token": {"pki_enroll_v1_test-secret-value"},
		"targets":          {"pc-001.example.test,windows,amd64\n"},
		"version":          {"9.9.9"},
		"agent_code":       {"attacker-controlled"},
		"pki_endpoint":     {"https://untrusted.example.test"},
	}
	req := httptest.NewRequestWithContext(
		context.Background(), http.MethodPost, "/api/v1/fleet/package",
		strings.NewReader(form.Encode()),
	)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "application/zip", rec.Header().Get("Content-Type"))
	assert.Equal(t, `attachment; filename="kite-deployment.zip"`, rec.Header().Get("Content-Disposition"))
	assert.Equal(t, "no-store", rec.Header().Get("Cache-Control"))
	zr, err := zip.NewReader(bytes.NewReader(rec.Body.Bytes()), int64(rec.Body.Len()))
	require.NoError(t, err)
	bundleFiles := make(map[string]string, len(zr.File))
	for _, file := range zr.File {
		rc, openErr := file.Open()
		require.NoError(t, openErr)
		body, readErr := io.ReadAll(rc)
		require.NoError(t, readErr)
		require.NoError(t, rc.Close())
		bundleFiles[file.Name] = string(body)
		assert.NotContains(t, string(body), "pki_enroll_v1_test-secret-value",
			"a manually submitted credential must be ignored")
		if file.Name != "inventory/group_vars/all.yml" {
			continue
		}
		assert.Contains(t, string(body), `kite_version: "0.42.0"`)
		assert.Contains(t, string(body), `kite_pki_endpoint: "https://pki.example.test"`)
		assert.NotContains(t, string(body), "untrusted.example.test")
		assert.NotContains(t, string(body), "attacker-controlled")
	}
	assert.Contains(t, bundleFiles, "bootstrap/windows/Enable-KiteWinRM.ps1")
	assert.Contains(t, bundleFiles, "bootstrap/windows/GPO-SETUP.md")
	assert.Contains(t, bundleFiles, "bootstrap/windows/WINDOWS-COMMAND.txt")
	assert.Contains(t, bundleFiles, "preflight.py")
	assert.Contains(t, bundleFiles["deploy.sh"], "python3 preflight.py")
	assert.Contains(t, bundleFiles["deploy.sh"], `windows_targets=("pc-001.example.test")`)
	assert.Contains(t, bundleFiles["deploy.sh"], `KITE_WINDOWS_USER_DEFAULT="${windows_target}\\Administrador"`)
	assert.Contains(t, bundleFiles["deploy.sh"], "press Enter if this is the correct user")
	assert.Contains(t, bundleFiles["deploy.sh"], `KITE_WINDOWS_USER="${KITE_WINDOWS_USER:-$KITE_WINDOWS_USER_DEFAULT}"`)
	assert.Contains(t, bundleFiles["deploy.sh"], `KITE_WINDOWS_USER="${KITE_WINDOWS_USER//\//\\}"`)
	assert.Contains(t, bundleFiles["deploy.sh"], `for windows_target in`)
	assert.Contains(t, bundleFiles["deploy.sh"], `--limit "$windows_target"`)
	assert.Contains(t, bundleFiles["preflight.py"], "ThreadPoolExecutor")
	assert.Contains(t, bundleFiles["playbooks/deploy.yml"], "ansible.builtin.raw")
	assert.NotContains(t, bundleFiles["playbooks/deploy.yml"], "Ansible requires PowerShell v5.1")
	assert.NotContains(t, bundleFiles["playbooks/deploy.yml"], "ansible.windows.win_file")
	assert.Contains(t, bundleFiles["bootstrap/windows/Enable-KiteWinRM.ps1"], "Enable-PSRemoting")
	assert.Contains(t, bundleFiles["bootstrap/windows/WINDOWS-COMMAND.txt"], "remoteip=localsubnet")
	assert.Contains(t, bundleFiles["bootstrap/windows/WINDOWS-COMMAND.txt"], `findstr ":5985"`)
	assert.Contains(t, bundleFiles["preflight.py"], "No file needs to be copied to Windows")
	assert.Contains(t, bundleFiles["targets.csv"], "hostname,os,arch,connection,address")
}

func TestRoute_POST_FleetPackage_AcceptsDiscoveredSelectionWithoutManualCSV(t *testing.T) {
	configureFleetTestEnvironment(t)
	handler := newFleetPackageTestHandler(t)
	form := url.Values{
		"enrollment_token":  {"pki_enroll_v1_test-secret-value"},
		"discovered_target": {"pc-discovered.example.test,windows,amd64"},
	}
	req := httptest.NewRequestWithContext(
		context.Background(), http.MethodPost, "/api/v1/fleet/package",
		strings.NewReader(form.Encode()),
	)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	zr, err := zip.NewReader(bytes.NewReader(rec.Body.Bytes()), int64(rec.Body.Len()))
	require.NoError(t, err)
	foundTarget := false
	for _, file := range zr.File {
		if file.Name != "targets.csv" {
			continue
		}
		rc, openErr := file.Open()
		require.NoError(t, openErr)
		body, readErr := io.ReadAll(rc)
		require.NoError(t, readErr)
		require.NoError(t, rc.Close())
		foundTarget = strings.Contains(string(body), "pc-discovered.example.test,windows,amd64")
	}
	assert.True(t, foundTarget)
}

func TestRoute_POST_FleetPackage_RejectsInvalidTargetWithoutEchoingToken(t *testing.T) {
	configureFleetTestEnvironment(t)
	handler := newTestHandler(t)
	const secret = "pki_enroll_v1_never-echo-this-token"
	form := url.Values{
		"enrollment_token": {secret},
		"targets":          {"pc-001.example.test,plan9,amd64\n"},
	}
	req := httptest.NewRequestWithContext(
		context.Background(), http.MethodPost, "/api/v1/fleet/package",
		strings.NewReader(form.Encode()),
	)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Contains(t, rec.Body.String(), "unsupported OS")
	assert.NotContains(t, rec.Body.String(), secret)
}

func TestRoute_POST_FleetPackage_RedirectsToVulnerTrackSignInWhenSessionMissing(t *testing.T) {
	configureFleetTestEnvironment(t)
	handler := newTestHandler(t)
	form := url.Values{"targets": {"pc-001.example.test,windows,amd64"}}
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost,
		"/api/v1/fleet/package", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusSeeOther, rec.Code)
	location := rec.Header().Get("Location")
	assert.Contains(t, location, "/kite-login?")
	assert.Contains(t, location, "dashboard=%2Ffleet")
	assert.Contains(t, location, "wait_id=fleet-")
}

type fakeFleetTokenIssuer struct{}

func (fakeFleetTokenIssuer) MintBatch(
	_ context.Context,
	_, _ string,
	agentCodes []string,
) (map[string]FleetEnrollmentToken, error) {
	issued := make(map[string]FleetEnrollmentToken, len(agentCodes))
	for _, agentCode := range agentCodes {
		issued[agentCode] = FleetEnrollmentToken{
			Token:   "pki_enroll_v1_" + agentCode + "_test-secret",
			TokenID: "token-" + agentCode,
		}
	}
	return issued, nil
}

func newFleetPackageTestHandler(t *testing.T) http.Handler {
	t.Helper()
	st := testStore(t)
	return Serve(":0", st, testContext(), nil, Options{
		FleetTokenIssuer: fakeFleetTokenIssuer{},
		FleetOperatorToken: func(context.Context) (string, error) {
			return "operator-oauth-token", nil
		},
	}).Handler
}

func configureFleetTestEnvironment(t *testing.T) {
	t.Helper()
	t.Setenv("KITE_FLEET_RELEASE_VERSION", "0.42.0")
	t.Setenv("KITE_PKI_ENDPOINT", "https://pki.example.test")
}
