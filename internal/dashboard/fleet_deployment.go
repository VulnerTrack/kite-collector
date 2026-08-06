package dashboard

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/vulnertrack/kite-collector/internal/model"
	"github.com/vulnertrack/kite-collector/internal/store"
)

const (
	defaultFleetPKIEndpoint = "https://pki.vulnertrack.io"
	maxFleetTargets         = 500
	maxFleetFormBytes       = 1 << 20
)

var (
	fleetHostPattern    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,252}$`)
	fleetVersionPattern = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+$`)
)

type fleetTarget struct {
	Hostname string
	OS       string
	Arch     string
	Local    bool
}

type fleetBundleRequest struct {
	Version          string
	PKIEndpoint      string
	EnrollmentTokens map[string]string
	TargetsCSV       string
}

type fleetPageView struct {
	Machines        []fleetMachineCandidate
	CompatibleCount int
	SkippedCount    int
	LocalNetwork    *fleetLocalNetwork
	Discovery       fleetDiscoveryStatus
}

type fleetMachineCandidate struct {
	Hostname         string
	OS               string
	Arch             string
	MachineType      string
	DiscoverySource  string
	LastSeen         string
	TargetLine       string
	Reason           string
	Detection        string
	Compatible       bool
	ArchInferred     bool
	NeedsOSSelection bool
	TargetWindows    string
	TargetLinuxAMD64 string
	TargetLinuxARM64 string
	TargetMacAMD64   string
	TargetMacARM64   string
}

const fleetDeploymentTemplate = `<div class="fleet-hero">
  <div>
    <span class="badge badge-blue">Fleet controller</span>
    <h1>Mass deployment</h1>
    <p class="muted">Generate one short-lived Ansible package for Windows, Linux, and macOS.
       The operator downloads it here; the deployment runner asks for AD/SSH credentials only when executed.</p>
  </div>
</div>

<div class="fleet-grid">
  <section class="card">
    <h2>1. Select the fleet</h2>
    <p class="muted">Kite automatically reuses compatible computers from the local Machines inventory.
       Hostnames may also be IP addresses.</p>
    {{if .LocalNetwork}}
    <div class="fleet-network-discovery">
      <div class="fleet-network-copy">
        <strong>Discover computers on this network</strong>
        <span class="muted small">Local IP <code>{{.LocalNetwork.LocalIP}}</code> · Network <code>{{.LocalNetwork.CIDR}}</code> · Interface {{.LocalNetwork.InterfaceName}}</span>
        <span class="muted small">One click combines TCP/SSH, Bonjour, NetBIOS, SSDP and WS-Discovery on this local network.</span>
      </div>
      <form method="post" action="/api/v1/fleet/discover" onsubmit="startFleetDiscovery(this)">
        <button class="btn-primary fleet-discovery-button {{if .Discovery.Running}}is-loading{{end}}" type="submit"
                aria-describedby="fleet-discovery-progress" {{if .Discovery.Running}}disabled aria-busy="true"{{end}}>
          <span class="fleet-discovery-spinner" aria-hidden="true"></span>
          <span class="fleet-discovery-button-label">{{if .Discovery.Running}}Searching network…{{else}}Discover computers{{end}}</span>
        </button>
        <span id="fleet-discovery-progress" class="sr-only" role="status" aria-live="polite">{{if .Discovery.Running}}Searching for computers on the local network. This can take up to 45 seconds.{{end}}</span>
      </form>
    </div>
    {{else}}
    <div class="fleet-warning"><strong>Network unavailable:</strong> Kite could not detect an active private IPv4 network.</div>
    {{end}}
    {{if .Discovery.HasRun}}
      {{if .Discovery.Error}}
      <div class="fleet-discovery-result fleet-discovery-error"><strong>Network scan failed.</strong> {{.Discovery.Error}}</div>
      {{else}}
      <div class="fleet-discovery-result"><strong>Automatic discovery complete.</strong> Found {{.Discovery.Found}} observations across five discovery methods; added {{.Discovery.Inserted}} and updated {{.Discovery.Updated}}. <span class="muted small">TCP {{.Discovery.TCPFound}} · Bonjour {{.Discovery.MDNSFound}} · NetBIOS {{.Discovery.NetBIOSFound}} · SSDP {{.Discovery.SSDPFound}} · WS-Discovery {{.Discovery.WSDFound}} · {{.Discovery.CompletedAt}}</span></div>
      {{end}}
    {{end}}
    <form method="post" action="/api/v1/fleet/package" class="fleet-package-form">
      {{if .Machines}}
      <div class="fleet-discovered">
        <div class="fleet-discovered-heading">
          <div>
            <h3>Computers discovered by Kite</h3>
            <span class="muted small">{{.CompatibleCount}} compatible{{if .SkippedCount}} · {{.SkippedCount}} skipped for safety{{end}}</span>
          </div>
          {{if .CompatibleCount}}
          <div class="fleet-selection-actions">
            <button class="btn" type="button" onclick="setFleetSelection(true)">Select compatible</button>
            <button class="btn btn-ghost" type="button" onclick="setFleetSelection(false)">Clear</button>
          </div>
          {{end}}
        </div>
        <div class="fleet-machine-list" role="group" aria-label="Discovered computers">
          {{range .Machines}}
          <label class="fleet-machine {{if and (not .Compatible) (not .NeedsOSSelection)}}fleet-machine-disabled{{end}}">
            {{if .Compatible}}
            <input type="checkbox" name="discovered_target" value="{{.TargetLine}}"
                   class="fleet-machine-checkbox" checked>
            {{else if .NeedsOSSelection}}
            <span class="fleet-machine-unknown" aria-hidden="true">?</span>
            {{else}}
            <input type="checkbox" class="fleet-machine-checkbox" disabled>
            {{end}}
            <span class="fleet-machine-main">
              <strong>{{.Hostname}}</strong>
              <span class="muted small">{{.MachineType}} · {{.DiscoverySource}} · {{.LastSeen}}</span>
              {{if .Detection}}<span class="muted small">{{.Detection}}</span>{{end}}
              {{if and .NeedsOSSelection .Reason}}<span class="fleet-detection-hint">{{.Reason}}</span>{{end}}
            </span>
            {{if .Compatible}}
            {{if eq .OS "auto"}}
            <span class="badge badge-blue">Linux/macOS · automatic</span>
            {{else}}
            <span class="badge badge-blue">{{.OS}}/{{.Arch}}{{if .ArchInferred}} default{{end}}</span>
            {{end}}
            {{else if .NeedsOSSelection}}
            <select name="discovered_target" class="fleet-os-select" aria-label="Choose operating system for {{.Hostname}}">
              <option value="">Choose OS…</option>
              <option value="{{.TargetWindows}}">Windows amd64</option>
              <option value="{{.TargetLinuxAMD64}}">Linux amd64</option>
              <option value="{{.TargetLinuxARM64}}">Linux arm64</option>
              <option value="{{.TargetMacAMD64}}">macOS amd64</option>
              <option value="{{.TargetMacARM64}}">macOS arm64</option>
            </select>
            {{else}}
            <span class="fleet-machine-reason">{{.Reason}}</span>
            {{end}}
          </label>
          {{end}}
        </div>
      </div>
      {{else}}
      <div class="fleet-empty-machines">
        <strong>No computers discovered yet.</strong>
        <span class="muted small">Run a Kite scan or configure AD/MDM discovery, then return to this page.</span>
      </div>
      {{end}}
      <div class="form-row">
        <label for="fleet-targets">Additional computers <span class="muted small">(optional)</span></label>
        <textarea id="fleet-targets" name="targets" rows="5"
                  spellcheck="false" placeholder="hostname,os,arch&#10;pc-001.corp.example.com,windows,amd64&#10;srv-001.corp.example.com,linux,amd64&#10;mac-001.corp.example.com,macos,arm64"></textarea>
        <span class="muted small">One computer per line using <code>hostname,os,arch</code>. This is useful for an IP or host not present in Machines.</span>
      </div>
      <div class="cta-bar">
        <button class="btn-primary" type="submit">Generate deployment package</button>
        <span class="muted small">Kite automatically creates one single-use, two-hour credential per computer. Treat the ZIP as a secret.</span>
      </div>
    </form>
  </section>

  <aside class="card fleet-how-it-works">
    <h2>2. Run one command</h2>
    <pre><code>unzip kite-deployment.zip
cd kite-deployment
./deploy.sh</code></pre>
    <ol>
      <li>Installs an isolated Ansible runtime.</li>
      <li>Prompts for Windows and/or SSH credentials.</li>
      <li>Automatically distinguishes Linux from macOS and detects CPU architecture.</li>
      <li>Downloads versioned release artifacts and validates checksums.</li>
      <li>Installs, enrolls, and starts each collector.</li>
      <li>Saves detection results without storing infrastructure passwords.</li>
    </ol>
    <div class="fleet-warning"><strong>Network prerequisites:</strong> Windows targets need WinRM; Linux/macOS targets need SSH and sudo access.</div>
  </aside>
</div>`

const fleetSelectionScript = `<script>
function startFleetDiscovery(form) {
  var button = form.querySelector('.fleet-discovery-button');
  if (!button || button.disabled) return;
  button.disabled = true;
  button.setAttribute('aria-busy', 'true');
  button.classList.add('is-loading');
  var label = button.querySelector('.fleet-discovery-button-label');
  if (label) label.textContent = 'Searching network…';
  var progress = form.querySelector('[role="status"]');
  if (progress) progress.textContent = 'Searching for computers on the local network. This can take up to 45 seconds.';
}
function setFleetSelection(selected) {
  document.querySelectorAll('.fleet-machine-checkbox:not(:disabled)').forEach(function(box) {
    box.checked = selected;
  });
}
</script>`

var fleetDeploymentTmpl = template.Must(template.New("fleet-deployment").Parse(fleetDeploymentTemplate))

func renderFleetDeploymentFragment(
	w io.Writer,
	ctx context.Context,
	st store.Store,
	_ Options,
	discovery *fleetDiscoveryController,
) error {
	machines, err := st.ListMachines(ctx, store.MachineFilter{Limit: maxFleetTargets})
	if err != nil {
		return fmt.Errorf("list machines for fleet deployment: %w", err)
	}
	candidates := fleetCandidatesFromMachines(machines)
	compatibleCount := 0
	for _, candidate := range candidates {
		if candidate.Compatible {
			compatibleCount++
		}
	}
	var localNetwork *fleetLocalNetwork
	if networkInfo, detectErr := discovery.detect(); detectErr == nil {
		localNetwork = &networkInfo
	}
	if err := fleetDeploymentTmpl.Execute(w, fleetPageView{
		Machines:        candidates,
		CompatibleCount: compatibleCount,
		SkippedCount:    len(candidates) - compatibleCount,
		LocalNetwork:    localNetwork,
		Discovery:       discovery.snapshot(),
	}); err != nil {
		return fmt.Errorf("render fleet deployment template: %w", err)
	}
	_, err = io.WriteString(w, fleetSelectionScript)
	if err != nil {
		return fmt.Errorf("render fleet selection script: %w", err)
	}
	return nil
}

func handleFleetPackage(
	w http.ResponseWriter,
	r *http.Request,
	logger *slog.Logger,
	opts Options,
	service *fleetPackageService,
) {
	r.Body = http.MaxBytesReader(w, r.Body, maxFleetFormBytes)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid deployment form", http.StatusBadRequest)
		return
	}
	version, err := resolveFleetReleaseVersion(opts)
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	req := fleetBundleRequest{
		Version:     version,
		PKIEndpoint: resolveFleetPKIEndpoint(),
		TargetsCSV:  mergeFleetTargetInputs(r.FormValue("targets"), r.Form["discovered_target"]),
	}
	targets, err := validateFleetBundleRequest(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	req.EnrollmentTokens, err = service.issueTokens(r.Context(), req.PKIEndpoint, targets)
	if err != nil {
		if errors.Is(err, errFleetSignInRequired) {
			loginURL := "/kite-login?dashboard=" + url.QueryEscape("/fleet") +
				"&wait_id=" + url.QueryEscape("fleet-"+uuid.NewString())
			http.Redirect(w, r, loginURL, http.StatusSeeOther)
			return
		}
		logger.Error("dashboard: issue fleet enrollment credentials",
			"code", string(LogCodeFleetPackageBuild),
			"error", err,
			"target_count", len(targets))
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}

	var bundle bytes.Buffer
	if err = writeFleetBundle(&bundle, req, targets); err != nil {
		logger.Error("dashboard: build fleet deployment package",
			"code", string(LogCodeFleetPackageBuild),
			"error", err,
			"target_count", len(targets))
		http.Error(w, "could not build deployment package", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", `attachment; filename="kite-deployment.zip"`)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(bundle.Bytes())
}

func validateFleetBundleRequest(req fleetBundleRequest) ([]fleetTarget, error) {
	if !fleetVersionPattern.MatchString(req.Version) {
		return nil, fmt.Errorf("version must use numeric major.minor.patch format")
	}
	pkiURL, err := url.Parse(req.PKIEndpoint)
	if err != nil || pkiURL.Host == "" || (pkiURL.Scheme != "https" && pkiURL.Scheme != "http") {
		return nil, fmt.Errorf("PKI endpoint must be a valid HTTP or HTTPS URL")
	}
	targets, err := parseFleetTargets(req.TargetsCSV)
	if err != nil {
		return nil, err
	}
	if len(targets) == 0 {
		return nil, fmt.Errorf("at least one target computer is required")
	}
	return targets, nil
}

func resolveFleetReleaseVersion(opts Options) (string, error) {
	if override := strings.TrimSpace(os.Getenv("KITE_FLEET_RELEASE_VERSION")); override != "" {
		version := strings.TrimPrefix(override, "v")
		if !fleetVersionPattern.MatchString(version) {
			return "", fmt.Errorf("KITE_FLEET_RELEASE_VERSION must use numeric major.minor.patch format")
		}
		return version, nil
	}
	version := strings.TrimPrefix(strings.TrimSpace(opts.AppVersion), "v")
	if !fleetVersionPattern.MatchString(version) {
		return "", fmt.Errorf("fleet deployment requires a released kite-collector build")
	}
	return version, nil
}

func resolveFleetPKIEndpoint() string {
	if endpoint := strings.TrimSpace(os.Getenv("KITE_PKI_ENDPOINT")); endpoint != "" {
		return strings.TrimRight(endpoint, "/")
	}
	return defaultFleetPKIEndpoint
}

func mergeFleetTargetInputs(manual string, selected []string) string {
	lines := make([]string, 0, len(selected)+1)
	if trimmed := strings.TrimSpace(manual); trimmed != "" {
		lines = append(lines, trimmed)
	}
	for _, target := range selected {
		if trimmed := strings.TrimSpace(target); trimmed != "" {
			lines = append(lines, trimmed)
		}
	}
	return strings.Join(lines, "\n")
}

func fleetCandidatesFromMachines(machines []model.Machine) []fleetMachineCandidate {
	candidates := make([]fleetMachineCandidate, 0, len(machines))
	byHostname := make(map[string]int, len(machines))
	for _, machine := range machines {
		candidate := fleetCandidateFromMachine(machine)
		key := strings.ToLower(strings.TrimSpace(candidate.Hostname))
		if index, exists := byHostname[key]; exists {
			// A hostname can exist under more than one machine type. Prefer a
			// deployable record, while keeping the most recently seen record when
			// both have the same compatibility state (ListMachines is newest first).
			if !candidates[index].Compatible && candidate.Compatible {
				candidates[index] = candidate
			}
			continue
		}
		byHostname[key] = len(candidates)
		candidates = append(candidates, candidate)
	}
	sort.SliceStable(candidates, func(i, j int) bool {
		if candidates[i].Compatible != candidates[j].Compatible {
			return candidates[i].Compatible
		}
		return strings.ToLower(candidates[i].Hostname) < strings.ToLower(candidates[j].Hostname)
	})
	return candidates
}

func fleetCandidateFromMachine(machine model.Machine) fleetMachineCandidate {
	hostname := strings.TrimSpace(machine.Hostname)
	candidate := fleetMachineCandidate{
		Hostname:        hostname,
		MachineType:     string(machine.MachineType),
		DiscoverySource: strings.TrimSpace(machine.DiscoverySource),
		LastSeen:        "never",
	}
	if !machine.LastSeenAt.IsZero() {
		candidate.LastSeen = machine.LastSeenAt.UTC().Format("2006-01-02 15:04 UTC")
	}
	if candidate.MachineType == "" {
		candidate.MachineType = "unknown type"
	}
	if candidate.DiscoverySource == "" {
		candidate.DiscoverySource = "unknown source"
	}
	candidate.Detection = fleetDetectionDescription(machine.Tags)
	if strings.HasPrefix(strings.ToLower(hostname), "urn:") || !fleetHostPattern.MatchString(hostname) {
		candidate.Reason = "invalid hostname or IP"
		return candidate
	}
	if !isDeployableMachineType(machine.MachineType) {
		candidate.Reason = "device type is not deployable"
		return candidate
	}
	if machine.IsAuthorized == model.AuthorizationUnauthorized {
		candidate.Reason = "machine is marked unauthorized"
		return candidate
	}

	osName, err := normalizeDiscoveredFleetOS(machine.OSFamily)
	if err != nil {
		if strings.EqualFold(strings.TrimSpace(machine.DiscoverySource), "network_scan") {
			if fleetCanAutoDetectUnix(hostname, machine.Tags) {
				candidate.OS = "auto"
				candidate.Arch = "auto"
				candidate.TargetLine = hostname + ",auto,auto"
				candidate.Compatible = true
				candidate.Detection = "Linux or macOS will be detected automatically over SSH"
				return candidate
			}
			candidate.NeedsOSSelection = true
			candidate.Reason = fleetUnknownOSReason(machine.Tags)
			candidate.TargetWindows = hostname + ",windows,amd64"
			candidate.TargetLinuxAMD64 = hostname + ",linux,amd64"
			candidate.TargetLinuxARM64 = hostname + ",linux,arm64"
			candidate.TargetMacAMD64 = hostname + ",macos,amd64"
			candidate.TargetMacARM64 = hostname + ",macos,arm64"
			return candidate
		}
		candidate.Reason = "unsupported or unknown OS"
		return candidate
	}
	candidate.OS = osName

	archValue := strings.TrimSpace(machine.Architecture)
	if archValue == "" {
		if osName == "macos" {
			candidate.Reason = "macOS architecture is required"
			return candidate
		}
		candidate.Arch = "amd64"
		candidate.ArchInferred = true
	} else {
		candidate.Arch, err = normalizeFleetArch(archValue)
		if err != nil {
			candidate.Reason = "unsupported architecture"
			return candidate
		}
	}
	if osName == "windows" && candidate.Arch != "amd64" {
		candidate.Reason = "Windows release requires amd64"
		return candidate
	}
	candidate.TargetLine = strings.Join([]string{hostname, candidate.OS, candidate.Arch}, ",")
	if strings.EqualFold(candidate.DiscoverySource, "local_controller") {
		candidate.TargetLine += ",local"
	}
	candidate.Compatible = true
	return candidate
}

type fleetDetectionTags struct {
	OpenPorts  []int  `json:"network_scan_open_ports"`
	Confidence string `json:"deployment_os_confidence"`
	Evidence   string `json:"deployment_os_evidence"`
	SSHBanner  string `json:"ssh_banner"`
}

func parseFleetDetectionTags(raw string) fleetDetectionTags {
	var tags fleetDetectionTags
	_ = json.Unmarshal([]byte(raw), &tags)
	return tags
}

func fleetCanAutoDetectUnix(_ string, raw string) bool {
	tags := parseFleetDetectionTags(raw)
	banner := strings.ToLower(tags.SSHBanner)
	// A generic OpenSSH banner is not proof that a target is a computer:
	// routers, switches and NAS appliances commonly expose it too. Only an
	// OS-identifying banner is strong enough for unattended deployment.
	hasComputerOS := strings.Contains(banner, "ubuntu") ||
		strings.Contains(banner, "debian") ||
		strings.Contains(banner, "freebsd") ||
		strings.Contains(banner, "darwin") ||
		strings.Contains(banner, "macos")
	return hasComputerOS && strings.Contains(banner, "openssh") &&
		!strings.Contains(banner, "openssh_for_windows") &&
		!strings.Contains(banner, "dropbear") &&
		!strings.Contains(banner, "openwrt")
}

func fleetDetectionDescription(raw string) string {
	tags := parseFleetDetectionTags(raw)
	if tags.Confidence == "high" && tags.Evidence != "" {
		return "OS detected with high confidence · " + tags.Evidence
	}
	return ""
}

func fleetUnknownOSReason(raw string) string {
	tags := parseFleetDetectionTags(raw)
	has := func(wanted int) bool {
		for _, port := range tags.OpenPorts {
			if port == wanted {
				return true
			}
		}
		return false
	}
	switch {
	case has(3389) || has(445) || has(135) || has(139):
		return "Windows-like signals found; enable WinRM or choose OS"
	case has(22):
		return "SSH found; choose Linux or macOS"
	default:
		return "OS not confirmed; choose it"
	}
}

func isDeployableMachineType(machineType model.MachineType) bool {
	switch machineType {
	case model.MachineTypeServer,
		model.MachineTypeWorkstation,
		model.MachineTypeCloudInstance,
		model.MachineTypeVirtualMachine:
		return true
	default:
		return false
	}
}

func normalizeDiscoveredFleetOS(value string) (string, error) {
	if normalized, err := normalizeFleetOS(value); err == nil {
		return normalized, nil
	}
	lower := strings.ToLower(strings.TrimSpace(value))
	switch {
	case strings.Contains(lower, "windows"):
		return "windows", nil
	case strings.Contains(lower, "macos"), strings.Contains(lower, "mac os"),
		strings.Contains(lower, "os x"), strings.Contains(lower, "darwin"):
		return "macos", nil
	case strings.Contains(lower, "linux"), strings.Contains(lower, "ubuntu"),
		strings.Contains(lower, "debian"), strings.Contains(lower, "red hat"),
		strings.Contains(lower, "rhel"), strings.Contains(lower, "fedora"),
		strings.Contains(lower, "centos"), strings.Contains(lower, "alpine"),
		strings.Contains(lower, "suse"):
		return "linux", nil
	default:
		return "", fmt.Errorf("unsupported OS %q", strings.TrimSpace(value))
	}
}

func parseFleetTargets(raw string) ([]fleetTarget, error) {
	reader := csv.NewReader(strings.NewReader(raw))
	reader.TrimLeadingSpace = true
	reader.FieldsPerRecord = -1

	seen := make(map[string]struct{})
	targets := make([]fleetTarget, 0)
	for line := 1; ; line++ {
		record, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("targets line %d is not valid CSV", line)
		}
		if len(record) == 0 || strings.TrimSpace(record[0]) == "" || strings.HasPrefix(strings.TrimSpace(record[0]), "#") {
			continue
		}
		if line == 1 && strings.EqualFold(strings.TrimSpace(record[0]), "hostname") {
			continue
		}
		if len(record) < 2 || len(record) > 4 {
			return nil, fmt.Errorf("targets line %d must be hostname,os,arch", line)
		}
		hostname := strings.TrimSpace(record[0])
		if !fleetHostPattern.MatchString(hostname) {
			return nil, fmt.Errorf("targets line %d has an invalid hostname", line)
		}
		key := strings.ToLower(hostname)
		if _, exists := seen[key]; exists {
			return nil, fmt.Errorf("targets line %d duplicates hostname %q", line, hostname)
		}
		seen[key] = struct{}{}

		osName, err := normalizeFleetOS(record[1])
		if err != nil {
			return nil, fmt.Errorf("targets line %d: %w", line, err)
		}
		arch := "amd64"
		if osName == "auto" {
			arch = "auto"
		}
		if len(record) == 3 && strings.TrimSpace(record[2]) != "" {
			arch, err = normalizeFleetArch(record[2])
			if err != nil {
				return nil, fmt.Errorf("targets line %d: %w", line, err)
			}
		}
		if osName == "windows" && arch != "amd64" {
			return nil, fmt.Errorf("targets line %d: Windows releases currently support amd64 only", line)
		}
		if osName == "auto" && arch != "auto" {
			return nil, fmt.Errorf("targets line %d: automatic Unix detection requires automatic architecture", line)
		}
		local := false
		if len(record) == 4 {
			switch strings.ToLower(strings.TrimSpace(record[3])) {
			case "", "remote":
			case "local":
				local = true
			default:
				return nil, fmt.Errorf("targets line %d has an invalid connection mode", line)
			}
		}
		targets = append(targets, fleetTarget{Hostname: hostname, OS: osName, Arch: arch, Local: local})
		if len(targets) > maxFleetTargets {
			return nil, fmt.Errorf("a deployment package supports at most %d targets", maxFleetTargets)
		}
	}
	sort.SliceStable(targets, func(i, j int) bool {
		if targets[i].OS == targets[j].OS {
			return targets[i].Hostname < targets[j].Hostname
		}
		return targets[i].OS < targets[j].OS
	})
	return targets, nil
}

func normalizeFleetOS(value string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "windows", "win":
		return "windows", nil
	case "linux", "ubuntu", "debian", "rhel", "redhat", "fedora", "centos":
		return "linux", nil
	case "macos", "darwin", "osx":
		return "macos", nil
	case "auto", "unix", "linux-or-macos":
		return "auto", nil
	default:
		return "", fmt.Errorf("unsupported OS %q", strings.TrimSpace(value))
	}
}

func normalizeFleetArch(value string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "auto", "detect":
		return "auto", nil
	case "amd64", "x86_64", "x64":
		return "amd64", nil
	case "arm64", "aarch64":
		return "arm64", nil
	default:
		return "", fmt.Errorf("unsupported architecture %q", strings.TrimSpace(value))
	}
}

func writeFleetBundle(w io.Writer, req fleetBundleRequest, targets []fleetTarget) error {
	for _, target := range targets {
		if len(strings.TrimSpace(req.EnrollmentTokens[target.Hostname])) < 20 {
			return fmt.Errorf("missing enrollment credential for target %s", target.Hostname)
		}
	}
	zw := zip.NewWriter(w)
	files := map[string]string{
		"README.md":                    fleetBundleReadme(req, targets),
		"ansible.cfg":                  fleetAnsibleConfig,
		"deploy.sh":                    fleetDeployScript(targets),
		"inventory/hosts.yml":          fleetInventoryYAML(req, targets),
		"inventory/group_vars/all.yml": fleetAllVarsYAML(req),
		"playbooks/deploy.yml":         fleetPlaybookYAML,
		"targets.csv":                  fleetTargetsCSV(targets),
	}
	manifest, err := json.MarshalIndent(map[string]any{
		"created_at":    time.Now().UTC().Format(time.RFC3339),
		"pki_endpoint":  req.PKIEndpoint,
		"target_count":  len(targets),
		"version":       req.Version,
		"windows_count": countFleetOS(targets, "windows"),
		"linux_count":   countFleetOS(targets, "linux"),
		"macos_count":   countFleetOS(targets, "macos"),
		"auto_count":    countFleetOS(targets, "auto"),
	}, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal deployment manifest: %w", err)
	}
	files["deployment.json"] = string(manifest) + "\n"

	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		header := &zip.FileHeader{Name: name, Method: zip.Deflate}
		// ZIP's portable timestamp range starts in 1980. Keeping a fixed value
		// makes generated bundles reproducible without showing a misleading
		// 1969 date in time zones west of UTC.
		header.SetModTime(time.Date(1980, time.January, 1, 12, 0, 0, 0, time.UTC))
		if name == "deploy.sh" {
			header.SetMode(0o700)
		} else {
			header.SetMode(0o600)
		}
		entry, createErr := zw.CreateHeader(header)
		if createErr != nil {
			return fmt.Errorf("create bundle entry %s: %w", name, createErr)
		}
		if _, writeErr := io.WriteString(entry, files[name]); writeErr != nil {
			return fmt.Errorf("write bundle entry %s: %w", name, writeErr)
		}
	}
	if err := zw.Close(); err != nil {
		return fmt.Errorf("close deployment bundle: %w", err)
	}
	return nil
}

func fleetInventoryYAML(req fleetBundleRequest, targets []fleetTarget) string {
	var b strings.Builder
	b.WriteString("---\nall:\n  children:\n")
	for _, group := range []string{"windows", "linux", "macos", "unix_auto"} {
		b.WriteString("    " + group + ":\n      hosts:\n")
		found := false
		for _, target := range targets {
			targetGroup := target.OS
			if targetGroup == "auto" {
				targetGroup = "unix_auto"
			}
			if targetGroup != group {
				continue
			}
			found = true
			b.WriteString("        " + strconv.Quote(target.Hostname) + ":\n")
			b.WriteString("          kite_asset_arch: " + strconv.Quote(target.Arch) + "\n")
			b.WriteString("          kite_agent_code: " + strconv.Quote(fleetAgentCode(target.Hostname)) + "\n")
			if target.Local {
				b.WriteString("          kite_connection: local\n")
			}
			tokenB64 := base64.StdEncoding.EncodeToString([]byte(req.EnrollmentTokens[target.Hostname]))
			b.WriteString("          kite_enrollment_token_b64: " + strconv.Quote(tokenB64) + "\n")
		}
		if !found {
			b.WriteString("        {}\n")
		}
	}
	return b.String()
}

func fleetAgentCode(hostname string) string {
	sum := sha256.Sum256([]byte(strings.ToLower(strings.TrimSpace(hostname))))
	return fmt.Sprintf("kite-%x", sum[:10])
}

func fleetAllVarsYAML(req fleetBundleRequest) string {
	return fmt.Sprintf(`---
kite_version: %s
kite_release_base: %s
kite_pki_endpoint: %s
`, strconv.Quote(req.Version),
		strconv.Quote("https://github.com/VulnerTrack/kite-collector/releases/download/v"+req.Version),
		strconv.Quote(req.PKIEndpoint))
}

func fleetTargetsCSV(targets []fleetTarget) string {
	var b strings.Builder
	b.WriteString("hostname,os,arch,connection\n")
	for _, target := range targets {
		connection := "remote"
		if target.Local {
			connection = "local"
		}
		fmt.Fprintf(&b, "%s,%s,%s,%s\n", target.Hostname, target.OS, target.Arch, connection)
	}
	return b.String()
}

func fleetBundleReadme(req fleetBundleRequest, targets []fleetTarget) string {
	return fmt.Sprintf(`# Kite Collector fleet deployment

This confidential package installs and enrolls Kite Collector %s on %d computers.

Run from a Linux control node that can reach Windows over WinRM and Unix hosts over SSH:

    ./deploy.sh

The script prompts for infrastructure credentials at runtime. Those credentials are exported only to the child Ansible process and are never written into this package.
Each target receives a deterministic, unique agent code derived from its hostname or IP.
For SSH targets marked automatic, the playbook runs uname itself, validates Linux/macOS and CPU architecture, and saves the result to detected-platforms.csv. The operator does not run detection commands manually.

Security:

- This ZIP contains one single-use, two-hour enrollment credential per computer. Do not email it or commit it.
- Delete the extracted directory and ZIP after the run.
- Unused credentials expire automatically; revoke the deployment if the ZIP is exposed.
- Windows targets require WinRM; Linux/macOS targets require SSH and sudo.
`, req.Version, len(targets))
}

func countFleetOS(targets []fleetTarget, osName string) int {
	count := 0
	for _, target := range targets {
		if target.OS == osName {
			count++
		}
	}
	return count
}

const fleetAnsibleConfig = `[defaults]
inventory = inventory/hosts.yml
forks = 20
timeout = 60
retry_files_enabled = False

[winrm]
operation_timeout_sec = 60
read_timeout_sec = 90
`

func fleetDeployScript(targets []fleetTarget) string {
	hasWindows := countFleetOS(targets, "windows") > 0
	hasRemoteUnix := false
	hasLocalUnix := false
	for _, target := range targets {
		if target.OS == "linux" || target.OS == "macos" || target.OS == "auto" {
			if target.Local {
				hasLocalUnix = true
			} else {
				hasRemoteUnix = true
			}
		}
	}
	return fmt.Sprintf(`#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

if ! command -v python3 >/dev/null 2>&1; then
  echo "error: python3 is required on this Linux control node" >&2
  exit 1
fi

install_python_venv() {
  if [ "$(id -u)" -eq 0 ]; then
    privilege=()
  elif command -v sudo >/dev/null 2>&1; then
    privilege=(sudo)
  else
    echo "error: creating the Ansible runtime requires root or sudo to install Python venv support" >&2
    return 1
  fi

  echo "Python venv support is missing; installing the operating-system package..."
  if command -v apt-get >/dev/null 2>&1; then
    "${privilege[@]}" apt-get update
    "${privilege[@]}" apt-get install -y python3-venv
  elif command -v dnf >/dev/null 2>&1; then
    "${privilege[@]}" dnf install -y python3 python3-pip
  elif command -v yum >/dev/null 2>&1; then
    "${privilege[@]}" yum install -y python3 python3-pip
  elif command -v pacman >/dev/null 2>&1; then
    "${privilege[@]}" pacman -Sy --needed --noconfirm python python-pip
  elif command -v zypper >/dev/null 2>&1; then
    "${privilege[@]}" zypper --non-interactive install python3 python3-pip
  elif command -v apk >/dev/null 2>&1; then
    "${privilege[@]}" apk add python3 py3-pip py3-virtualenv
  else
    echo "error: unsupported Linux package manager; install Python venv support and run ./deploy.sh again" >&2
    return 1
  fi
}

if [ ! -x .venv/bin/ansible-playbook ]; then
  echo "Preparing isolated Ansible runtime..."
  if ! python3 -m venv .venv; then
    install_python_venv
    python3 -m venv .venv || {
      echo "error: Python venv support is still unavailable after package installation" >&2
      exit 1
    }
  fi
  .venv/bin/pip install --quiet --upgrade pip
  .venv/bin/pip install --quiet ansible 'pywinrm>=0.4.3'
  .venv/bin/ansible-galaxy collection install ansible.windows
fi

export KITE_WINDOWS_USER=""
export KITE_WINDOWS_PASSWORD=""
export KITE_SSH_USER=""
export KITE_SSH_KEY=""
export KITE_BECOME_PASSWORD=""

if %t; then
  read -r -p "Windows domain user (DOMAIN\\user): " KITE_WINDOWS_USER
  read -r -s -p "Windows password: " KITE_WINDOWS_PASSWORD
  echo
  export KITE_WINDOWS_USER KITE_WINDOWS_PASSWORD
fi
if %t; then
  read -r -p "SSH user for Linux/macOS: " KITE_SSH_USER
  read -r -p "SSH private key [${HOME}/.ssh/id_rsa]: " KITE_SSH_KEY
  KITE_SSH_KEY="${KITE_SSH_KEY:-${HOME}/.ssh/id_rsa}"
  export KITE_SSH_USER KITE_SSH_KEY
fi

if %t; then
  echo "Enter the sudo password for the Linux/macOS computers. Nothing will appear while you type."
  read -r -s -p "Sudo password: " KITE_BECOME_PASSWORD
  echo
  export KITE_BECOME_PASSWORD
fi

args=(playbooks/deploy.yml)
if %t; then args+=(--ask-become-pass); fi
.venv/bin/ansible-playbook "${args[@]}"

if %t; then
  echo "Restarting the local Kite Collector dashboard with the collected data..."
  if command -v docker >/dev/null 2>&1; then
    docker rm -f kite-collector-local >/dev/null 2>&1 || true
  fi
  printf '%%s\n' "$KITE_BECOME_PASSWORD" | sudo -S -p '' systemctl restart kite-collector
  dashboard_url="http://127.0.0.1:9090/machines"
  if command -v curl >/dev/null 2>&1; then
    echo "Waiting for the initial machine and software inventory..."
    for _ in $(seq 1 90); do
      machines_page="$(curl -fsS http://127.0.0.1:9090/machines 2>/dev/null || true)"
      software_page="$(curl -fsS http://127.0.0.1:9090/software 2>/dev/null || true)"
      if [ -n "$machines_page" ] && [ -n "$software_page" ] &&
         ! grep -q 'Machines (0)' <<<"$machines_page" &&
         ! grep -q 'Software (0)' <<<"$software_page"; then
        break
      fi
      sleep 1
    done
  fi
  echo "Opening Kite Collector: ${dashboard_url}"
  if command -v xdg-open >/dev/null 2>&1; then
    xdg-open "$dashboard_url" >/dev/null 2>&1 &
  fi
fi

unset KITE_WINDOWS_PASSWORD
unset KITE_BECOME_PASSWORD
echo "Deployment finished. Verify fleet heartbeats, then delete this package."
`, hasWindows, hasRemoteUnix, hasLocalUnix || hasRemoteUnix, hasRemoteUnix, hasLocalUnix)
}

const fleetPlaybookYAML = `---
- name: Deploy Kite Collector to Windows
  hosts: windows
  gather_facts: false
  serial:
    - 1
    - 5
    - 25
  max_fail_percentage: 10
  vars:
    ansible_connection: winrm
    ansible_winrm_transport: ntlm
    ansible_winrm_message_encryption: always
    ansible_port: 5985
    ansible_user: "{{ lookup('env', 'KITE_WINDOWS_USER') }}"
    ansible_password: "{{ lookup('env', 'KITE_WINDOWS_PASSWORD') }}"
    kite_msi_name: "kite-collector_{{ kite_version }}_amd64.msi"
    kite_msi_path: "C:\\ProgramData\\VulnerTrack\\packages\\{{ kite_msi_name }}"
    kite_executable: 'C:\Program Files\Kite Collector\kite-collector.exe'
    kite_data_dir: 'C:\ProgramData\kite-collector'
  tasks:
    - name: Create package directory
      ansible.windows.win_file:
        path: 'C:\ProgramData\VulnerTrack\packages'
        state: directory
    - name: Download and verify MSI
      ansible.windows.win_get_url:
        url: "{{ kite_release_base }}/{{ kite_msi_name }}"
        dest: "{{ kite_msi_path }}"
        checksum_url: "{{ kite_release_base }}/{{ kite_msi_name }}.sha256"
        checksum_algorithm: sha256
        force: false
    - name: Install or update collector
      ansible.windows.win_package:
        path: "{{ kite_msi_path }}"
        provider: msi
        state: present
    - name: Stop service during enrollment check
      ansible.windows.win_service:
        name: kite-collector
        state: stopped
    - name: Check enrollment certificate
      ansible.windows.win_stat:
        path: '{{ kite_data_dir }}\agent.pem'
      register: kite_windows_cert
    - name: Enroll Windows collector
      ansible.windows.win_command:
        argv:
          - "{{ kite_executable }}"
          - enroll
          - --agent-code
          - "{{ kite_agent_code }}"
          - --enrollment-token
          - "{{ kite_enrollment_token_b64 | b64decode }}"
          - --certs-dir
          - "{{ kite_data_dir }}"
        creates: '{{ kite_data_dir }}\agent.pem'
      environment:
        KITE_PKI_ENDPOINT: "{{ kite_pki_endpoint }}"
      when: not kite_windows_cert.stat.exists
      no_log: true
    - name: Start Windows collector
      ansible.windows.win_service:
        name: kite-collector
        start_mode: auto
        state: started

- name: Detect Linux or macOS automatically
  hosts: unix_auto
  gather_facts: false
  serial: 25
  vars:
    ansible_connection: "{{ kite_connection | default('ssh') }}"
    ansible_user: "{{ lookup('env', 'KITE_SSH_USER') }}"
    ansible_ssh_private_key_file: "{{ lookup('env', 'KITE_SSH_KEY') }}"
    ansible_become_password: "{{ lookup('env', 'KITE_BECOME_PASSWORD') }}"
  pre_tasks:
    - name: Initialize local platform detection report
      ansible.builtin.copy:
        content: "hostname,os,arch\n"
        dest: "{{ playbook_dir }}/../detected-platforms.csv"
        mode: '0600'
      delegate_to: localhost
      become: false
      run_once: true
  tasks:
    - name: Read remote kernel and architecture
      ansible.builtin.raw: >-
        kernel="$(uname -s)";
        if [ "$kernel" = "Linux" ]; then
          test ! -f /etc/openwrt_release;
          test ! -d /etc/config;
          test -f /etc/os-release;
          command -v systemctl >/dev/null;
          ! command -v ubus >/dev/null 2>&1;
          ! command -v opkg >/dev/null 2>&1;
        elif [ "$kernel" = "Darwin" ]; then
          command -v sw_vers >/dev/null;
        else
          exit 2;
        fi;
        printf '%s\n%s\n' "$kernel" "$(uname -m)"
      register: kite_uname
      changed_when: false
    - name: Normalize detected platform
      ansible.builtin.set_fact:
        kite_detected_kernel: "{{ (kite_uname.stdout_lines | first) | trim }}"
        kite_detected_machine: "{{ (kite_uname.stdout_lines | last) | trim }}"
    - name: Refuse unsupported or ambiguous platforms
      ansible.builtin.assert:
        that:
          - kite_detected_kernel in ['Linux', 'Darwin']
          - kite_detected_machine in ['x86_64', 'amd64', 'aarch64', 'arm64']
        fail_msg: "Host is not a supported Linux/macOS computer; nothing was installed"
    - name: Add host to its detected deployment group
      ansible.builtin.add_host:
        name: "{{ inventory_hostname }}"
        groups: "{{ 'macos' if kite_detected_kernel == 'Darwin' else 'linux' }}"
        kite_asset_arch: "{{ 'arm64' if kite_detected_machine in ['aarch64', 'arm64'] else 'amd64' }}"
        kite_agent_code: "{{ hostvars[inventory_hostname].kite_agent_code }}"
    - name: Save detected platform in local report
      ansible.builtin.lineinfile:
        path: "{{ playbook_dir }}/../detected-platforms.csv"
        line: "{{ inventory_hostname }},{{ 'macos' if kite_detected_kernel == 'Darwin' else 'linux' }},{{ 'arm64' if kite_detected_machine in ['aarch64', 'arm64'] else 'amd64' }}"
        create: true
        mode: '0600'
      delegate_to: localhost
      become: false
      throttle: 1

- name: Deploy Kite Collector to Linux and macOS
  hosts: linux:macos
  gather_facts: false
  become: true
  serial:
    - 1
    - 5
    - 25
  max_fail_percentage: 10
  vars:
    ansible_connection: "{{ kite_connection | default('ssh') }}"
    ansible_user: "{{ lookup('env', 'KITE_SSH_USER') }}"
    ansible_ssh_private_key_file: "{{ lookup('env', 'KITE_SSH_KEY') }}"
    ansible_become_password: "{{ lookup('env', 'KITE_BECOME_PASSWORD') }}"
    kite_asset_os: "{{ 'darwin' if inventory_hostname in groups['macos'] else 'linux' }}"
    kite_archive_name: "kite-collector_{{ kite_asset_os }}_{{ kite_asset_arch }}.tar.gz"
    kite_stage_dir: "/tmp/kite-collector-{{ kite_version }}"
    kite_data_dir: "/var/lib/kite-collector"
  tasks:
    - name: Create staging directory
      ansible.builtin.file:
        path: "{{ kite_stage_dir }}"
        state: directory
        mode: '0700'
    - name: Download and verify release archive
      ansible.builtin.get_url:
        url: "{{ kite_release_base }}/{{ kite_archive_name }}"
        dest: "{{ kite_stage_dir }}/{{ kite_archive_name }}"
        checksum: "sha256:{{ kite_release_base }}/checksums.txt"
        mode: '0600'
    - name: Extract release archive
      ansible.builtin.unarchive:
        src: "{{ kite_stage_dir }}/{{ kite_archive_name }}"
        dest: "{{ kite_stage_dir }}"
        remote_src: true
    - name: Install collector binary
      ansible.builtin.copy:
        src: "{{ kite_stage_dir }}/kite-collector"
        dest: /usr/local/bin/kite-collector
        remote_src: true
        mode: '0755'
    - name: Check enrollment certificate
      ansible.builtin.stat:
        path: "{{ kite_data_dir }}/agent.pem"
      register: kite_unix_cert
    - name: Register collector service
      ansible.builtin.command:
        argv:
          - /usr/local/bin/kite-collector
          - install
          - --no-start
      when: not kite_unix_cert.stat.exists
    - name: Enroll Unix collector
      ansible.builtin.command:
        argv:
          - /usr/local/bin/kite-collector
          - enroll
          - --agent-code
          - "{{ kite_agent_code }}"
          - --enrollment-token
          - "{{ kite_enrollment_token_b64 | b64decode }}"
          - --certs-dir
          - "{{ kite_data_dir }}"
        creates: "{{ kite_data_dir }}/agent.pem"
      environment:
        KITE_PKI_ENDPOINT: "{{ kite_pki_endpoint }}"
      no_log: true
    - name: Start collector service
      ansible.builtin.service:
        name: kite-collector
        enabled: true
        state: started
`
