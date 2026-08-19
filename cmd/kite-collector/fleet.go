package main

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/vulnertrack/kite-collector/internal/dashboard"
)

type fleetDiscoverResponse struct {
	Network     string                  `json:"network"`
	CompletedAt string                  `json:"completed_at"`
	Error       string                  `json:"error,omitempty"`
	Found       int                     `json:"found"`
	Inserted    int                     `json:"inserted"`
	Updated     int                     `json:"updated"`
	Computers   []fleetDiscoverComputer `json:"computers"`
}

type fleetDiscoverComputer struct {
	Hostname         string `json:"hostname"`
	Address          string `json:"address,omitempty"`
	OS               string `json:"os,omitempty"`
	Arch             string `json:"arch,omitempty"`
	DiscoverySource  string `json:"discovery_source,omitempty"`
	Detection        string `json:"detection,omitempty"`
	Reason           string `json:"reason,omitempty"`
	Target           string `json:"target,omitempty"`
	Compatible       bool   `json:"compatible"`
	NeedsOSSelection bool   `json:"needs_os_selection"`
}

var errFleetDiscoveryInProgress = errors.New("network discovery is already running")

type fleetSignInRequiredError struct {
	URL string
}

func (e *fleetSignInRequiredError) Error() string {
	return "dashboard sign-in required before deployment: " + e.URL
}

var (
	openFleetLogin = dashboard.OpenBrowser
	waitFleetLogin = waitForDashboardEnrollment
)

func newFleetCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "fleet",
		Short: "Discover computers and deploy collectors",
	}
	discover := newFleetDiscoverCmd()
	discover.GroupID = "fleet-discover"
	deploy := newFleetDeployCmd()
	deploy.GroupID = "fleet-deploy"
	cmd.AddGroup(
		&cobra.Group{ID: "fleet-discover", Title: "Step 1 — Discover computers:"},
		&cobra.Group{ID: "fleet-deploy", Title: "Step 2 — Deploy collectors:"},
	)
	cmd.AddCommand(discover, deploy)
	return cmd
}

func newFleetDiscoverCmd() *cobra.Command {
	var (
		dashboardURL string
		timeout      time.Duration
		jsonOutput   bool
	)
	cmd := &cobra.Command{
		Use:   "discover",
		Short: "Find computers using the same scan as Discover computers",
		Long: `Ask the running local dashboard to scan the controller's local network.
The scan combines TCP, mDNS, NetBIOS, SSDP, and WS-Discovery and stores the
results in the same encrypted inventory used by mass deployment.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runFleetDiscover(cmd, dashboardURL, timeout, jsonOutput)
		},
	}
	cmd.Flags().StringVar(&dashboardURL, "dashboard-url", "http://127.0.0.1:9090", "local Kite dashboard URL")
	cmd.Flags().DurationVar(&timeout, "timeout", 75*time.Second, "maximum time to wait for discovery")
	cmd.Flags().BoolVar(&jsonOutput, "json", false, "print the discovery result as JSON")
	return cmd
}

func runFleetDiscover(cmd *cobra.Command, dashboardURL string, timeout time.Duration, jsonOutput bool) error {
	if !jsonOutput {
		_, _ = fmt.Fprintln(cmd.OutOrStdout(), "Discovering computers on the local network...")
	}
	result, err := requestFleetDiscovery(cmd.Context(), dashboardURL, timeout)
	if err != nil {
		return err
	}

	if jsonOutput {
		encoder := json.NewEncoder(cmd.OutOrStdout())
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(result); err != nil {
			return fmt.Errorf("encode fleet discovery result: %w", err)
		}
		return nil
	}

	out := cmd.OutOrStdout()
	_, _ = fmt.Fprintf(out, "Network: %s · found %d · added %d · updated %d\n\n",
		result.Network, result.Found, result.Inserted, result.Updated)
	w := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
	_, _ = fmt.Fprintln(w, "HOSTNAME\tADDRESS\tPLATFORM\tSTATUS\tSOURCE")
	for _, computer := range result.Computers {
		platform := strings.Trim(strings.Join([]string{computer.OS, computer.Arch}, "/"), "/")
		status := "ready"
		if computer.NeedsOSSelection {
			status = "choose OS"
		} else if !computer.Compatible {
			status = "skipped"
		}
		_, _ = fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n",
			computer.Hostname, computer.Address, platform, status, computer.DiscoverySource)
	}
	if err := w.Flush(); err != nil {
		return fmt.Errorf("write fleet discovery output: %w", err)
	}
	_, _ = fmt.Fprintf(out, "\nCompleted: %s\n", result.CompletedAt)
	return nil
}

func requestFleetDiscovery(parent context.Context, dashboardURL string, timeout time.Duration) (fleetDiscoverResponse, error) {
	endpoint, err := fleetEndpoint(dashboardURL, "/api/v1/fleet/discover")
	if err != nil {
		return fleetDiscoverResponse{}, err
	}
	if parent == nil {
		parent = context.Background()
	}
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, nil)
	if err != nil {
		return fleetDiscoverResponse{}, fmt.Errorf("create fleet discovery request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	resp, err := (&http.Client{Timeout: timeout}).Do(req)
	if err != nil {
		return fleetDiscoverResponse{}, fmt.Errorf("contact local Kite dashboard at %s: %w", dashboardURL, err)
	}
	defer func() { _ = resp.Body.Close() }()

	var result fleetDiscoverResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return fleetDiscoverResponse{}, fmt.Errorf("decode fleet discovery response (HTTP %d): %w", resp.StatusCode, err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		if result.Error == "" {
			result.Error = resp.Status
		}
		if resp.StatusCode == http.StatusConflict {
			return fleetDiscoverResponse{}, fmt.Errorf("%w: %s", errFleetDiscoveryInProgress, result.Error)
		}
		return fleetDiscoverResponse{}, fmt.Errorf("fleet discovery failed: %s", result.Error)
	}
	return result, nil
}

func fleetEndpoint(dashboardURL, path string) (string, error) {
	base, err := url.Parse(strings.TrimSpace(dashboardURL))
	if err != nil || base.Scheme == "" || base.Host == "" {
		return "", fmt.Errorf("invalid dashboard URL %q", dashboardURL)
	}
	if base.Scheme != "http" && base.Scheme != "https" {
		return "", fmt.Errorf("dashboard URL must use http or https")
	}
	base.Path = strings.TrimRight(base.Path, "/") + path
	base.RawQuery = ""
	base.Fragment = ""
	return base.String(), nil
}

func newFleetDeployCmd() *cobra.Command {
	var (
		dashboardURL string
		timeout      time.Duration
		packageOnly  bool
		output       string
	)
	cmd := &cobra.Command{
		Use:   "deploy [hostname-or-address]",
		Short: "Deploy collectors to all compatible discovered computers",
		Long: `Discover remote computers, mint one short-lived enrollment credential
per computer, and run one mass deployment interactively. Windows credentials
are read by the deployment runner and are never sent to or stored by Kite.

With no argument, the collector is deployed to the local controller and every compatible remote computer found in the scan.
An optional hostname or address limits deployment to that computer.`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			requested := ""
			if len(args) == 1 {
				requested = args[0]
			}
			return runFleetDeploy(cmd, dashboardURL, timeout, requested, packageOnly, output)
		},
	}
	cmd.Flags().StringVar(&dashboardURL, "dashboard-url", "http://127.0.0.1:9090", "local Kite dashboard URL")
	cmd.Flags().DurationVar(&timeout, "timeout", 75*time.Second, "maximum time to wait for discovery")
	cmd.Flags().BoolVar(&packageOnly, "package-only", false, "generate the deployment ZIP without running it")
	cmd.Flags().StringVarP(&output, "output", "o", "kite-deployment.zip", "ZIP path used with --package-only")
	return cmd
}

func runFleetDeploy(cmd *cobra.Command, dashboardURL string, timeout time.Duration, requested string, packageOnly bool, output string) error {
	ctx := cmd.Context()
	if ctx == nil {
		ctx = context.Background()
	}
	out := cmd.OutOrStdout()
	if strings.TrimSpace(requested) == "" {
		_, _ = fmt.Fprintln(out, "Loading computers from the latest fleet discovery...")
	} else {
		_, _ = fmt.Fprintf(out, "Loading %s from the latest fleet discovery...\n", requested)
	}
	result, err := requestFleetDiscoveryResults(ctx, dashboardURL, timeout)
	if err != nil {
		return err
	}
	var targets []fleetDiscoverComputer
	if strings.TrimSpace(requested) == "" {
		targets = fleetEnrollmentComputers(result.Computers)
		if len(targets) == 0 {
			return fmt.Errorf("no computer is currently available for deployment; run `kite-collector fleet discover` and verify the discovery result")
		}
	} else {
		target, selectErr := selectFleetComputer(result.Computers, requested)
		if selectErr != nil {
			return selectErr
		}
		targets = []fleetDiscoverComputer{target}
	}
	_, _ = fmt.Fprintf(out, "Computers selected for deployment: %d\n", len(targets))
	targetLines := make([]string, 0, len(targets))
	for _, target := range targets {
		_, _ = fmt.Fprintf(out, "  - %s · %s · %s/%s\n", target.Hostname, target.Address, target.OS, target.Arch)
		targetLines = append(targetLines, target.Target)
	}
	_, _ = fmt.Fprintln(out, "Generating one single-use enrollment credential per computer...")
	bundle, err := requestFleetPackage(ctx, dashboardURL, targetLines)
	var signInRequired *fleetSignInRequiredError
	if errors.As(err, &signInRequired) {
		if loginErr := completeFleetSignIn(ctx, out, signInRequired.URL); loginErr != nil {
			return loginErr
		}
		_, _ = fmt.Fprintln(out, "Sign-in completed. Generating the deployment package...")
		bundle, err = requestFleetPackage(ctx, dashboardURL, targetLines)
	}
	if err != nil {
		return err
	}

	if packageOnly {
		if writeErr := os.WriteFile(output, bundle, 0o600); writeErr != nil {
			return fmt.Errorf("write deployment package %s: %w", output, writeErr)
		}
		_, _ = fmt.Fprintf(out, "Deployment package written to %s (contains a short-lived secret).\n", output)
		return nil
	}

	workDir, err := os.MkdirTemp("", "kite-enroll-")
	if err != nil {
		return fmt.Errorf("create private deployment directory: %w", err)
	}
	removeWorkDir := false
	defer func() {
		if removeWorkDir {
			_ = os.RemoveAll(workDir)
		}
	}()
	if err := extractFleetBundle(bundle, workDir); err != nil {
		return fmt.Errorf("extract deployment package: %w", err)
	}
	_, _ = fmt.Fprintln(out, "Starting deployment. Enter the Windows administrator credentials when prompted.")
	deploy := exec.CommandContext(ctx, "bash", filepath.Join(workDir, "deploy.sh")) // #nosec G204 -- path is a validated entry from the locally generated bundle
	deploy.Dir = workDir
	deploy.Stdin = cmd.InOrStdin()
	deploy.Stdout = out
	deploy.Stderr = cmd.ErrOrStderr()
	if err := deploy.Run(); err != nil {
		return fmt.Errorf("deployment failed; retry files retained in %s: %w", workDir, err)
	}
	removeWorkDir = true
	_, _ = fmt.Fprintf(out, "Deployment completed for %d computer(s). Temporary credentials removed.\n", len(targets))
	return nil
}

func completeFleetSignIn(ctx context.Context, out io.Writer, loginURL string) error {
	parsed, err := url.Parse(loginURL)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" || parsed.Path != "/kite-login" {
		return fmt.Errorf("invalid dashboard sign-in URL %q", loginURL)
	}
	waitID := strings.TrimSpace(parsed.Query().Get("wait_id"))
	if waitID == "" {
		return fmt.Errorf("dashboard sign-in URL is missing its wait identifier")
	}
	baseURL := parsed.Scheme + "://" + parsed.Host
	_, _ = fmt.Fprintf(out, "VulnerTrack sign-in required. Opening your browser:\n%s\n", loginURL)
	openFleetLogin(loginURL)
	_, _ = fmt.Fprintln(out, "Waiting for sign-in to complete...")
	if err := waitFleetLogin(ctx, baseURL, waitID); err != nil {
		return fmt.Errorf("wait for dashboard sign-in: %w", err)
	}
	return nil
}

func requestFleetDiscoveryResults(parent context.Context, dashboardURL string, timeout time.Duration) (fleetDiscoverResponse, error) {
	endpoint, err := fleetEndpoint(dashboardURL, "/api/v1/fleet/discover")
	if err != nil {
		return fleetDiscoverResponse{}, err
	}
	if parent == nil {
		parent = context.Background()
	}
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return fleetDiscoverResponse{}, fmt.Errorf("create fleet discovery results request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	resp, err := (&http.Client{Timeout: timeout}).Do(req)
	if err != nil {
		return fleetDiscoverResponse{}, fmt.Errorf("contact local Kite dashboard at %s: %w", dashboardURL, err)
	}
	defer func() { _ = resp.Body.Close() }()
	var result fleetDiscoverResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return fleetDiscoverResponse{}, fmt.Errorf("decode fleet discovery results (HTTP %d): %w", resp.StatusCode, err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		if result.Error == "" {
			result.Error = resp.Status
		}
		return fleetDiscoverResponse{}, fmt.Errorf("load fleet discovery results: %s", result.Error)
	}
	return result, nil
}

func fleetEnrollmentComputers(computers []fleetDiscoverComputer) []fleetDiscoverComputer {
	available := make([]fleetDiscoverComputer, 0, len(computers))
	addressIndex := make(map[string]int)
	for _, computer := range computers {
		if computer.Compatible && !computer.NeedsOSSelection && strings.TrimSpace(computer.Target) != "" &&
			fleetComputerManagementReady(computer) {
			address := strings.ToLower(strings.TrimSpace(computer.Address))
			if index, exists := addressIndex[address]; address != "" && exists {
				// Discovery methods may report the same Windows host once by IP and
				// once by computer name. Keep the human-readable identity.
				if net.ParseIP(strings.TrimSpace(available[index].Hostname)) != nil && net.ParseIP(strings.TrimSpace(computer.Hostname)) == nil {
					available[index] = computer
				}
				continue
			}
			available = append(available, computer)
			if address != "" {
				addressIndex[address] = len(available) - 1
			}
		}
	}
	return available
}

func fleetComputerManagementReady(computer fleetDiscoverComputer) bool {
	source := strings.TrimSpace(computer.DiscoverySource)
	if strings.EqualFold(source, "local_controller") {
		return true
	}
	// The active TCP scanner emits network_scan only after the host answered
	// during the latest discovery. Identity protocols can retain stale IPs
	// advertised by a machine before it moved networks; those records remain
	// useful inventory, but must never mint credentials or enter deployment.
	return strings.EqualFold(source, "network_scan")
}

func selectFleetComputer(computers []fleetDiscoverComputer, requested string) (fleetDiscoverComputer, error) {
	requested = strings.TrimSpace(requested)
	var matches []fleetDiscoverComputer
	for _, computer := range computers {
		if strings.EqualFold(strings.TrimSpace(computer.Hostname), requested) {
			matches = append(matches, computer)
		}
	}
	if len(matches) == 0 {
		for _, computer := range computers {
			if strings.EqualFold(strings.TrimSpace(computer.Address), requested) {
				matches = append(matches, computer)
			}
		}
	}
	if len(matches) == 0 {
		return fleetDiscoverComputer{}, fmt.Errorf("computer %q was not found; run `kite-collector fleet discover` to list available computers", requested)
	}
	if len(matches) > 1 {
		return fleetDiscoverComputer{}, fmt.Errorf("%q matches %d discovery records; use its unique hostname", requested, len(matches))
	}
	target := matches[0]
	if target.NeedsOSSelection {
		return fleetDiscoverComputer{}, fmt.Errorf("operating system for %s could not be determined", target.Hostname)
	}
	if !target.Compatible || strings.TrimSpace(target.Target) == "" {
		reason := strings.TrimSpace(target.Reason)
		if reason == "" {
			reason = "the target is not compatible with automatic deployment"
		}
		return fleetDiscoverComputer{}, fmt.Errorf("cannot enroll %s: %s", target.Hostname, reason)
	}
	if !fleetComputerManagementReady(target) {
		return fleetDiscoverComputer{}, fmt.Errorf("cannot enroll %s: its management port did not answer in the latest discovery; run `kite-collector fleet discover` after the computer is online", target.Hostname)
	}
	return target, nil
}

func requestFleetPackage(ctx context.Context, dashboardURL string, targets []string) ([]byte, error) {
	endpoint, err := fleetEndpoint(dashboardURL, "/api/v1/fleet/package")
	if err != nil {
		return nil, err
	}
	form := url.Values{"discovered_target": targets}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("create fleet package request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/zip")
	client := &http.Client{CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request fleet deployment package: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode == http.StatusSeeOther {
		location := resp.Header.Get("Location")
		dashboardBase, baseErr := url.Parse(strings.TrimSpace(dashboardURL))
		if strings.HasPrefix(location, "/") {
			reference, referenceErr := url.Parse(location)
			if baseErr == nil && referenceErr == nil {
				location = dashboardBase.ResolveReference(reference).String()
			}
		}
		login, loginErr := url.Parse(location)
		if baseErr != nil || loginErr != nil || login.Scheme != dashboardBase.Scheme || login.Host != dashboardBase.Host || login.Path != "/kite-login" {
			return nil, fmt.Errorf("dashboard returned an invalid sign-in redirect")
		}
		return nil, &fleetSignInRequiredError{URL: login.String()}
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<10))
		message := strings.TrimSpace(string(body))
		if message == "" {
			message = resp.Status
		}
		return nil, fmt.Errorf("generate fleet deployment package: %s", message)
	}
	bundle, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if err != nil {
		return nil, fmt.Errorf("read fleet deployment package: %w", err)
	}
	if len(bundle) == 0 {
		return nil, fmt.Errorf("dashboard returned an empty deployment package")
	}
	return bundle, nil
}

// maxFleetBundleEntrySize caps the decompressed size of one deployment package
// entry so a malformed bundle cannot exhaust local disk during extraction.
const maxFleetBundleEntrySize = 256 << 20

func extractFleetBundle(bundle []byte, destination string) error {
	zr, err := zip.NewReader(bytes.NewReader(bundle), int64(len(bundle)))
	if err != nil {
		return fmt.Errorf("open deployment package: %w", err)
	}
	root, err := os.OpenRoot(destination)
	if err != nil {
		return fmt.Errorf("open deployment directory %s: %w", destination, err)
	}
	defer func() { _ = root.Close() }()
	for _, entry := range zr.File {
		name := filepath.Clean(entry.Name)
		if name == "." || filepath.IsAbs(name) || name == ".." || strings.HasPrefix(name, ".."+string(filepath.Separator)) {
			return fmt.Errorf("unsafe ZIP entry %q", entry.Name)
		}
		if entry.FileInfo().Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("symlink ZIP entry %q is not allowed", entry.Name)
		}
		if entry.FileInfo().IsDir() {
			if err := root.MkdirAll(name, 0o700); err != nil {
				return fmt.Errorf("create directory for ZIP entry %q: %w", entry.Name, err)
			}
			continue
		}
		if dir := filepath.Dir(name); dir != "." {
			if err := root.MkdirAll(dir, 0o700); err != nil {
				return fmt.Errorf("create parent directory for ZIP entry %q: %w", entry.Name, err)
			}
		}
		mode := os.FileMode(0o600)
		if entry.Mode()&0o100 != 0 {
			mode = 0o700
		}
		if err := extractFleetBundleFile(root, entry, name, mode); err != nil {
			return err
		}
	}
	return nil
}

func extractFleetBundleFile(root *os.Root, entry *zip.File, name string, mode os.FileMode) error {
	source, err := entry.Open()
	if err != nil {
		return fmt.Errorf("open ZIP entry %q: %w", entry.Name, err)
	}
	defer func() { _ = source.Close() }()
	destinationFile, err := root.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
	if err != nil {
		return fmt.Errorf("create file for ZIP entry %q: %w", entry.Name, err)
	}
	_, copyErr := io.CopyN(destinationFile, source, maxFleetBundleEntrySize+1)
	closeErr := destinationFile.Close()
	switch {
	case errors.Is(copyErr, io.EOF):
		// The whole entry fit under the extraction cap.
	case copyErr != nil:
		return fmt.Errorf("write ZIP entry %q: %w", entry.Name, copyErr)
	default:
		return fmt.Errorf("ZIP entry %q exceeds the %d byte extraction limit", entry.Name, maxFleetBundleEntrySize)
	}
	if closeErr != nil {
		return fmt.Errorf("close extracted ZIP entry %q: %w", entry.Name, closeErr)
	}
	return nil
}
