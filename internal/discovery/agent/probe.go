package agent

import (
	"bufio"
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/vulnertrack/kite-collector/internal/discovery/agent/software"
	"github.com/vulnertrack/kite-collector/internal/model"
)

// Probe implements discovery.Source by inspecting the local host. It collects
// hostname, OS details, network interfaces, and optionally installed software.
type Probe struct{}

// New returns a new agent Probe.
func New() *Probe {
	return &Probe{}
}

// Name returns the stable identifier for this source.
func (p *Probe) Name() string { return "agent" }

// Discover collects information about the local host and returns a single
// Asset representing it.
//
// Supported config keys:
//
//	collect_software   – bool; when true, attempt to enumerate installed packages
//	collect_interfaces – bool; when true (default), enumerate network interfaces
func (p *Probe) Discover(ctx context.Context, cfg map[string]any) ([]model.Asset, error) {
	hostname, err := os.Hostname()
	if err != nil {
		return nil, fmt.Errorf("agent probe: hostname: %w", err)
	}

	osFamily := runtime.GOOS
	osVersion := readOSVersion()

	now := time.Now().UTC()

	asset := model.Asset{
		AssetType:       assetTypeForOS(osFamily),
		Hostname:        hostname,
		OSFamily:        osFamily,
		OSVersion:       osVersion,
		KernelVersion:   readKernelVersion(),
		Architecture:    runtime.GOARCH,
		DiscoverySource: "agent",
		FirstSeenAt:     now,
		LastSeenAt:      now,
		IsAuthorized:    model.AuthorizationUnknown,
		IsManaged:       model.ManagedUnknown,
	}

	assets := []model.Asset{asset}

	// Collect network interfaces if not explicitly disabled.
	collectInterfaces := true
	if ci, ok := cfg["collect_interfaces"].(bool); ok {
		collectInterfaces = ci
	}

	if collectInterfaces {
		ifaces, err := collectNetworkInterfaces()
		if err != nil {
			slog.Warn("agent probe: failed to collect interfaces", "error", err)
		} else {
			slog.Info("agent probe: collected interfaces", "count", len(ifaces))
			// Store interfaces as a detail we can use after dedup assigns IDs.
			_ = ifaces // Interfaces are collected but require an asset ID to persist.
			// Callers should use CollectNetworkInterfaces directly after dedup.
		}
	}

	// Collect installed software if requested.
	collectSoftware := false
	if cs, ok := cfg["collect_software"].(bool); ok {
		collectSoftware = cs
	}
	if collectSoftware {
		software, err := collectInstalledSoftware(ctx)
		if err != nil {
			slog.Warn("agent probe: failed to collect software", "error", err)
		} else {
			slog.Info("agent probe: collected software", "count", len(software))
		}
	}

	return assets, nil
}

// assetTypeForOS maps a GOOS value to an AssetType.
func assetTypeForOS(goos string) model.AssetType {
	switch goos {
	case "darwin", "windows":
		return model.AssetTypeWorkstation
	default:
		return model.AssetTypeServer
	}
}

// readOSVersion attempts to read /etc/os-release on Linux. For other
// operating systems it falls back to runtime.GOOS/GOARCH.
func readOSVersion() string {
	if runtime.GOOS == "linux" {
		f, err := os.Open("/etc/os-release")
		if err == nil {
			defer func() { _ = f.Close() }()
			scanner := bufio.NewScanner(f)
			for scanner.Scan() {
				line := scanner.Text()
				if strings.HasPrefix(line, "PRETTY_NAME=") {
					val := strings.TrimPrefix(line, "PRETTY_NAME=")
					val = strings.Trim(val, "\"")
					return val
				}
			}
		}
	}
	return fmt.Sprintf("%s/%s", runtime.GOOS, runtime.GOARCH)
}

// readKernelVersion reads the running kernel version. On Linux it reads
// /proc/version and extracts the version string. On other platforms it
// falls back to runtime.GOARCH.
func readKernelVersion() string {
	if runtime.GOOS == "linux" {
		data, err := os.ReadFile("/proc/version")
		if err == nil {
			// /proc/version format: "Linux version 6.1.0-amd64 (...) ..."
			fields := strings.Fields(string(data))
			if len(fields) >= 3 {
				return fields[2]
			}
		}
	}
	return ""
}

// CollectNetworkInterfaces enumerates the host's network interfaces and
// returns model objects for each address found. The caller must set the
// AssetID field on each returned interface.
func CollectNetworkInterfaces() ([]model.NetworkInterface, error) {
	return collectNetworkInterfaces()
}

func collectNetworkInterfaces() ([]model.NetworkInterface, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("list interfaces: %w", err)
	}

	var result []model.NetworkInterface
	first := true

	for _, iface := range ifaces {
		// Skip loopback and down interfaces.
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		if iface.Flags&net.FlagUp == 0 {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			slog.Warn("agent probe: failed to get addrs",
				"interface", iface.Name, "error", err)
			continue
		}

		mac := iface.HardwareAddr.String()

		for _, addr := range addrs {
			ipNet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}
			ip := ipNet.IP
			if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
				continue
			}

			ni := model.NetworkInterface{
				ID:            uuid.Must(uuid.NewV7()),
				InterfaceName: iface.Name,
				IPAddress:     ip.String(),
				MACAddress:    mac,
				Subnet:        ipNet.String(),
				IsPrimary:     first,
				IsPublic:      !ip.IsPrivate(),
			}
			result = append(result, ni)
			first = false
		}
	}

	return result, nil
}

// CollectInstalledSoftware enumerates installed packages on the host using
// all available package manager collectors (dpkg, pacman, rpm).
func CollectInstalledSoftware(ctx context.Context) ([]model.InstalledSoftware, error) {
	return collectInstalledSoftware(ctx)
}

func collectInstalledSoftware(ctx context.Context) ([]model.InstalledSoftware, error) {
	reg := software.NewRegistry()
	result := reg.Collect(ctx)
	if result.HasErrors() {
		slog.Warn("agent probe: software parse errors", "count", result.TotalErrors())
	}
	return result.Items, nil
}

// ensure Probe satisfies the discovery.Source interface at compile time.
var _ interface {
	Name() string
	Discover(ctx context.Context, cfg map[string]any) ([]model.Asset, error)
} = (*Probe)(nil)
