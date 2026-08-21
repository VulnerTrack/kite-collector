package software

import (
	"context"
	"fmt"
	"runtime"
	"strings"

	"github.com/google/uuid"

	"github.com/vulnertrack/kite-collector/internal/discovery/agent/windowssoftware"
	"github.com/vulnertrack/kite-collector/internal/model"
)

// WindowsRegistry adapts the comprehensive Windows Uninstall registry probe
// into the cross-platform InstalledSoftware inventory shown by the dashboard.
// It covers machine-wide 64/32-bit installers and per-user installers from
// every loaded user hive, independently of winget or Chocolatey availability.
type WindowsRegistry struct {
	collector windowssoftware.Collector
}

func NewWindowsRegistry() *WindowsRegistry {
	return &WindowsRegistry{collector: windowssoftware.NewCollector()}
}

func (w *WindowsRegistry) Name() string { return "windows-registry" }

func (w *WindowsRegistry) Available() bool { return runtime.GOOS == "windows" }

func (w *WindowsRegistry) Collect(ctx context.Context) (*Result, error) {
	inventory, err := w.collector.Collect(ctx)
	if err != nil {
		return nil, fmt.Errorf("windows uninstall registry: %w", err)
	}
	return WindowsProgramsToSoftware(inventory.Programs), nil
}

// WindowsProgramsToSoftware maps named registry entries to the main software
// model. Nameless registry stubs are deliberately excluded: they cannot be
// presented meaningfully and are still retained in host_windows_programs for
// forensic inspection.
func WindowsProgramsToSoftware(programs []windowssoftware.Program) *Result {
	result := &Result{Items: make([]model.InstalledSoftware, 0, len(programs))}
	for _, program := range programs {
		name := strings.TrimSpace(program.DisplayName)
		if name == "" {
			continue
		}
		architecture := ""
		if program.Source == windowssoftware.SourceRegistryHKLMWow64 {
			architecture = "x86"
		}
		description := "Windows installed program"
		if program.IsPerUser {
			description += "; per-user installation"
		}
		if program.IsSystemComponent {
			description += "; system component"
		}
		item := model.InstalledSoftware{
			ID:             uuid.Must(uuid.NewV7()),
			SoftwareName:   name,
			Vendor:         strings.TrimSpace(program.Publisher),
			Version:        strings.TrimSpace(program.DisplayVersion),
			PackageManager: string(program.Source),
			Architecture:   architecture,
			Description:    description,
			InstallPath:    strings.TrimSpace(program.InstallLocation),
		}
		item.CPE23 = BuildCPE23(item.Vendor, item.SoftwareName, item.Version)
		result.Items = append(result.Items, item)
	}
	result.Sort()
	return result
}

var _ Collector = (*WindowsRegistry)(nil)
