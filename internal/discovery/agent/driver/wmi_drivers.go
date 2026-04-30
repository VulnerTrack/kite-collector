package driver

import (
	"context"
	"encoding/json"
	"fmt"
	"runtime"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/vulnertrack/kite-collector/internal/discovery/agent/software"
)

// WMIDrivers enumerates Windows kernel drivers via WMI through PowerShell.
// Equivalent of `Get-CimInstance -ClassName Win32_SystemDriver | ConvertTo-Json`,
// merged with `Get-CimInstance -ClassName Win32_PnPSignedDriver | ConvertTo-Json`.
//
// Why PowerShell instead of a WMI Go binding: keeps the agent pure-Go,
// CGO_ENABLED=0, and dependency-free. The cost is a single per-collect
// process spawn capped at execTimeout.
type WMIDrivers struct {
	now            func() time.Time
	powershellPath string // overridable for tests
}

// NewWMIDrivers constructs a WMIDrivers with the default PowerShell path.
func NewWMIDrivers() *WMIDrivers {
	return &WMIDrivers{
		powershellPath: "powershell.exe",
		now:            func() time.Time { return time.Now().UTC() },
	}
}

// Name returns the registry identifier.
func (w *WMIDrivers) Name() string { return "windows-wmi-drivers" }

// Available returns true on Windows hosts only.
func (w *WMIDrivers) Available() bool {
	return runtime.GOOS == "windows"
}

// systemDriverRow models the JSON shape produced by Win32_SystemDriver.
type systemDriverRow struct {
	Name        string `json:"Name"`
	DisplayName string `json:"DisplayName"`
	PathName    string `json:"PathName"`
	Description string `json:"Description"`
	State       string `json:"State"`
	StartMode   string `json:"StartMode"`
	ServiceType string `json:"ServiceType"`
}

// pnpSignedDriverRow models the JSON shape produced by Win32_PnPSignedDriver.
type pnpSignedDriverRow struct {
	DeviceName    string `json:"DeviceName"`
	DriverName    string `json:"DriverName"`
	Manufacturer  string `json:"Manufacturer"`
	DriverVersion string `json:"DriverVersion"`
	Signer        string `json:"Signer"`
	HardwareID    string `json:"HardwareID"`
	InfName       string `json:"InfName"`
	IsSigned      bool   `json:"IsSigned"`
}

// Collect runs WMI queries and merges them into a single Result.
func (w *WMIDrivers) Collect(ctx context.Context) (*Result, error) {
	res := &Result{}
	now := w.now()

	systemDrivers, err := w.querySystemDrivers(ctx)
	if err != nil {
		return nil, fmt.Errorf("Win32_SystemDriver: %w", err)
	}
	for _, sd := range systemDrivers {
		drv := LoadedDriver{
			ID:              uuid.Must(uuid.NewV7()),
			CollectedAt:     now,
			Name:            sd.Name,
			DisplayName:     sd.DisplayName,
			Path:            sd.PathName,
			Description:     sd.Description,
			State:           sd.State,
			StartMode:       sd.StartMode,
			DriverFramework: classifyServiceType(sd.ServiceType),
			Architecture:    runtime.GOARCH,
		}
		res.Drivers = append(res.Drivers, drv)
	}

	signed, err := w.queryPnPSignedDrivers(ctx)
	if err == nil {
		applyPnPSignedAttrs(res.Drivers, signed)
	}

	res.Sort()
	return res, nil
}

// querySystemDrivers calls PowerShell and parses the resulting JSON array.
func (w *WMIDrivers) querySystemDrivers(ctx context.Context) ([]systemDriverRow, error) {
	out, err := runWithLimits(ctx, w.powershellPath, "-NoProfile", "-NonInteractive", "-Command",
		"Get-CimInstance -ClassName Win32_SystemDriver | "+
			"Select-Object Name,DisplayName,PathName,Description,State,StartMode,ServiceType | "+
			"ConvertTo-Json -Depth 2 -Compress")
	if err != nil {
		return nil, err
	}
	return parseSystemDriverJSON(out)
}

// queryPnPSignedDrivers fetches signature/manufacturer info for PnP devices.
func (w *WMIDrivers) queryPnPSignedDrivers(ctx context.Context) ([]pnpSignedDriverRow, error) {
	out, err := runWithLimits(ctx, w.powershellPath, "-NoProfile", "-NonInteractive", "-Command",
		"Get-CimInstance -ClassName Win32_PnPSignedDriver | "+
			"Select-Object DeviceName,DriverName,Manufacturer,DriverVersion,Signer,IsSigned,HardwareID,InfName | "+
			"ConvertTo-Json -Depth 2 -Compress")
	if err != nil {
		return nil, err
	}
	return parsePnPSignedDriverJSON(out)
}

// parseSystemDriverJSON tolerates the PowerShell single-object-vs-array quirk:
// when only one row matches, ConvertTo-Json emits an object; for many rows it
// emits an array.
func parseSystemDriverJSON(raw []byte) ([]systemDriverRow, error) {
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" {
		return nil, nil
	}
	if trimmed[0] == '[' {
		var rows []systemDriverRow
		if err := json.Unmarshal(raw, &rows); err != nil {
			return nil, fmt.Errorf("unmarshal Win32_SystemDriver array: %w", err)
		}
		return rows, nil
	}
	var single systemDriverRow
	if err := json.Unmarshal(raw, &single); err != nil {
		return nil, fmt.Errorf("unmarshal Win32_SystemDriver row: %w", err)
	}
	return []systemDriverRow{single}, nil
}

// parsePnPSignedDriverJSON mirrors parseSystemDriverJSON for PnP rows.
func parsePnPSignedDriverJSON(raw []byte) ([]pnpSignedDriverRow, error) {
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" {
		return nil, nil
	}
	if trimmed[0] == '[' {
		var rows []pnpSignedDriverRow
		if err := json.Unmarshal(raw, &rows); err != nil {
			return nil, fmt.Errorf("unmarshal Win32_PnPSignedDriver array: %w", err)
		}
		return rows, nil
	}
	var single pnpSignedDriverRow
	if err := json.Unmarshal(raw, &single); err != nil {
		return nil, fmt.Errorf("unmarshal Win32_PnPSignedDriver row: %w", err)
	}
	return []pnpSignedDriverRow{single}, nil
}

// applyPnPSignedAttrs decorates already-collected drivers with signer/version
// info from the PnP table when their service-name matches.
func applyPnPSignedAttrs(drivers []LoadedDriver, signed []pnpSignedDriverRow) {
	byName := make(map[string]pnpSignedDriverRow, len(signed))
	for _, s := range signed {
		key := strings.ToLower(strings.TrimSpace(s.DriverName))
		if key == "" {
			continue
		}
		byName[key] = s
	}
	for i := range drivers {
		key := strings.ToLower(strings.TrimSpace(drivers[i].Name))
		s, ok := byName[key]
		if !ok {
			continue
		}
		if s.Signer != "" {
			drivers[i].Signer = s.Signer
			drivers[i].SignatureState = SignatureValid
			if drivers[i].Vendor == "" {
				drivers[i].Vendor = strings.TrimSpace(strings.SplitN(s.Signer, ",", 2)[0])
			}
		} else if s.IsSigned {
			drivers[i].SignatureState = SignatureValid
		}
		if s.DriverVersion != "" {
			drivers[i].Version = s.DriverVersion
		}
		if drivers[i].Vendor == "" && s.Manufacturer != "" {
			drivers[i].Vendor = s.Manufacturer
		}
		drivers[i].CPE23 = software.BuildCPE23WithTargetSW(drivers[i].Vendor, drivers[i].Name, drivers[i].Version, "windows")
	}
}

// classifyServiceType maps Win32_SystemDriver.ServiceType (2/4/8/16/32) to
// the corresponding RFC-0128 framework label. Anything else degrades to WDM.
//
//	Service type    Meaning
//	1               Kernel Driver
//	2               File System Driver
//	4               Adapter
//	8               Recognizer Driver
func classifyServiceType(s string) string {
	switch strings.TrimSpace(s) {
	case "1", "Kernel Driver":
		return FrameworkWDM
	case "2", "File System Driver":
		return FrameworkWDM
	default:
		return FrameworkWDM
	}
}
