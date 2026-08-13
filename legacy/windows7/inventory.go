package main

import (
	"bytes"
	"context"
	"encoding/csv"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strings"
	"time"
	"unicode/utf16"
	"unicode/utf8"

	"golang.org/x/text/encoding/charmap"
	"golang.org/x/text/transform"
)

// inventorySnapshot is deliberately generic: Windows 7 exposes valuable
// inventory through several stable inbox CLIs (WMIC, reg, netsh, schtasks),
// each with a different schema. Keeping each row as string fields preserves
// every value without forcing a lossy lowest-common-denominator model.
type inventorySnapshot struct {
	CollectedAt time.Time                      `json:"collected_at"`
	Hostname    string                         `json:"hostname"`
	Categories  map[string][]map[string]string `json:"categories"`
	Errors      map[string]string              `json:"errors,omitempty"`
}

type inventoryProbe struct {
	name string
	exe  string
	args []string
	csv  bool
}

var inventoryProbes = []inventoryProbe{
	{name: "system", exe: "systeminfo.exe", args: []string{"/FO", "CSV"}, csv: true},
	{name: "computer_system", exe: "wmic.exe", args: []string{"computersystem", "get", "Manufacturer,Model,Name,Domain,TotalPhysicalMemory,NumberOfProcessors,SystemType,UserName,Workgroup", "/format:csv"}, csv: true},
	{name: "operating_system", exe: "wmic.exe", args: []string{"os", "get", "Caption,Version,BuildNumber,OSArchitecture,SerialNumber,InstallDate,LastBootUpTime,WindowsDirectory,Locale,ServicePackMajorVersion", "/format:csv"}, csv: true},
	{name: "processors", exe: "wmic.exe", args: []string{"cpu", "get", "Name,Manufacturer,Architecture,AddressWidth,NumberOfCores,NumberOfLogicalProcessors,MaxClockSpeed,ProcessorId", "/format:csv"}, csv: true},
	{name: "memory", exe: "wmic.exe", args: []string{"memorychip", "get", "BankLabel,Capacity,DeviceLocator,Manufacturer,PartNumber,SerialNumber,Speed", "/format:csv"}, csv: true},
	{name: "bios", exe: "wmic.exe", args: []string{"bios", "get", "Manufacturer,Name,SerialNumber,SMBIOSBIOSVersion,ReleaseDate,Version", "/format:csv"}, csv: true},
	{name: "baseboard", exe: "wmic.exe", args: []string{"baseboard", "get", "Manufacturer,Product,SerialNumber,Version", "/format:csv"}, csv: true},
	{name: "video_controllers", exe: "wmic.exe", args: []string{"path", "Win32_VideoController", "get", "Name,AdapterCompatibility,AdapterRAM,DriverVersion,PNPDeviceID,Status,VideoModeDescription", "/format:csv"}, csv: true},
	{name: "sound_devices", exe: "wmic.exe", args: []string{"path", "Win32_SoundDevice", "get", "Name,Manufacturer,PNPDeviceID,Status", "/format:csv"}, csv: true},
	{name: "batteries", exe: "wmic.exe", args: []string{"path", "Win32_Battery", "get", "Name,DeviceID,BatteryStatus,EstimatedChargeRemaining,EstimatedRunTime,Status", "/format:csv"}, csv: true},
	{name: "pnp_devices", exe: "wmic.exe", args: []string{"path", "Win32_PnPEntity", "get", "Name,Manufacturer,PNPClass,PNPDeviceID,Service,Status,ConfigManagerErrorCode", "/format:csv"}, csv: true},
	{name: "physical_disks", exe: "wmic.exe", args: []string{"diskdrive", "get", "Model,InterfaceType,MediaType,SerialNumber,Size,Status,Partitions", "/format:csv"}, csv: true},
	{name: "volumes", exe: "wmic.exe", args: []string{"logicaldisk", "get", "DeviceID,DriveType,FileSystem,FreeSpace,Size,VolumeName,VolumeSerialNumber", "/format:csv"}, csv: true},
	{name: "network_adapters", exe: "wmic.exe", args: []string{"nicconfig", "where", "IPEnabled=true", "get", "Description,DHCPEnabled,DHCPServer,DNSDomain,IPAddress,IPSubnet,DefaultIPGateway,MACAddress,DNSServerSearchOrder", "/format:csv"}, csv: true},
	{name: "hotfixes", exe: "wmic.exe", args: []string{"qfe", "get", "HotFixID,Description,InstalledBy,InstalledOn,Caption", "/format:csv"}, csv: true},
	{name: "users", exe: "wmic.exe", args: []string{"useraccount", "get", "Name,Domain,SID,Disabled,Lockout,LocalAccount,PasswordExpires,PasswordRequired,Status", "/format:csv"}, csv: true},
	{name: "groups", exe: "wmic.exe", args: []string{"group", "get", "Name,Domain,SID,LocalAccount,Status", "/format:csv"}, csv: true},
	{name: "services", exe: "wmic.exe", args: []string{"service", "get", "Name,DisplayName,State,StartMode,StartName,PathName,ProcessId,Status", "/format:csv"}, csv: true},
	{name: "processes", exe: "wmic.exe", args: []string{"process", "get", "Name,ProcessId,ParentProcessId,ExecutablePath,CreationDate,ThreadCount,WorkingSetSize", "/format:csv"}, csv: true},
	{name: "startup", exe: "wmic.exe", args: []string{"startup", "get", "Name,Command,Location,User", "/format:csv"}, csv: true},
	{name: "shares", exe: "wmic.exe", args: []string{"share", "get", "Name,Path,Description,Status,Type", "/format:csv"}, csv: true},
	{name: "printers", exe: "wmic.exe", args: []string{"printer", "get", "Name,DriverName,PortName,Default,Network,Shared,ShareName,Status", "/format:csv"}, csv: true},
	{name: "antivirus", exe: "wmic.exe", args: []string{"/namespace:\\\\root\\SecurityCenter2", "path", "AntiVirusProduct", "get", "displayName,pathToSignedProductExe,pathToSignedReportingExe,productState,timestamp", "/format:csv"}, csv: true},
	{name: "drivers", exe: "driverquery.exe", args: []string{"/FO", "CSV", "/V"}, csv: true},
	{name: "scheduled_tasks", exe: "schtasks.exe", args: []string{"/Query", "/FO", "CSV", "/V"}, csv: true},
	{name: "routes", exe: "route.exe", args: []string{"PRINT"}},
	{name: "arp", exe: "arp.exe", args: []string{"-a"}},
	{name: "local_groups", exe: "net.exe", args: []string{"localgroup"}},
	{name: "sessions", exe: "query.exe", args: []string{"user"}},
	{name: "network_configuration", exe: "ipconfig.exe", args: []string{"/all"}},
	{name: "listening_ports", exe: "netstat.exe", args: []string{"-ano"}},
	{name: "firewall", exe: "netsh.exe", args: []string{"advfirewall", "show", "allprofiles"}},
	{name: "audit_policy", exe: "auditpol.exe", args: []string{"/get", "/category:*", "/r"}, csv: true},
	{name: "bitlocker", exe: "manage-bde.exe", args: []string{"-status"}},
	{name: "time_sync", exe: "w32tm.exe", args: []string{"/query", "/status"}},
	{name: "event_logs", exe: "wevtutil.exe", args: []string{"el"}},
	{name: "certificates_machine_personal", exe: "certutil.exe", args: []string{"-store", "My"}},
	{name: "certificates_machine_root", exe: "certutil.exe", args: []string{"-store", "Root"}},
}

func collectInventory(ctx context.Context) inventorySnapshot {
	hostname := strings.TrimSpace(runText(ctx, "hostname.exe"))
	snapshot := inventorySnapshot{
		CollectedAt: time.Now().UTC(),
		Hostname:    hostname,
		Categories:  make(map[string][]map[string]string),
		Errors:      make(map[string]string),
	}
	for _, probe := range inventoryProbes {
		output, err := runProbe(ctx, probe.exe, probe.args...)
		if err != nil {
			snapshot.Errors[probe.name] = err.Error()
			continue
		}
		var rows []map[string]string
		if probe.csv {
			rows, err = parseCSVRows(output)
		} else {
			rows = parseTextRows(output)
		}
		if err != nil {
			snapshot.Errors[probe.name] = err.Error()
			continue
		}
		snapshot.Categories[probe.name] = rows
	}
	softwareRoots := map[string]string{
		"installed_software_native": `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`,
		"installed_software_wow64":  `HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall`,
	}
	for category, root := range softwareRoots {
		output, err := runProbe(ctx, "reg.exe", "query", root, "/s")
		if err != nil {
			// Wow64 is absent on a 32-bit operating system; represent that as an
			// empty category instead of a failed collector.
			if category == "installed_software_wow64" {
				snapshot.Categories[category] = nil
				continue
			}
			snapshot.Errors[category] = err.Error()
			continue
		}
		snapshot.Categories[category] = parseInstalledApplications(output, category)
	}
	for category, roots := range map[string][]string{
		"run_keys": {`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`, `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`},
	} {
		var rows []map[string]string
		for _, root := range roots {
			output, err := runProbe(ctx, "reg.exe", "query", root, "/s")
			if err != nil {
				snapshot.Errors[category+":"+root] = err.Error()
				continue
			}
			rows = append(rows, parseRegistryRows(output)...)
		}
		snapshot.Categories[category] = rows
	}
	if len(snapshot.Errors) == 0 {
		snapshot.Errors = nil
	}
	return snapshot
}

func runText(ctx context.Context, exe string, args ...string) string {
	out, _ := runProbe(ctx, exe, args...)
	return string(out)
}

func runProbe(parent context.Context, exe string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(parent, 90*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, exe, args...)
	cmd.Env = os.Environ()
	out, err := cmd.CombinedOutput()
	out = decodeWindowsOutput(out)
	if ctx.Err() != nil {
		return out, fmt.Errorf("timed out after 90s")
	}
	if err != nil {
		return out, fmt.Errorf("%s: %v: %s", exe, err, strings.TrimSpace(string(out)))
	}
	return bytes.TrimSpace(out), nil
}

// decodeWindowsOutput normalizes the encodings emitted by Windows 7 inbox
// tools. WMIC may emit UTF-16LE while localized console programs use the OEM
// code page (CP850 on the Spanish installations this compatibility agent
// targets). UTF-8 is preserved when a newer tool already emits it.
func decodeWindowsOutput(data []byte) []byte {
	if len(data) >= 2 && data[0] == 0xff && data[1] == 0xfe {
		return []byte(decodeUTF16LE(data[2:]))
	}
	if bytes.IndexByte(data, 0) >= 0 {
		return []byte(decodeUTF16LE(data))
	}
	if utf8.Valid(data) {
		return data
	}
	decoded, _, err := transform.Bytes(charmap.CodePage850.NewDecoder(), data)
	if err == nil {
		return decoded
	}
	decoded, _, err = transform.Bytes(charmap.Windows1252.NewDecoder(), data)
	if err == nil {
		return decoded
	}
	return bytes.ToValidUTF8(data, []byte("?"))
}

func decodeUTF16LE(data []byte) string {
	units := make([]uint16, 0, len(data)/2)
	for i := 0; i+1 < len(data); i += 2 {
		units = append(units, uint16(data[i])|uint16(data[i+1])<<8)
	}
	return string(utf16.Decode(units))
}

func parseCSVRows(data []byte) ([]map[string]string, error) {
	clean := bytes.TrimPrefix(bytes.TrimSpace(data), []byte{0xef, 0xbb, 0xbf})
	reader := csv.NewReader(bytes.NewReader(clean))
	reader.FieldsPerRecord = -1
	records, err := reader.ReadAll()
	if err != nil {
		return nil, fmt.Errorf("parse CSV: %w", err)
	}
	if len(records) < 2 {
		return nil, nil
	}
	headers := records[0]
	rows := make([]map[string]string, 0, len(records)-1)
	for _, record := range records[1:] {
		row := make(map[string]string)
		nonempty := false
		for i, value := range record {
			if i >= len(headers) {
				break
			}
			key := strings.TrimSpace(headers[i])
			value = strings.TrimSpace(value)
			if key != "" {
				row[key] = value
			}
			if value != "" {
				nonempty = true
			}
		}
		if nonempty {
			rows = append(rows, row)
		}
	}
	return rows, nil
}

func parseTextRows(data []byte) []map[string]string {
	var rows []map[string]string
	for _, line := range strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n") {
		if line = strings.TrimSpace(line); line != "" {
			rows = append(rows, map[string]string{"line": line})
		}
	}
	return rows
}

func parseRegistryRows(data []byte) []map[string]string {
	var rows []map[string]string
	current := ""
	for _, line := range strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		if strings.HasPrefix(strings.ToUpper(trimmed), "HKEY_") {
			current = trimmed
			continue
		}
		fields := strings.Fields(trimmed)
		if len(fields) < 3 || current == "" {
			continue
		}
		typeIndex := -1
		for i, field := range fields {
			if strings.HasPrefix(field, "REG_") {
				typeIndex = i
				break
			}
		}
		if typeIndex <= 0 {
			continue
		}
		value := strings.Join(fields[typeIndex+1:], " ")
		lowerName := strings.ToLower(strings.Join(fields[:typeIndex], " "))
		for _, sensitive := range []string{"password", "passwd", "token", "secret", "credential", "api_key", "apikey"} {
			if strings.Contains(lowerName, sensitive) {
				value = "[REDACTED]"
				break
			}
		}
		rows = append(rows, map[string]string{
			"key": current, "name": strings.Join(fields[:typeIndex], " "),
			"type": fields[typeIndex], "value": value,
		})
	}
	sort.Slice(rows, func(i, j int) bool {
		return rows[i]["key"]+rows[i]["name"] < rows[j]["key"]+rows[j]["name"]
	})
	return rows
}

func parseInstalledApplications(data []byte, source string) []map[string]string {
	byKey := make(map[string]map[string]string)
	current := ""
	for _, line := range strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		if strings.HasPrefix(strings.ToUpper(trimmed), "HKEY_") {
			current = trimmed
			if byKey[current] == nil {
				byKey[current] = map[string]string{"registry_key": current, "source": source}
			}
			continue
		}
		if current == "" {
			continue
		}
		fields := strings.Fields(trimmed)
		typeIndex := -1
		for i, field := range fields {
			if strings.HasPrefix(field, "REG_") {
				typeIndex = i
				break
			}
		}
		if typeIndex <= 0 {
			continue
		}
		name := strings.Join(fields[:typeIndex], " ")
		value := strings.Join(fields[typeIndex+1:], " ")
		switch strings.ToLower(name) {
		case "displayname":
			byKey[current]["name"] = value
		case "displayversion":
			byKey[current]["version"] = value
		case "publisher":
			byKey[current]["publisher"] = value
		case "installdate":
			byKey[current]["install_date"] = value
		case "installlocation":
			byKey[current]["install_location"] = value
		case "estimatedsize":
			byKey[current]["estimated_size_kb"] = value
		case "windowsinstaller":
			byKey[current]["windows_installer"] = value
		}
	}
	rows := make([]map[string]string, 0, len(byKey))
	for _, row := range byKey {
		if strings.TrimSpace(row["name"]) != "" {
			rows = append(rows, row)
		}
	}
	sort.Slice(rows, func(i, j int) bool {
		return strings.ToLower(rows[i]["name"]) < strings.ToLower(rows[j]["name"])
	})
	return rows
}
