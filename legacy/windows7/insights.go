package main

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

type inventorySummary struct {
	OS       string
	Model    string
	CPU      string
	Memory   string
	Disk     string
	IP       string
	Uptime   string
	Software int
	Services int
	Ports    int
}

type securityFinding struct {
	Severity string
	Title    string
	Detail   string
	Category string
}

type categoryChange struct {
	Category string
	Before   int
	After    int
	Delta    int
}

func summarizeInventory(snapshot *inventorySnapshot) inventorySummary {
	s := inventorySummary{}
	if row := firstRow(snapshot, "operating_system"); row != nil {
		s.OS = firstValue(row, "Caption", "OS Name")
		s.Uptime = firstValue(row, "LastBootUpTime", "System Boot Time")
	}
	if row := firstRow(snapshot, "computer_system"); row != nil {
		s.Model = strings.TrimSpace(firstValue(row, "Manufacturer") + " " + firstValue(row, "Model"))
		if raw := firstValue(row, "TotalPhysicalMemory"); raw != "" {
			if value, err := strconv.ParseUint(raw, 10, 64); err == nil {
				s.Memory = fmt.Sprintf("%.1f GB", float64(value)/(1024*1024*1024))
			}
		}
	}
	if row := firstRow(snapshot, "processors"); row != nil {
		s.CPU = firstValue(row, "Name")
	}
	if row := firstRow(snapshot, "physical_disks"); row != nil {
		s.Disk = firstValue(row, "Model")
		if raw := firstValue(row, "Size"); raw != "" {
			if value, err := strconv.ParseUint(raw, 10, 64); err == nil {
				s.Disk += fmt.Sprintf(" (%.1f GB)", float64(value)/(1024*1024*1024))
			}
		}
	}
	if row := firstRow(snapshot, "network_adapters"); row != nil {
		s.IP = firstValue(row, "IPAddress")
	}
	s.Software = len(snapshot.Categories["installed_software_native"]) + len(snapshot.Categories["installed_software_wow64"])
	s.Services = len(snapshot.Categories["services"])
	s.Ports = len(snapshot.Categories["listening_ports"])
	return s
}

func firstRow(snapshot *inventorySnapshot, category string) map[string]string {
	if rows := snapshot.Categories[category]; len(rows) > 0 {
		return rows[0]
	}
	return nil
}

func firstValue(row map[string]string, keys ...string) string {
	for _, key := range keys {
		if value := strings.TrimSpace(row[key]); value != "" {
			return value
		}
	}
	return ""
}

func buildSecurityFindings(snapshot *inventorySnapshot) []securityFinding {
	var findings []securityFinding
	text := func(category string) string {
		var b strings.Builder
		for _, row := range snapshot.Categories[category] {
			for _, value := range row {
				b.WriteString(strings.ToLower(value))
				b.WriteByte('\n')
			}
		}
		return b.String()
	}
	firewall := text("firewall")
	if firewall == "" {
		findings = append(findings, securityFinding{"high", "Firewall status unavailable", "Kite could not read Windows Firewall state.", "firewall"})
	} else if strings.Contains(firewall, "state off") || strings.Contains(firewall, "estado desactivado") {
		findings = append(findings, securityFinding{"high", "Windows Firewall disabled", "At least one firewall profile reports an OFF state.", "firewall"})
	}
	if len(snapshot.Categories["antivirus"]) == 0 {
		findings = append(findings, securityFinding{"high", "No antivirus reported", "Windows Security Center did not report an antivirus product.", "antivirus"})
	}
	ports := text("listening_ports")
	for _, risky := range []struct{ port, service string }{{":23", "Telnet"}, {":21", "FTP"}, {":445", "SMB"}, {":3389", "RDP"}} {
		if strings.Contains(ports, risky.port) {
			findings = append(findings, securityFinding{"medium", risky.service + " port listening", "A local listener was detected on TCP " + strings.TrimPrefix(risky.port, ":") + ".", "listening_ports"})
		}
	}
	if len(snapshot.Categories["hotfixes"]) == 0 {
		findings = append(findings, securityFinding{"medium", "No hotfix inventory", "No installed Windows hotfixes were returned.", "hotfixes"})
	}
	if strings.Contains(text("time_sync"), "error") || len(snapshot.Categories["time_sync"]) == 0 {
		findings = append(findings, securityFinding{"medium", "Time synchronization unavailable", "Certificate validation and event correlation require an accurate clock.", "time_sync"})
	}
	for category, errText := range snapshot.Errors {
		findings = append(findings, securityFinding{"info", "Collector unavailable: " + category, errText, category})
	}
	order := map[string]int{"high": 0, "medium": 1, "low": 2, "info": 3}
	sort.Slice(findings, func(i, j int) bool { return order[findings[i].Severity] < order[findings[j].Severity] })
	return findings
}

func compareSnapshots(current, previous *inventorySnapshot) []categoryChange {
	if current == nil || previous == nil {
		return nil
	}
	names := make(map[string]struct{})
	for name := range current.Categories {
		names[name] = struct{}{}
	}
	for name := range previous.Categories {
		names[name] = struct{}{}
	}
	var changes []categoryChange
	for name := range names {
		before, after := len(previous.Categories[name]), len(current.Categories[name])
		if before != after {
			changes = append(changes, categoryChange{name, before, after, after - before})
		}
	}
	sort.Slice(changes, func(i, j int) bool { return changes[i].Category < changes[j].Category })
	return changes
}

var categorySections = []struct {
	Name       string
	Categories []string
}{
	{"Overview", []string{"machines", "system", "operating_system", "computer_system"}},
	{"Hardware", []string{"processors", "memory", "bios", "baseboard", "video_controllers", "sound_devices", "batteries", "pnp_devices", "physical_disks", "volumes"}},
	{"Software", []string{"installed_software_native", "installed_software_wow64", "hotfixes"}},
	{"Network", []string{"network_adapters", "network_configuration", "listening_ports", "routes", "arp"}},
	{"Identity", []string{"users", "groups", "local_groups", "sessions"}},
	{"Runtime", []string{"services", "processes", "startup", "run_keys", "scheduled_tasks"}},
	{"Security", []string{"antivirus", "firewall", "audit_policy", "bitlocker", "certificates_machine_personal", "certificates_machine_root", "time_sync"}},
	{"Devices", []string{"drivers", "printers", "shares", "event_logs"}},
}
