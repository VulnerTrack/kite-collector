package btnames

import (
	"bufio"
	"bytes"
	"strconv"
	"strings"
)

// BlueZInfo is the parsed view of a single
// /var/lib/bluetooth/<adapter>/<MAC>/info file. BlueZ stores per-
// device pairing state as an INI-style file with sections like
// `[General]`, `[DeviceID]`, `[LinkKey]`. We only read the
// non-cryptographic fields — never the keys themselves.
type BlueZInfo struct {
	Name          string
	Alias         string
	DeviceClass   DeviceClass
	Manufacturer  string
	AddressType   string
	LastConnected string
	Class         uint32
	IsBLE         bool
	IsTrusted     bool
	IsBlocked     bool
	IsConnected   bool
}

// ParseBlueZInfo parses a BlueZ per-device info file. Returns the
// zero value when the file is empty or unparseable; callers ignore
// rows whose Name + Alias are both empty.
func ParseBlueZInfo(body []byte) BlueZInfo {
	var out BlueZInfo
	if len(body) == 0 {
		return out
	}
	scanner := bufio.NewScanner(bytes.NewReader(body))
	scanner.Buffer(make([]byte, 0, 64*1024), 1<<20)
	var section string
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.TrimSpace(line[1 : len(line)-1])
			continue
		}
		eq := strings.Index(line, "=")
		if eq < 0 {
			continue
		}
		key := strings.TrimSpace(line[:eq])
		val := strings.TrimSpace(line[eq+1:])
		switch section {
		case "General":
			switch key {
			case "Name":
				out.Name = val
			case "Alias":
				out.Alias = val
			case "Class":
				c := parseClass(val)
				if c > 0 {
					out.Class = c
					out.DeviceClass = CoDMajorClass(c)
				}
			case "AddressType":
				out.AddressType = strings.ToLower(val)
				if out.AddressType == "static" || out.AddressType == "random" {
					out.IsBLE = true
				}
			case "Trusted":
				out.IsTrusted = parseBool(val)
			case "Blocked":
				out.IsBlocked = parseBool(val)
			case "Connected":
				out.IsConnected = parseBool(val)
			}
		case "DeviceID":
			switch key {
			case "Manufacturer":
				out.Manufacturer = val
			}
		case "ConnectionParameters":
			// LE devices carry this section even when AddressType is
			// missing — additional BLE signal.
			out.IsBLE = true
		}
	}
	return out
}

// parseClass parses a BlueZ Class= field. Format is typically
// `0x000508` (hex) or a decimal int.
func parseClass(s string) uint32 {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0
	}
	base := 10
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		base = 16
		s = s[2:]
	}
	v, err := strconv.ParseUint(s, base, 32)
	if err != nil {
		return 0
	}
	return uint32(v)
}

// parseBool maps BlueZ's `true` / `false` / `1` / `0` to Go bool.
func parseBool(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "true", "yes", "1", "on":
		return true
	}
	return false
}

// DeviceMACFromPath extracts the device MAC from a BlueZ path like
// `/var/lib/bluetooth/AA:BB:CC:DD:EE:FF/11:22:33:44:55:66/info`.
// Returns ("", "") when the path doesn't conform.
func DeviceMACFromPath(path string) (adapter, device string) {
	// Split on `/` and look for two MAC-shaped segments.
	parts := strings.Split(path, "/")
	macs := make([]string, 0, 2)
	for _, p := range parts {
		if IsValidMAC(p) {
			macs = append(macs, p)
		}
	}
	if len(macs) >= 2 {
		return macs[0], macs[1]
	}
	if len(macs) == 1 {
		return macs[0], ""
	}
	return "", ""
}
