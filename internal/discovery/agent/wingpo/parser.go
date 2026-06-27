package wingpo

import (
	"bufio"
	"bytes"
	"strconv"
	"strings"
)

// ParseGPTIni walks a `gpt.ini` body and surfaces the headline
// `Version` (a 4-byte little-endian split into a hi-word and
// lo-word; whole number is what we record) and
// `gPCMachineExtensionNames` strings. The grammar is plain INI:
//
//	[General]
//	gPCMachineExtensionNames=[{...}{...}]
//	Version=131073
//	displayName=Local Group Policy
func ParseGPTIni(body []byte) (version int, extensionNames string) {
	if len(body) == 0 {
		return 0, ""
	}
	body = stripBOM(body)
	scan := bufio.NewScanner(bytes.NewReader(body))
	scan.Buffer(make([]byte, 0, 4096), 1<<20)
	for scan.Scan() {
		line := strings.TrimSpace(scan.Text())
		if line == "" || strings.HasPrefix(line, ";") || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "[") {
			continue
		}
		key, value, ok := splitKV(line)
		if !ok {
			continue
		}
		switch strings.ToLower(key) {
		case "version":
			if n, err := strconv.Atoi(strings.TrimSpace(value)); err == nil {
				version = n
			}
		case "gpcmachineextensionnames", "gpcuserextensionnames":
			if extensionNames == "" {
				extensionNames = value
			}
		}
	}
	return version, extensionNames
}

// splitKV separates `key=value` (no whitespace around `=`).
func splitKV(line string) (string, string, bool) {
	if i := strings.IndexByte(line, '='); i > 0 {
		return strings.TrimSpace(line[:i]),
			strings.TrimSpace(line[i+1:]),
			true
	}
	return "", "", false
}

// stripBOM drops a UTF-8 BOM if present. gpt.ini is plain ASCII
// in practice but Notepad-edited copies occasionally have one.
func stripBOM(b []byte) []byte {
	if len(b) >= 3 && b[0] == 0xEF && b[1] == 0xBB && b[2] == 0xBF {
		return b[3:]
	}
	return b
}
