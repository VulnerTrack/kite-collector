package agent

import (
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// Hardware product facts, not serials/asset tags. Fixed read-only sysfs files
// identify the hardware independently of the installed operating system.
func hardwareTags() map[string]string {
	if runtime.GOOS != "linux" {
		return map[string]string{}
	}
	return readHardwareTags("/sys/class/dmi/id")
}

func readHardwareTags(root string) map[string]string {
	tags := make(map[string]string)
	for key, name := range map[string]string{
		"hardware_manufacturer": "sys_vendor",
		"hardware_model":        "product_name",
		"hardware_version":      "product_version",
	} {
		f, err := os.Open(filepath.Join(root, name)) //#nosec G304 -- fixed sysfs paths; root is a test seam
		if err != nil {
			continue
		}
		data, readErr := io.ReadAll(io.LimitReader(f, 1025))
		_ = f.Close()
		if readErr != nil || len(data) > 1024 {
			continue
		}
		value := strings.TrimSpace(string(data))
		switch strings.ToLower(value) {
		case "", "none", "unknown", "default string", "system product name", "to be filled by o.e.m.":
			continue
		}
		tags[key] = value
	}
	return tags
}
