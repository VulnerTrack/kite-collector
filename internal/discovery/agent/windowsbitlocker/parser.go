package windowsbitlocker

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// PowerShellScript wraps Get-BitLockerVolume in a JSON-emitting
// envelope. On hosts where the BitLocker feature isn't installed
// (Server Core w/o the feature, Windows Home SKUs) the cmdlet
// throws — we trap that and emit `volumes: []` so the audit
// pipeline gets a "no probe ran" signal it can act on.
const PowerShellScript = `
$ErrorActionPreference = 'Stop'
$rows = @()
try {
    $vols = Get-BitLockerVolume -ErrorAction Stop
    foreach ($v in $vols) {
        $kp = @()
        if ($v.KeyProtector) {
            foreach ($p in $v.KeyProtector) {
                if ($p.KeyProtectorType) { $kp += [string]$p.KeyProtectorType }
            }
        }
        $pct = 0
        if ($v.EncryptionPercentage -ne $null) { $pct = [int]$v.EncryptionPercentage }
        $rows += [pscustomobject]@{
            mount_point              = [string]$v.MountPoint
            volume_type              = [string]$v.VolumeType
            protection_status        = [string]$v.ProtectionStatus
            lock_status              = [string]$v.LockStatus
            volume_status            = [string]$v.VolumeStatus
            encryption_method        = [string]$v.EncryptionMethod
            encryption_percentage    = $pct
            auto_unlock_enabled      = [bool]$v.AutoUnlockEnabled
            key_protectors           = $kp
        }
    }
} catch {}
[pscustomobject]@{
    source  = 'powershell-bitlocker'
    volumes = $rows
} | ConvertTo-Json -Depth 5 -Compress
`

// rawPayload mirrors the wire JSON shape.
type rawPayload struct {
	Source  string      `json:"source"`
	Volumes []rawVolume `json:"volumes"`
}

type rawVolume struct {
	KeyProtectors        any         `json:"key_protectors"`
	MountPoint           string      `json:"mount_point"`
	VolumeType           string      `json:"volume_type"`
	ProtectionStatus     string      `json:"protection_status"`
	LockStatus           string      `json:"lock_status"`
	VolumeStatus         string      `json:"volume_status"`
	EncryptionMethod     string      `json:"encryption_method"`
	EncryptionPercentage json.Number `json:"encryption_percentage"`
	AutoUnlockEnabled    bool        `json:"auto_unlock_enabled"`
}

// ParsePowerShellOutput converts the JSON blob into a slice of
// Volume. Empty payloads return an error so the collector can flip
// Source=unknown; everything else falls through with whatever fields
// the shim populated.
func ParsePowerShellOutput(data []byte) ([]Volume, error) {
	trimmed := trimUTF8BOM(data)
	trimmed = []byte(strings.TrimSpace(string(trimmed)))
	if len(trimmed) == 0 {
		return nil, fmt.Errorf("empty PowerShell output")
	}
	var raw rawPayload
	dec := json.NewDecoder(strings.NewReader(string(trimmed)))
	dec.UseNumber()
	if err := dec.Decode(&raw); err != nil {
		return nil, fmt.Errorf("decode bitlocker json: %w", err)
	}

	out := make([]Volume, 0, len(raw.Volumes))
	for _, rv := range raw.Volumes {
		v := Volume{
			Source:               SourcePowerShellBitLocker,
			MountPoint:           strings.TrimSpace(rv.MountPoint),
			VolumeType:           strings.TrimSpace(rv.VolumeType),
			ProtectionStatus:     strings.TrimSpace(rv.ProtectionStatus),
			LockStatus:           strings.TrimSpace(rv.LockStatus),
			VolumeStatus:         strings.TrimSpace(rv.VolumeStatus),
			EncryptionMethod:     strings.TrimSpace(rv.EncryptionMethod),
			EncryptionPercentage: parseInt(rv.EncryptionPercentage),
			AutoUnlockEnabled:    rv.AutoUnlockEnabled,
			KeyProtectors:        normaliseProtectors(rv.KeyProtectors),
		}
		if v.MountPoint == "" {
			// Drop rows BitLocker emits without a mount point; they
			// can't be meaningfully joined and skew dedup.
			continue
		}
		AnnotateSecurity(&v)
		SortKeyProtectors(&v)
		out = append(out, v)
		if len(out) >= MaxVolumes {
			break
		}
	}
	SortVolumes(out)
	return out, nil
}

// normaliseProtectors handles PowerShell's "singleton arrays
// collapse to scalars" quirk: a single key protector arrives as a
// bare string, not a one-element list.
func normaliseProtectors(v any) []string {
	switch t := v.(type) {
	case nil:
		return nil
	case string:
		s := strings.TrimSpace(t)
		if s == "" {
			return nil
		}
		return []string{s}
	case []any:
		out := make([]string, 0, len(t))
		for _, e := range t {
			if s, ok := e.(string); ok {
				if s = strings.TrimSpace(s); s != "" {
					out = append(out, s)
				}
			}
		}
		return out
	}
	return nil
}

func parseInt(n json.Number) int {
	if n == "" {
		return 0
	}
	if v, err := n.Int64(); err == nil {
		return int(v)
	}
	if i, err := strconv.Atoi(n.String()); err == nil {
		return i
	}
	return 0
}

func trimUTF8BOM(data []byte) []byte {
	if len(data) >= 3 && data[0] == 0xEF && data[1] == 0xBB && data[2] == 0xBF {
		return data[3:]
	}
	return data
}
