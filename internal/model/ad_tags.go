package model

import (
	"encoding/json"
	"strconv"
	"time"

	"github.com/vulnertrack/kite-collector/internal/telemetry/contract"
)

// ADAttributesFromTags lifts the contract.AttrAD* tags the LDAP source
// writes onto a machine into their string wire form, keyed by the contract
// key. Empty values are dropped; nil when the machine carries none.
func ADAttributesFromTags(tags map[string]any) map[string]string {
	var out map[string]string
	for _, key := range contract.ADMachineAttributes {
		v := adWireValue(key, tags[key])
		if v == "" {
			continue
		}
		if out == nil {
			out = make(map[string]string, len(contract.ADMachineAttributes))
		}
		out[key] = v
	}
	return out
}

// adWireValue renders one decoded tag value. Tags round-trip through JSON,
// so numbers arrive as float64 and string lists as []any. The two AD
// timestamps are stored as Unix seconds and go out as RFC 3339, like
// security.machine.first_seen.
func adWireValue(key string, raw any) string {
	switch v := raw.(type) {
	case string:
		return v
	case bool:
		return strconv.FormatBool(v)
	case float64:
		if key == contract.AttrADLastLogonTimestamp || key == contract.AttrADPasswordLastSet {
			if v <= 0 {
				return ""
			}
			return time.Unix(int64(v), 0).UTC().Format(time.RFC3339)
		}
		return strconv.FormatFloat(v, 'f', -1, 64)
	case []any:
		if len(v) == 0 {
			return ""
		}
		encoded, err := json.Marshal(v)
		if err != nil {
			return ""
		}
		return string(encoded)
	default:
		return ""
	}
}
