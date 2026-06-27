// Package cmdb provides discovery sources for Configuration Management
// Database (CMDB) systems. Each source implements [discovery.Source] and
// enumerates configuration items / devices as [model.Asset] values.
// Assets imported from a CMDB are considered authorised by default since
// their presence in the CMDB implies organisational awareness.
package cmdb

// toString extracts a string value from an any, returning empty string if
// the value is nil or not a string.
func toString(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

// truncateBytes returns at most maxLen bytes from data as a string.
func truncateBytes(data []byte, maxLen int) string {
	if len(data) <= maxLen {
		return string(data)
	}
	return string(data[:maxLen]) + "..."
}
