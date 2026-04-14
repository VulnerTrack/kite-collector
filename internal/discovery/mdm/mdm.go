// Package mdm provides discovery sources for Mobile Device Management and
// endpoint management platforms. Each source implements [discovery.Source]
// and enumerates managed devices as [model.Asset] values.
package mdm

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
