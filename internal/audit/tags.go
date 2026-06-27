package audit

import "encoding/json"

// extractContainerIDTag reads the "container_id" key from an asset's JSON
// tags blob, the same shape produced by docker.containerToAsset. The tags
// blob can mix string and non-string values (booleans, slices), so we
// unmarshal into map[string]any and only return the value when it is a
// string. Returns an empty string for malformed or missing tags.
func extractContainerIDTag(tags string) string {
	return jsonTagString(tags, "container_id")
}

// jsonTagString returns the string value at key in the JSON object encoded
// in tags, or "" when the tags are unparseable, the key is missing, or the
// value is not a JSON string.
func jsonTagString(tags, key string) string {
	if tags == "" {
		return ""
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(tags), &m); err != nil {
		return ""
	}
	v, ok := m[key]
	if !ok {
		return ""
	}
	s, ok := v.(string)
	if !ok {
		return ""
	}
	return s
}
