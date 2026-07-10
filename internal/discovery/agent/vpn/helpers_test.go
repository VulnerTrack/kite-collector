package vpn

import (
	"encoding/json"
	"fmt"
)

// decodeJSON is a tiny helper that keeps test files self-contained
// without each one needing to import encoding/json directly.
func decodeJSON(raw string, v any) error {
	if err := json.Unmarshal([]byte(raw), v); err != nil {
		return fmt.Errorf("decode json: %w", err)
	}
	return nil
}
