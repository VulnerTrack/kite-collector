package enrollment

import (
	"io"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEnforceMinKeyBackend_AllPolicyOutcomes(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	tests := []struct {
		name    string
		current string
		minimum string
		wantErr string
	}{
		{name: "no policy", current: "file", minimum: ""},
		{name: "equal strength", current: "keyring", minimum: "keyring"},
		{name: "stronger than minimum", current: "tpm", minimum: "file"},
		{name: "below minimum", current: "file", minimum: "keyring", wantErr: "does not meet minimum"},
		{name: "unknown minimum", current: "file", minimum: "hardware", wantErr: "unknown minimum"},
		{name: "unknown current", current: "memory", minimum: "file", wantErr: "unknown current"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := EnforceMinKeyBackend(tc.current, tc.minimum, logger)
			if tc.wantErr == "" {
				require.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.wantErr)
		})
	}
}
