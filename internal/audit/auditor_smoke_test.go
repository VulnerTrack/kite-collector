package audit

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vulnertrack/kite-collector/internal/model"
)

// Every auditor's Audit wrapper is a thin read-only probe over its pure
// Evaluate* core: it shells out to (possibly absent) tools or walks
// (possibly restricted) paths and must degrade to partial results, never
// an error, on any host. Running them for real on the test host is safe —
// discovery is read-only by project guideline 4.2 — and pins exactly that
// degradation contract: whatever this machine looks like, Audit returns
// findings (possibly none) and a nil error before the deadline.
func TestAuditors_SmokeRunOnRealHost(t *testing.T) {
	machine := model.Machine{Hostname: "smoke-host", MachineType: model.MachineTypeServer}

	auditors := []Auditor{
		NewFirewall(),
		NewKernel(),
		NewSSH(""),          // default sshd_config path; may not exist
		NewService(nil),     // default critical port set
		NewPermissions(nil), // default path set; some will be unreadable
	}

	for _, a := range auditors {
		t.Run(a.Name(), func(t *testing.T) {
			assert.NotEmpty(t, a.Name(), "auditor name is the registry key")
			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer cancel()

			findings, err := a.Audit(ctx, machine)
			require.NoError(t, err,
				"auditors must return partial results, not errors, on an arbitrary host")
			for _, f := range findings {
				assert.Equal(t, a.Name(), f.Auditor,
					"every finding must carry its auditor's name")
				assert.NotEmpty(t, f.CheckID)
				assert.NotEmpty(t, f.Title)
			}
		})
	}
}

// A cancelled context must not wedge the wrappers either — the exec-based
// probes inherit the deadline.
func TestAuditors_CancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := NewFirewall().Audit(ctx, model.Machine{})
	assert.NoError(t, err, "command failures under cancellation degrade to empty output")
}
