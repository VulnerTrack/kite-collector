package enrollment

import (
	"fmt"
	"log/slog"
)

// keyBackendRank maps backend names to a security strength ranking.
// Higher values indicate stronger key protection.
var keyBackendRank = map[string]int{
	"file":    1,
	"keyring": 2,
	"tpm":     3,
}

// EnforceMinKeyBackend checks whether the agent's key_backend meets
// the minimum required by the SaaS policy (RFC-0077 §R14).
//
// If the requirement is not met, it returns an error describing the
// gap. If minBackend is empty, no enforcement is applied.
func EnforceMinKeyBackend(currentBackend, minBackend string, logger *slog.Logger) error {
	if minBackend == "" {
		return nil
	}

	minRank, ok := keyBackendRank[minBackend]
	if !ok {
		return fmt.Errorf("unknown minimum key_backend %q", minBackend)
	}

	currentRank, ok := keyBackendRank[currentBackend]
	if !ok {
		return fmt.Errorf("unknown current key_backend %q", currentBackend)
	}

	if currentRank < minRank {
		logger.Warn(
			"key_backend below policy minimum; enrollment rejected",
			"code", string(LogCodeEnrollmentKeyBackendBelowPolicy),
			"current", currentBackend,
			"current_rank", currentRank,
			"required", minBackend,
			"required_rank", minRank,
		)
		return fmt.Errorf(
			"enrollment rejected: key_backend=%q does not meet minimum=%q; "+
				"upgrade to key_backend=%s or higher for enrollment",
			currentBackend, minBackend, minBackend,
		)
	}

	logger.Info(
		"key_backend meets enrollment policy",
		"code", string(LogCodeEnrollmentKeyBackendOK),
		"current", currentBackend,
		"required", minBackend,
	)
	return nil
}
