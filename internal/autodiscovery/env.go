package autodiscovery

import (
	"os"
)

// probeEnvVars checks whether any environment variables referenced by the
// known service signatures are set.  If endpoint env vars (EnvVars) or
// credential env vars (CredentialEnvs) are found, the service is reported.
func probeEnvVars(services []ServiceSignature) []DiscoveredService {
	var results []DiscoveredService

	for _, svc := range services {
		endpoint := ""

		// Check endpoint-related env vars.
		for _, env := range svc.EnvVars {
			if v := os.Getenv(env); v != "" {
				endpoint = v
				break
			}
		}

		// Check credential env vars.
		allCredsSet := len(svc.CredentialEnvs) > 0
		var missing []string
		for _, env := range svc.CredentialEnvs {
			if os.Getenv(env) == "" {
				allCredsSet = false
				missing = append(missing, env)
			}
		}

		// Only report if at least one env var is set.
		if endpoint == "" && !allCredsSet {
			// Check if at least one credential env is set (partial config).
			hasAnyCred := false
			for _, env := range svc.CredentialEnvs {
				if os.Getenv(env) != "" {
					hasAnyCred = true
					break
				}
			}
			if !hasAnyCred {
				continue
			}
		}

		status := "needs_credentials"
		if allCredsSet || len(svc.CredentialEnvs) == 0 {
			status = "ready"
		}

		results = append(results, DiscoveredService{
			Name:        svc.Name,
			DisplayName: svc.DisplayName,
			Endpoint:    endpoint,
			Method:      "env_var",
			Status:      status,
			Credentials: missing,
			SetupHint:   svc.SetupHint,
		})
	}

	return results
}
