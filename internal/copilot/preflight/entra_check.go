package preflight

import (
	"context"
	"fmt"
	"os"
	"regexp"
	"strings"
)

// guidPattern matches the canonical 8-4-4-4-12 hexadecimal Microsoft Entra
// GUID form (case-insensitive). Optional surrounding braces are tolerated
// because the Azure portal copy button sometimes emits {GUID}.
var guidPattern = regexp.MustCompile(
	`^\{?[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-` +
		`[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}?$`,
)

// EntraTenantIDChecker validates that the configured Entra tenant ID is a
// well-formed GUID. The Microsoft identity platform rejects malformed
// tenant IDs with an opaque AADSTS90002 error very late in the OAuth2
// dance — catching the typo here lets the wizard surface a precise hint
// before the first scan attempts authentication.
type EntraTenantIDChecker struct{}

func (c *EntraTenantIDChecker) Check(_ context.Context, nodeID string, value any, _ map[string]any) CheckResult {
	tenantID, ok := value.(string)
	if !ok || strings.TrimSpace(tenantID) == "" {
		return CheckResult{
			NodeID:  nodeID,
			Check:   "entra:tenant_id:guid",
			Passed:  true,
			Message: "no tenant_id configured, skipping",
		}
	}
	if !guidPattern.MatchString(strings.TrimSpace(tenantID)) {
		return CheckResult{
			NodeID:  nodeID,
			Check:   "entra:tenant_id:guid",
			Passed:  false,
			Message: fmt.Sprintf("tenant_id %q is not a valid GUID", tenantID),
			Hint:    "Copy the Directory (tenant) ID from Azure Portal → Entra ID → Overview",
		}
	}
	return CheckResult{
		NodeID:  nodeID,
		Check:   "entra:tenant_id:guid",
		Passed:  true,
		Message: "tenant_id is a valid GUID",
	}
}

// EntraClientIDChecker validates that the configured Entra application
// (client) ID is a well-formed GUID. The same rationale as for tenant_id
// applies: Microsoft rejects malformed client IDs late, with a generic
// invalid_client error.
type EntraClientIDChecker struct{}

func (c *EntraClientIDChecker) Check(_ context.Context, nodeID string, value any, _ map[string]any) CheckResult {
	clientID, ok := value.(string)
	if !ok || strings.TrimSpace(clientID) == "" {
		return CheckResult{
			NodeID:  nodeID,
			Check:   "entra:client_id:guid",
			Passed:  true,
			Message: "no client_id configured, skipping",
		}
	}
	if !guidPattern.MatchString(strings.TrimSpace(clientID)) {
		return CheckResult{
			NodeID:  nodeID,
			Check:   "entra:client_id:guid",
			Passed:  false,
			Message: fmt.Sprintf("client_id %q is not a valid GUID", clientID),
			Hint:    "Copy the Application (client) ID from Azure Portal → App registrations → <app> → Overview",
		}
	}
	return CheckResult{
		NodeID:  nodeID,
		Check:   "entra:client_id:guid",
		Passed:  true,
		Message: "client_id is a valid GUID",
	}
}

// EntraSecretEnvChecker verifies that the environment variable named in
// the node's value is exported and non-empty. The Entra source refuses to
// acquire an OAuth2 token without a client secret, so a missing env var
// is a hard failure — the wizard should fail loudly here rather than
// have the first scan log "tenant_id, client_id, or client_secret not
// configured, skipping" and produce no findings.
type EntraSecretEnvChecker struct{}

func (c *EntraSecretEnvChecker) Check(_ context.Context, nodeID string, value any, _ map[string]any) CheckResult {
	envVar, ok := value.(string)
	if !ok || strings.TrimSpace(envVar) == "" {
		return CheckResult{
			NodeID:  nodeID,
			Check:   "entra:secret:env",
			Passed:  true,
			Message: "no client_secret env var configured, skipping",
		}
	}
	envVar = strings.TrimSpace(envVar)
	if os.Getenv(envVar) == "" {
		return CheckResult{
			NodeID:  nodeID,
			Check:   "entra:secret:env",
			Passed:  false,
			Message: fmt.Sprintf("env var %s is not set", envVar),
			Hint:    fmt.Sprintf("export %s=<client-secret-value>", envVar),
		}
	}
	return CheckResult{
		NodeID:  nodeID,
		Check:   "entra:secret:env",
		Passed:  true,
		Message: fmt.Sprintf("%s is set", envVar),
	}
}
