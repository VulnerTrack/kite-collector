// Cloud DNS preflight checks (RFC-0122 Phase 4).
//
// These checks validate that the env vars required by each cloud DNS source
// are present at startup, so the wizard can surface a precise hint instead
// of letting the agent fail mid-scan with an opaque "401 Unauthorized" or
// "credentials not found" from the upstream SDK.
//
// Each check is conservative: if the source is configured but the operator
// has not enabled it (the typed `value` arg is nil/false/empty), the check
// returns Passed=true with a "skipping" message — preflight should never
// block on a feature that is not in use.
//
// Active credential probes (CallerIdentity / WhoAmI) are out of scope for
// these checks and live in the source-side `Discover` calls, where they
// can fail loudly with the provider's own error text.
package preflight

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// route53RequiredEnv is the canonical AWS credential pair the Route53 source
// reads via loadAWSCredentials() in apps/kite-collector/internal/discovery/cloud/aws.go.
var route53RequiredEnv = []string{"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"}

// cloudflareRequiredEnv is the API token env var the Cloudflare source reads.
var cloudflareRequiredEnv = []string{"CF_API_TOKEN"}

// azureDNSRequiredEnv is the service-principal triplet the Azure DNS source
// reads. AZURE_SUBSCRIPTION_ID is optional (cfg can override) so it is not
// required here.
var azureDNSRequiredEnv = []string{
	"AZURE_TENANT_ID",
	"AZURE_CLIENT_ID",
	"AZURE_CLIENT_SECRET",
}

// gcpCloudDNSRequiredEnv is the path to a Google service-account key that
// the GCP source reads via the standard GOOGLE_APPLICATION_CREDENTIALS env.
var gcpCloudDNSRequiredEnv = []string{"GOOGLE_APPLICATION_CREDENTIALS"}

// asEnabled coerces a wizard value into a boolean. Wizard schemas may emit
// the enabled flag as a bool, a "true"/"false" string, or omit it entirely
// (nil) when the operator skipped the section. Anything else is treated as
// disabled — an unrecognized value is safer to skip than to scream about.
func asEnabled(value any) bool {
	switch v := value.(type) {
	case nil:
		return false
	case bool:
		return v
	case string:
		s := strings.TrimSpace(strings.ToLower(v))
		return s == "true" || s == "1" || s == "yes" || s == "on"
	}
	return false
}

// cloudDNSEnvCheck is the shared body for every per-provider env check. It
// runs only when “value“ indicates the source is enabled; otherwise it
// returns a passing "skipping" result so the operator is not pestered about
// credentials for a source they are not using. “hintFmt“ is rendered
// once per missing var with “%s“ substituted for the var name.
func cloudDNSEnvCheck(
	checkTag string,
	nodeID string,
	value any,
	requiredEnv []string,
	hintFmt string,
) CheckResult {
	if !asEnabled(value) {
		return CheckResult{
			NodeID:  nodeID,
			Check:   checkTag,
			Passed:  true,
			Message: fmt.Sprintf("%s disabled, skipping", checkTag),
		}
	}
	missing := make([]string, 0, len(requiredEnv))
	for _, env := range requiredEnv {
		if strings.TrimSpace(os.Getenv(env)) == "" {
			missing = append(missing, env)
		}
	}
	if len(missing) > 0 {
		return CheckResult{
			NodeID:  nodeID,
			Check:   checkTag,
			Passed:  false,
			Message: fmt.Sprintf("missing env: %s", strings.Join(missing, ", ")),
			Hint:    fmt.Sprintf(hintFmt, strings.Join(missing, " ")),
		}
	}
	return CheckResult{
		NodeID:  nodeID,
		Check:   checkTag,
		Passed:  true,
		Message: fmt.Sprintf("all required env vars set: %s", strings.Join(requiredEnv, ", ")),
	}
}

// CloudDNSRoute53EnvChecker validates AWS credentials when route53 enabled.
type CloudDNSRoute53EnvChecker struct{}

func (c *CloudDNSRoute53EnvChecker) Check(_ context.Context, nodeID string, value any, _ map[string]any) CheckResult {
	return cloudDNSEnvCheck(
		"cloud_dns:route53:env",
		nodeID,
		value,
		route53RequiredEnv,
		"export %s=<value>; an IAM user with the AmazonRoute53ReadOnlyAccess managed policy is sufficient",
	)
}

// CloudDNSCloudflareEnvChecker validates the Cloudflare API token env var.
type CloudDNSCloudflareEnvChecker struct{}

func (c *CloudDNSCloudflareEnvChecker) Check(_ context.Context, nodeID string, value any, _ map[string]any) CheckResult {
	return cloudDNSEnvCheck(
		"cloud_dns:cloudflare:env",
		nodeID,
		value,
		cloudflareRequiredEnv,
		"export %s=<token>; create a token with the Zone:Read and DNS:Read scopes at https://dash.cloudflare.com/profile/api-tokens",
	)
}

// CloudDNSAzureEnvChecker validates the service-principal triplet for
// Azure DNS enumeration.
type CloudDNSAzureEnvChecker struct{}

func (c *CloudDNSAzureEnvChecker) Check(_ context.Context, nodeID string, value any, _ map[string]any) CheckResult {
	return cloudDNSEnvCheck(
		"cloud_dns:azure:env",
		nodeID,
		value,
		azureDNSRequiredEnv,
		"export %s=<value>; the service principal needs the DNS Zone Reader role on the target subscription",
	)
}

// CloudDNSGCPEnvChecker validates the GCP application-credentials env var
// the gcloud SDK uses to bootstrap auth.
type CloudDNSGCPEnvChecker struct{}

func (c *CloudDNSGCPEnvChecker) Check(_ context.Context, nodeID string, value any, _ map[string]any) CheckResult {
	res := cloudDNSEnvCheck(
		"cloud_dns:gcp:env",
		nodeID,
		value,
		gcpCloudDNSRequiredEnv,
		"export %s=/path/to/service-account-key.json; the service account needs the roles/dns.reader role on the target project",
	)
	if !res.Passed {
		return res
	}
	// Verify the credential file is actually present — GOOGLE_APPLICATION_CREDENTIALS
	// is a path, and a missing file fails late inside the GCP client with a
	// generic "could not find default credentials" message. filepath.Clean
	// removes traversal components from the operator-supplied path before
	// it reaches os.Stat.
	rawPath := strings.TrimSpace(os.Getenv("GOOGLE_APPLICATION_CREDENTIALS"))
	if strings.ContainsRune(rawPath, 0) {
		return CheckResult{
			NodeID:  nodeID,
			Check:   "cloud_dns:gcp:env",
			Passed:  false,
			Message: "GOOGLE_APPLICATION_CREDENTIALS contains a NUL byte",
			Hint:    "Set GOOGLE_APPLICATION_CREDENTIALS to a plain absolute filesystem path",
		}
	}
	cleanPath := filepath.Clean(rawPath)
	if _, err := os.Stat(cleanPath); err != nil {
		return CheckResult{
			NodeID:  nodeID,
			Check:   "cloud_dns:gcp:env",
			Passed:  false,
			Message: fmt.Sprintf("GOOGLE_APPLICATION_CREDENTIALS points to %q which is not readable: %v", cleanPath, err),
			Hint:    "Create a service-account JSON key at the GCP Console (IAM & Admin → Service Accounts → Keys → Add Key) and point the env at it",
		}
	}
	return res
}
