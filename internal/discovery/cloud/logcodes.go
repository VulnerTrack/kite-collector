package cloud

// LogCode is the typed identifier attached to every structured log
// entry the cloud discovery package emits. Convention:
// `cloud.<provider>.<event>` or `cloud.<surface>.<event>` so
// downstream tooling can pivot on a stable identifier without parsing
// freeform message text.
//
// Codes are split PER PROVIDER (rather than shared via a `provider`
// structured field) because the runbook for "AWS auth failed" is
// substantively different from "Azure auth failed" — different IAM
// systems, different documentation, different teams may own the
// remediation. On-call routing can map a code directly to a team
// without parsing a sub-field.
//
// Codes are immutable once shipped. Renaming a code is a breaking
// change for any alert/dashboard that filters on it; add a new code
// and mark the old one Deprecated instead.
type LogCode string

const (
	// --- AWS EC2 compute discovery -----------------------------------
	LogCodeAWSEC2Starting         LogCode = "cloud.aws_ec2.starting"
	LogCodeAWSEC2CredsMissing     LogCode = "cloud.aws_ec2.creds_missing" //#nosec G101 -- log code identifier emitted when AWS EC2 credentials env vars are absent, not a credential value
	LogCodeAWSEC2AssumeRole       LogCode = "cloud.aws_ec2.assume_role"
	LogCodeAWSEC2AssumeRoleFailed LogCode = "cloud.aws_ec2.assume_role_failed"
	LogCodeAWSEC2UsingAssumedRole LogCode = "cloud.aws_ec2.using_assumed_role"
	LogCodeAWSEC2DefaultRegions   LogCode = "cloud.aws_ec2.default_regions"
	LogCodeAWSEC2RegionStarting   LogCode = "cloud.aws_ec2.region_starting"
	LogCodeAWSEC2DescribeFailed   LogCode = "cloud.aws_ec2.describe_failed"
	LogCodeAWSEC2RegionComplete   LogCode = "cloud.aws_ec2.region_complete"
	LogCodeAWSEC2Complete         LogCode = "cloud.aws_ec2.completed"

	// --- Azure VM compute discovery ----------------------------------
	LogCodeAzureVMStarting            LogCode = "cloud.azure_vm.starting"
	LogCodeAzureVMCredsMissing        LogCode = "cloud.azure_vm.creds_missing"        //#nosec G101 -- log code identifier signalling Azure VM credentials env vars are missing, not a credential value
	LogCodeAzureVMTokenAcquireFailed  LogCode = "cloud.azure_vm.token_acquire_failed" //#nosec G101 -- log code identifier for Azure VM OAuth token acquisition failure, not a token value
	LogCodeAzureVMEnumeratingSubs     LogCode = "cloud.azure_vm.enumerating_subscriptions"
	LogCodeAzureVMEnumerateSubsFailed LogCode = "cloud.azure_vm.enumerate_subscriptions_failed"
	LogCodeAzureVMNoSubsAccessible    LogCode = "cloud.azure_vm.no_subscriptions_accessible"
	LogCodeAzureVMSubsDiscovered      LogCode = "cloud.azure_vm.subscriptions_discovered"
	LogCodeAzureVMListingVMs          LogCode = "cloud.azure_vm.listing_vms"
	LogCodeAzureVMListVMsFailed       LogCode = "cloud.azure_vm.list_vms_failed"
	LogCodeAzureVMComplete            LogCode = "cloud.azure_vm.completed"
	LogCodeAzureVMSkipUnparseable     LogCode = "cloud.azure_vm.skip_unparseable_vm"

	// --- GCP Compute discovery ---------------------------------------
	LogCodeGCPComputeStarting             LogCode = "cloud.gcp_compute.starting"
	LogCodeGCPComputeProjectMissing       LogCode = "cloud.gcp_compute.project_missing"
	LogCodeGCPComputeTokenAcquireFailed   LogCode = "cloud.gcp_compute.token_acquire_failed" //#nosec G101 -- log code identifier for GCP Compute OAuth token acquisition failure, not a token value
	LogCodeGCPComputeComplete             LogCode = "cloud.gcp_compute.completed"
	LogCodeGCPComputeTokenFromMetadata    LogCode = "cloud.gcp_compute.token_from_metadata"     //#nosec G101 -- log code identifier marking that GCP Compute used the metadata server for tokens, not a token value
	LogCodeGCPComputeTokenFromCredsFile   LogCode = "cloud.gcp_compute.token_from_creds_file"   //#nosec G101 -- log code identifier marking that GCP Compute used a service-account JSON file for tokens, not a token value
	LogCodeGCPComputeTokenCredsFileFailed LogCode = "cloud.gcp_compute.token_creds_file_failed" //#nosec G101 -- log code identifier for failure to acquire a token from a GCP credentials file, not a token value
	LogCodeGCPComputeDiskFetchFailed      LogCode = "cloud.gcp_compute.disk_fetch_failed"

	// --- Route53 DNS discovery (AWS DNS) -----------------------------
	LogCodeRoute53Disabled            LogCode = "cloud.dns_route53.disabled"
	LogCodeRoute53CredsMissing        LogCode = "cloud.dns_route53.creds_missing" //#nosec G101 -- log code identifier emitted when Route53 credentials env vars are absent, not a credential value
	LogCodeRoute53AssumeRole          LogCode = "cloud.dns_route53.assume_role"
	LogCodeRoute53AssumeRoleFailed    LogCode = "cloud.dns_route53.assume_role_failed"
	LogCodeRoute53GetDNSSECFailed     LogCode = "cloud.dns_route53.get_dnssec_failed"
	LogCodeRoute53ListRecordsFailed   LogCode = "cloud.dns_route53.list_records_failed"
	LogCodeRoute53SkipUnsupportedType LogCode = "cloud.dns_route53.skip_unsupported_record_type"
	LogCodeRoute53Complete            LogCode = "cloud.dns_route53.completed"

	// --- Cloudflare DNS discovery ------------------------------------
	LogCodeCloudflareDisabled            LogCode = "cloud.dns_cloudflare.disabled"
	LogCodeCloudflareTokenMissing        LogCode = "cloud.dns_cloudflare.token_missing" //#nosec G101 -- log code identifier emitted when the Cloudflare API token env var is absent, not a token value
	LogCodeCloudflareListRecordsFailed   LogCode = "cloud.dns_cloudflare.list_records_failed"
	LogCodeCloudflareSkipUnsupportedType LogCode = "cloud.dns_cloudflare.skip_unsupported_record_type"
	LogCodeCloudflareComplete            LogCode = "cloud.dns_cloudflare.completed"

	// --- Azure DNS discovery -----------------------------------------
	LogCodeAzureDNSDisabled            LogCode = "cloud.dns_azure.disabled"
	LogCodeAzureDNSCredsMissing        LogCode = "cloud.dns_azure.creds_missing" //#nosec G101 -- log code identifier emitted when Azure DNS credentials env vars are absent, not a credential value
	LogCodeAzureDNSListZonesFailed     LogCode = "cloud.dns_azure.list_zones_failed"
	LogCodeAzureDNSListRecordsFailed   LogCode = "cloud.dns_azure.list_records_failed"
	LogCodeAzureDNSSkipUnsupportedType LogCode = "cloud.dns_azure.skip_unsupported_record_type"
	LogCodeAzureDNSComplete            LogCode = "cloud.dns_azure.completed"

	// --- GCP DNS discovery -------------------------------------------
	LogCodeGCPDNSDisabled            LogCode = "cloud.dns_gcp.disabled"
	LogCodeGCPDNSProjectMissing      LogCode = "cloud.dns_gcp.project_missing"
	LogCodeGCPDNSTokenAcquireFailed  LogCode = "cloud.dns_gcp.token_acquire_failed" //#nosec G101 -- log code identifier for GCP DNS OAuth token acquisition failure, not a token value
	LogCodeGCPDNSListRecordsFailed   LogCode = "cloud.dns_gcp.list_records_failed"
	LogCodeGCPDNSSkipUnsupportedType LogCode = "cloud.dns_gcp.skip_unsupported_record_type"
	LogCodeGCPDNSComplete            LogCode = "cloud.dns_gcp.completed"

	// --- Cross-provider DNS-discovery shared events ------------------
	// Zone + record "discovered" entries are emitted by every provider
	// in the same shape (so dashboards can sum across providers via
	// `code IN (...)` filters). The provider is always available in
	// the structured fields for per-provider breakdowns.
	LogCodeDNSZoneDiscovered   LogCode = "cloud.dns.zone_discovered"
	LogCodeDNSRecordDiscovered LogCode = "cloud.dns.record_discovered"

	// --- retry helper (retry.go) -------------------------------------
	// The retry wrapper logs at distinct stages so alerting can fire
	// independently on "we're retrying a lot" vs "access denied is
	// permanent" vs "throttled by upstream".
	LogCodeRetryBackoff      LogCode = "cloud.retry.backoff"
	LogCodeRetryNetworkError LogCode = "cloud.retry.network_error"
	LogCodeRetryAccessDenied LogCode = "cloud.retry.access_denied"
	LogCodeRetryRateLimited  LogCode = "cloud.retry.rate_limited"
	LogCodeRetryServerError  LogCode = "cloud.retry.server_error"
)
