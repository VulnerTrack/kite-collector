package cloud

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestLogCodes_FollowConvention pins the `cloud.<surface>.<event>` shape.
// Surfaces are predominantly per-provider (`aws_ec2`, `azure_vm`,
// `gcp_compute`, `dns_route53`, `dns_cloudflare`, `dns_azure`,
// `dns_gcp`) plus the shared `dns` surface for cross-provider zone /
// record discovery events and the `retry` surface for the HTTP retry
// helper used by every cloud provider.
func TestLogCodes_FollowConvention(t *testing.T) {
	codes := []LogCode{
		// AWS EC2
		LogCodeAWSEC2Starting, LogCodeAWSEC2CredsMissing, LogCodeAWSEC2AssumeRole,
		LogCodeAWSEC2AssumeRoleFailed, LogCodeAWSEC2UsingAssumedRole,
		LogCodeAWSEC2DefaultRegions, LogCodeAWSEC2RegionStarting,
		LogCodeAWSEC2DescribeFailed, LogCodeAWSEC2RegionComplete, LogCodeAWSEC2Complete,
		// Azure VM
		LogCodeAzureVMStarting, LogCodeAzureVMCredsMissing,
		LogCodeAzureVMTokenAcquireFailed, LogCodeAzureVMEnumeratingSubs,
		LogCodeAzureVMEnumerateSubsFailed, LogCodeAzureVMNoSubsAccessible,
		LogCodeAzureVMSubsDiscovered, LogCodeAzureVMListingVMs,
		LogCodeAzureVMListVMsFailed, LogCodeAzureVMComplete, LogCodeAzureVMSkipUnparseable,
		// GCP Compute
		LogCodeGCPComputeStarting, LogCodeGCPComputeProjectMissing,
		LogCodeGCPComputeTokenAcquireFailed, LogCodeGCPComputeComplete,
		LogCodeGCPComputeTokenFromMetadata, LogCodeGCPComputeTokenFromCredsFile,
		LogCodeGCPComputeTokenCredsFileFailed, LogCodeGCPComputeDiskFetchFailed,
		// Route53 DNS
		LogCodeRoute53Disabled, LogCodeRoute53CredsMissing, LogCodeRoute53AssumeRole,
		LogCodeRoute53AssumeRoleFailed, LogCodeRoute53GetDNSSECFailed,
		LogCodeRoute53ListRecordsFailed, LogCodeRoute53SkipUnsupportedType,
		LogCodeRoute53Complete,
		// Cloudflare DNS
		LogCodeCloudflareDisabled, LogCodeCloudflareTokenMissing,
		LogCodeCloudflareListRecordsFailed, LogCodeCloudflareSkipUnsupportedType,
		LogCodeCloudflareComplete,
		// Azure DNS
		LogCodeAzureDNSDisabled, LogCodeAzureDNSCredsMissing,
		LogCodeAzureDNSListZonesFailed, LogCodeAzureDNSListRecordsFailed,
		LogCodeAzureDNSSkipUnsupportedType, LogCodeAzureDNSComplete,
		// GCP DNS
		LogCodeGCPDNSDisabled, LogCodeGCPDNSProjectMissing,
		LogCodeGCPDNSTokenAcquireFailed, LogCodeGCPDNSListRecordsFailed,
		LogCodeGCPDNSSkipUnsupportedType, LogCodeGCPDNSComplete,
		// Cross-provider DNS shared events
		LogCodeDNSZoneDiscovered, LogCodeDNSRecordDiscovered,
		// Retry helper
		LogCodeRetryBackoff, LogCodeRetryNetworkError, LogCodeRetryAccessDenied,
		LogCodeRetryRateLimited, LogCodeRetryServerError,
	}
	for _, c := range codes {
		s := string(c)
		t.Run(s, func(t *testing.T) {
			parts := strings.Split(s, ".")
			assert.GreaterOrEqual(t, len(parts), 3,
				"code %q must have ≥3 dot-separated segments", s)
			assert.Equal(t, "cloud", parts[0],
				"code %q must lead with the cloud namespace prefix", s)
			assert.Equal(t, strings.ToLower(s), s,
				"code %q must be all lowercase", s)
			assert.NotContains(t, s, " ", "code %q must not contain spaces", s)
		})
	}
}

func TestLogCodes_AreUnique(t *testing.T) {
	seen := map[LogCode]bool{}
	for _, c := range []LogCode{
		LogCodeAWSEC2Starting, LogCodeAWSEC2CredsMissing, LogCodeAWSEC2AssumeRole,
		LogCodeAWSEC2AssumeRoleFailed, LogCodeAWSEC2UsingAssumedRole,
		LogCodeAWSEC2DefaultRegions, LogCodeAWSEC2RegionStarting,
		LogCodeAWSEC2DescribeFailed, LogCodeAWSEC2RegionComplete, LogCodeAWSEC2Complete,
		LogCodeAzureVMStarting, LogCodeAzureVMCredsMissing,
		LogCodeAzureVMTokenAcquireFailed, LogCodeAzureVMEnumeratingSubs,
		LogCodeAzureVMEnumerateSubsFailed, LogCodeAzureVMNoSubsAccessible,
		LogCodeAzureVMSubsDiscovered, LogCodeAzureVMListingVMs,
		LogCodeAzureVMListVMsFailed, LogCodeAzureVMComplete, LogCodeAzureVMSkipUnparseable,
		LogCodeGCPComputeStarting, LogCodeGCPComputeProjectMissing,
		LogCodeGCPComputeTokenAcquireFailed, LogCodeGCPComputeComplete,
		LogCodeGCPComputeTokenFromMetadata, LogCodeGCPComputeTokenFromCredsFile,
		LogCodeGCPComputeTokenCredsFileFailed, LogCodeGCPComputeDiskFetchFailed,
		LogCodeRoute53Disabled, LogCodeRoute53CredsMissing, LogCodeRoute53AssumeRole,
		LogCodeRoute53AssumeRoleFailed, LogCodeRoute53GetDNSSECFailed,
		LogCodeRoute53ListRecordsFailed, LogCodeRoute53SkipUnsupportedType,
		LogCodeRoute53Complete,
		LogCodeCloudflareDisabled, LogCodeCloudflareTokenMissing,
		LogCodeCloudflareListRecordsFailed, LogCodeCloudflareSkipUnsupportedType,
		LogCodeCloudflareComplete,
		LogCodeAzureDNSDisabled, LogCodeAzureDNSCredsMissing,
		LogCodeAzureDNSListZonesFailed, LogCodeAzureDNSListRecordsFailed,
		LogCodeAzureDNSSkipUnsupportedType, LogCodeAzureDNSComplete,
		LogCodeGCPDNSDisabled, LogCodeGCPDNSProjectMissing,
		LogCodeGCPDNSTokenAcquireFailed, LogCodeGCPDNSListRecordsFailed,
		LogCodeGCPDNSSkipUnsupportedType, LogCodeGCPDNSComplete,
		LogCodeDNSZoneDiscovered, LogCodeDNSRecordDiscovered,
		LogCodeRetryBackoff, LogCodeRetryNetworkError, LogCodeRetryAccessDenied,
		LogCodeRetryRateLimited, LogCodeRetryServerError,
	} {
		assert.False(t, seen[c],
			"duplicate log code constant %q", string(c))
		seen[c] = true
	}
}
