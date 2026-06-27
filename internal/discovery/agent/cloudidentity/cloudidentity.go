// Package cloudidentity probes the well-known link-local metadata
// endpoints — AWS IMDSv2/v1, Azure IMDS, GCP metadata server — to
// answer "which cloud is this host in?".
//
// This is the last item on the ServiceNow MID Server taxonomy
// (the "Cloud" row). Unlike most of the windows* track, the probe
// is cross-platform: AWS/Azure/GCP all expose their IMDS over plain
// HTTP at the same link-local IP regardless of guest OS.
//
// The collector returns one row per asset (singleton table) with:
//
//   - cloud_provider — aws/azure/gcp/none (the first responding probe wins)
//   - instance_id    — cross-cloud asset key
//   - account_id     — AWS account / Azure subscription / GCP project
//   - region/AZ/instance_type/image_id/private_ip/public_ip
//   - imds_v2_required (AWS only) — flags hosts still answering IMDSv1
//
// Every probe is **read-only** — pure HTTP GET (with a PUT for the
// IMDSv2 token), no side effects beyond the round-trip itself. The
// total probe budget is bounded by the per-cloud timeout × 3 (we
// run them serially with a tight default of 500ms each so on-prem
// hosts complete the whole pass in ~1.5s).
//
// MITRE T1082 (System Information Discovery, defender side):
// cross-cloud asset key. MITRE T1078.004 (Cloud Accounts): the
// audit pipeline joins this against host_cloud_credentials to spot
// hosts running with credentials from a different cloud account than
// the one they're hosted in (lateral-cloud-pivot indicator).
package cloudidentity

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"time"
)

// CloudProvider is the identified cloud. Pinned to the
// host_cloud_identity.cloud_provider CHECK enum.
type CloudProvider string

const (
	CloudAWS          CloudProvider = "aws"
	CloudAzure        CloudProvider = "azure"
	CloudGCP          CloudProvider = "gcp"
	CloudOracle       CloudProvider = "oracle"
	CloudDigitalOcean CloudProvider = "digitalocean"
	CloudHetzner      CloudProvider = "hetzner"
	CloudLinode       CloudProvider = "linode"
	CloudNone         CloudProvider = "none"
	CloudUnknown      CloudProvider = "unknown"
)

// Source identifies which probe path produced the row.
type Source string

const (
	SourceAWSIMDSv2   Source = "aws-imdsv2"
	SourceAWSIMDSv1   Source = "aws-imdsv1"
	SourceAzureIMDS   Source = "azure-imds"
	SourceGCPMetadata Source = "gcp-metadata"
	SourceNoProbe     Source = "no-probe"
	SourceUnknown     Source = "unknown"
)

// Info mirrors host_cloud_identity's column shape exactly. On-prem
// hosts return CloudProvider=CloudNone with the other fields empty.
type Info struct {
	PrivateIP        string        `json:"private_ip,omitempty"`
	Source           Source        `json:"source"`
	InstanceID       string        `json:"instance_id,omitempty"`
	AccountID        string        `json:"account_id,omitempty"`
	Region           string        `json:"region,omitempty"`
	AvailabilityZone string        `json:"availability_zone,omitempty"`
	InstanceType     string        `json:"instance_type,omitempty"`
	ImageID          string        `json:"image_id,omitempty"`
	ResourceGroup    string        `json:"resource_group,omitempty"`
	Hostname         string        `json:"hostname,omitempty"`
	VPCID            string        `json:"vpc_id,omitempty"`
	PublicIP         string        `json:"public_ip,omitempty"`
	CloudProvider    CloudProvider `json:"cloud_provider"`
	VNetID           string        `json:"vnet_id,omitempty"`
	NetworkID        string        `json:"network_id,omitempty"`
	RawPayloadHash   string        `json:"raw_payload_hash,omitempty"`
	Tags             []string      `json:"tags,omitempty"`
	SecurityGroups   []string      `json:"security_groups,omitempty"`
	IsSpotInstance   bool          `json:"is_spot_instance"`
	IMDSv2Required   bool          `json:"imds_v2_required"`
}

// Collector is the read-only contract every implementation satisfies.
type Collector interface {
	Name() string
	Collect(ctx context.Context) (Info, error)
}

// EncodeStringList returns a JSON array suitable for the *_json
// columns. Empty input always emits "[]" so the column is never NULL.
func EncodeStringList(ss []string) string {
	if len(ss) == 0 {
		return "[]"
	}
	b, err := json.Marshal(ss)
	if err != nil {
		return "[]"
	}
	return string(b)
}

// HashPayload returns the sha256 hex of a metadata payload. Drives
// drift detection — a VM that gets migrated to a different VPC /
// subscription will produce a new hash even when the fields the
// columns capture appear stable.
func HashPayload(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// DefaultProbeTimeout is the per-cloud wall-clock budget for the
// HTTP round-trip. We keep this tight because on-prem hosts hit the
// timeout three times in a row — the total Collect() time would
// blow past acceptable scan budgets if each probe waited 5s.
const DefaultProbeTimeout = 500 * time.Millisecond

// SortInfos returns a deterministic ordering for fleet aggregation —
// the single-asset agent always emits one Info; this helper exists
// for the audit pipeline's cross-host sort.
func SortInfos(infos []Info) {
	sort.Slice(infos, func(i, j int) bool {
		if infos[i].CloudProvider != infos[j].CloudProvider {
			return infos[i].CloudProvider < infos[j].CloudProvider
		}
		return infos[i].InstanceID < infos[j].InstanceID
	})
}
