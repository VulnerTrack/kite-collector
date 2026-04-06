package model

import (
	"crypto/sha256"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// Asset represents a single discovered asset on the network.
type Asset struct {
	FirstSeenAt     time.Time          `json:"first_seen_at"`
	LastSeenAt      time.Time          `json:"last_seen_at"`
	AssetType       AssetType          `json:"asset_type"`
	IsAuthorized    AuthorizationState `json:"is_authorized"`
	IsManaged       ManagedState       `json:"is_managed"`
	Hostname        string             `json:"hostname"`
	OSFamily        string             `json:"os_family"`
	OSVersion       string             `json:"os_version"`
	KernelVersion   string             `json:"kernel_version,omitempty"`
	Architecture    string             `json:"architecture,omitempty"`
	Environment     string             `json:"environment"`
	Owner           string             `json:"owner"`
	Criticality     string             `json:"criticality"`
	DiscoverySource string             `json:"discovery_source"`
	Tags            string             `json:"tags"`        // JSON
	NaturalKey      string             `json:"natural_key"` // computed dedup key
	ID              uuid.UUID          `json:"id"`
}

// ComputeNaturalKey sets NaturalKey to the SHA-256 hex digest of "hostname|asset_type".
func (a *Asset) ComputeNaturalKey() {
	raw := fmt.Sprintf("%s|%s", a.Hostname, a.AssetType)
	hash := sha256.Sum256([]byte(raw))
	a.NaturalKey = fmt.Sprintf("%x", hash)
}

// NetworkInterface captures a single network interface attached to an asset.
type NetworkInterface struct {
	InterfaceName string    `json:"interface_name"`
	IPAddress     string    `json:"ip_address"`
	MACAddress    string    `json:"mac_address"`
	Subnet        string    `json:"subnet"`
	ID            uuid.UUID `json:"id"`
	AssetID       uuid.UUID `json:"asset_id"`
	IsPrimary     bool      `json:"is_primary"`
	IsPublic      bool      `json:"is_public"`
}

// InstalledSoftware records a software package found on an asset.
type InstalledSoftware struct {
	SoftwareName   string    `json:"software_name"`
	Vendor         string    `json:"vendor"`
	Version        string    `json:"version"`
	CPE23          string    `json:"cpe23"`
	PackageManager string    `json:"package_manager"`
	Architecture   string    `json:"architecture,omitempty"`
	ID             uuid.UUID `json:"id"`
	AssetID        uuid.UUID `json:"asset_id"`
}
