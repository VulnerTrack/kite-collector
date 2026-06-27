package cloudidentity

import (
	"encoding/json"
	"fmt"
	"strings"
)

// ParseAWSIdentityDocument converts the JSON body returned by
// http://169.254.169.254/latest/dynamic/instance-identity/document
// into an Info. The IMDSv2 document is identical to IMDSv1 — the
// only difference is whether the request required a session token.
//
// Source layer: callers set Source=SourceAWSIMDSv2 or v1 depending
// on which path produced the bytes; we never override that here.
func ParseAWSIdentityDocument(data []byte) (Info, error) {
	if len(data) == 0 {
		return Info{}, fmt.Errorf("empty AWS identity document")
	}
	var doc awsIdentityDoc
	if err := json.Unmarshal(data, &doc); err != nil {
		return Info{}, fmt.Errorf("decode aws identity doc: %w", err)
	}
	info := Info{
		CloudProvider:    CloudAWS,
		InstanceID:       strings.TrimSpace(doc.InstanceID),
		AccountID:        strings.TrimSpace(doc.AccountID),
		Region:           strings.TrimSpace(doc.Region),
		AvailabilityZone: strings.TrimSpace(doc.AvailabilityZone),
		InstanceType:     strings.TrimSpace(doc.InstanceType),
		ImageID:          strings.TrimSpace(doc.ImageID),
		PrivateIP:        strings.TrimSpace(doc.PrivateIP),
		RawPayloadHash:   HashPayload(data),
	}
	return info, nil
}

type awsIdentityDoc struct {
	AccountID        string `json:"accountId"`
	InstanceID       string `json:"instanceId"`
	Region           string `json:"region"`
	AvailabilityZone string `json:"availabilityZone"`
	InstanceType     string `json:"instanceType"`
	ImageID          string `json:"imageId"`
	PrivateIP        string `json:"privateIp"`
}

// ParseAzureIMDS converts the JSON body returned by
// http://169.254.169.254/metadata/instance?api-version=...
// into an Info. The Azure payload nests `compute` + `network` —
// we flatten the security-relevant subset.
func ParseAzureIMDS(data []byte) (Info, error) {
	if len(data) == 0 {
		return Info{}, fmt.Errorf("empty Azure IMDS payload")
	}
	var payload azureIMDS
	if err := json.Unmarshal(data, &payload); err != nil {
		return Info{}, fmt.Errorf("decode azure imds: %w", err)
	}
	info := Info{
		CloudProvider:    CloudAzure,
		Source:           SourceAzureIMDS,
		InstanceID:       strings.TrimSpace(payload.Compute.VMID),
		AccountID:        strings.TrimSpace(payload.Compute.SubscriptionID),
		Region:           strings.TrimSpace(payload.Compute.Location),
		InstanceType:     strings.TrimSpace(payload.Compute.VMSize),
		ImageID:          azureImageRef(payload.Compute.StorageProfile.ImageReference),
		Hostname:         strings.TrimSpace(payload.Compute.Name),
		ResourceGroup:    strings.TrimSpace(payload.Compute.ResourceGroupName),
		AvailabilityZone: strings.TrimSpace(payload.Compute.Zone),
		Tags:             azureTags(payload.Compute.TagsList),
		IsSpotInstance:   strings.EqualFold(strings.TrimSpace(payload.Compute.Priority), "Spot"),
		RawPayloadHash:   HashPayload(data),
	}
	if len(payload.Network.Interface) > 0 {
		nic := payload.Network.Interface[0]
		if len(nic.IPv4.IPAddress) > 0 {
			info.PrivateIP = strings.TrimSpace(nic.IPv4.IPAddress[0].PrivateIPAddress)
			info.PublicIP = strings.TrimSpace(nic.IPv4.IPAddress[0].PublicIPAddress)
		}
		info.VNetID = strings.TrimSpace(nic.MACAddress) // best-effort placeholder
		if len(nic.IPv4.Subnet) > 0 {
			info.VNetID = strings.TrimSpace(nic.IPv4.Subnet[0].Address) +
				"/" + strings.TrimSpace(nic.IPv4.Subnet[0].Prefix)
		}
	}
	return info, nil
}

type azureIMDS struct {
	Compute azureCompute `json:"compute"`
	Network azureNetwork `json:"network"`
}

type azureCompute struct {
	VMID              string         `json:"vmId"`
	SubscriptionID    string         `json:"subscriptionId"`
	Location          string         `json:"location"`
	VMSize            string         `json:"vmSize"`
	Name              string         `json:"name"`
	ResourceGroupName string         `json:"resourceGroupName"`
	Zone              string         `json:"zone"`
	Priority          string         `json:"priority"`
	StorageProfile    azureStorage   `json:"storageProfile"`
	TagsList          []azureTagPair `json:"tagsList"`
}

type azureStorage struct {
	ImageReference azureImage `json:"imageReference"`
}

type azureImage struct {
	ID        string `json:"id"`
	Publisher string `json:"publisher"`
	Offer     string `json:"offer"`
	SKU       string `json:"sku"`
	Version   string `json:"version"`
}

type azureTagPair struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type azureNetwork struct {
	Interface []azureInterface `json:"interface"`
}

type azureInterface struct {
	MACAddress string  `json:"macAddress"`
	IPv4       azureV4 `json:"ipv4"`
}

type azureV4 struct {
	IPAddress []azureIPPair `json:"ipAddress"`
	Subnet    []azureSubnet `json:"subnet"`
}

type azureIPPair struct {
	PrivateIPAddress string `json:"privateIpAddress"`
	PublicIPAddress  string `json:"publicIpAddress"`
}

type azureSubnet struct {
	Address string `json:"address"`
	Prefix  string `json:"prefix"`
}

func azureImageRef(img azureImage) string {
	if img.ID != "" {
		return img.ID
	}
	parts := []string{img.Publisher, img.Offer, img.SKU, img.Version}
	out := make([]string, 0, 4)
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return strings.Join(out, ":")
}

func azureTags(in []azureTagPair) []string {
	if len(in) == 0 {
		return nil
	}
	out := make([]string, 0, len(in))
	for _, t := range in {
		out = append(out, t.Name+"="+t.Value)
	}
	return out
}

// ParseGCPMetadata converts the JSON body returned by
// http://metadata.google.internal/computeMetadata/v1/instance/?recursive=true&alt=json
// (with the `Metadata-Flavor: Google` header) into an Info.
//
// The collector also fetches /project/project-id separately for the
// AccountID; that string is passed in via the `projectID` arg so the
// parser stays HTTP-free.
func ParseGCPMetadata(instanceJSON []byte, projectID string) (Info, error) {
	if len(instanceJSON) == 0 {
		return Info{}, fmt.Errorf("empty GCP metadata payload")
	}
	var doc gcpInstance
	if err := json.Unmarshal(instanceJSON, &doc); err != nil {
		return Info{}, fmt.Errorf("decode gcp metadata: %w", err)
	}
	info := Info{
		CloudProvider:    CloudGCP,
		Source:           SourceGCPMetadata,
		InstanceID:       fmt.Sprintf("%d", doc.ID),
		AccountID:        strings.TrimSpace(projectID),
		Region:           gcpRegionFromZone(doc.Zone),
		AvailabilityZone: gcpShortName(doc.Zone),
		InstanceType:     gcpShortName(doc.MachineType),
		ImageID:          strings.TrimSpace(doc.Image),
		Hostname:         strings.TrimSpace(doc.Hostname),
		IsSpotInstance:   doc.Scheduling.Preemptible,
		Tags:             append([]string(nil), doc.Tags...),
		RawPayloadHash:   HashPayload(instanceJSON),
	}
	if len(doc.NetworkInterfaces) > 0 {
		nic := doc.NetworkInterfaces[0]
		info.PrivateIP = strings.TrimSpace(nic.IP)
		info.NetworkID = strings.TrimSpace(nic.Network)
		if len(nic.AccessConfigs) > 0 {
			info.PublicIP = strings.TrimSpace(nic.AccessConfigs[0].ExternalIP)
		}
	}
	return info, nil
}

type gcpInstance struct {
	Name              string               `json:"name"`
	Hostname          string               `json:"hostname"`
	Zone              string               `json:"zone"`
	MachineType       string               `json:"machineType"`
	Image             string               `json:"image"`
	Tags              []string             `json:"tags"`
	NetworkInterfaces []gcpNIC             `json:"networkInterfaces"`
	ID                uint64               `json:"id"`
	Scheduling        gcpSchedulingDetails `json:"scheduling"`
}

type gcpNIC struct {
	IP            string         `json:"ip"`
	Network       string         `json:"network"`
	AccessConfigs []gcpAccessCfg `json:"accessConfigs"`
}

type gcpAccessCfg struct {
	ExternalIP string `json:"externalIp"`
}

type gcpSchedulingDetails struct {
	Preemptible bool `json:"preemptible"`
}

// gcpShortName trims a fully-qualified Compute Engine resource path
// (e.g. "projects/123/zones/us-central1-a") to just the leaf name.
func gcpShortName(path string) string {
	s := strings.TrimSpace(path)
	if s == "" {
		return ""
	}
	if i := strings.LastIndexByte(s, '/'); i >= 0 {
		return s[i+1:]
	}
	return s
}

// gcpRegionFromZone strips the trailing zone letter — "us-central1-a"
// → "us-central1". GCE zones are always "<region>-<letter>".
func gcpRegionFromZone(zonePath string) string {
	zone := gcpShortName(zonePath)
	if i := strings.LastIndexByte(zone, '-'); i > 0 {
		return zone[:i]
	}
	return zone
}
