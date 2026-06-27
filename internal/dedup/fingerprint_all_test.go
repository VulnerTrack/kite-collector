package dedup

import (
	"strings"
	"testing"

	"github.com/vulnertrack/kite-collector/internal/model"
)

func TestAgentEnrolledHost_HardwareWhenTPMPresent(t *testing.T) {
	fp := AgentEnrolledHostFingerprinter{Type: model.AssetTypeServer}
	rec := DiscoveryRecord{
		TenantID:       "t",
		TPMEKPubSHA256: strings.Repeat("a", 64),
		MACAddresses:   []string{"aa:bb:cc:dd:ee:01"},
	}
	_, _, conf, ok := fp.Identity(rec)
	if !ok || conf != ConfidenceHardware {
		t.Fatalf("ok=%v conf=%v, want Hardware", ok, conf)
	}
}

func TestAgentEnrolledHost_NetworkWhenOnlyMACs(t *testing.T) {
	fp := AgentEnrolledHostFingerprinter{Type: model.AssetTypeServer}
	_, _, conf, ok := fp.Identity(DiscoveryRecord{
		MACAddresses: []string{"aa:bb:cc:dd:ee:01"},
	})
	if !ok || conf != ConfidenceNetwork {
		t.Fatalf("ok=%v conf=%v, want Network", ok, conf)
	}
}

func TestAgentEnrolledHost_DeclinesWithoutSignals(t *testing.T) {
	fp := AgentEnrolledHostFingerprinter{Type: model.AssetTypeServer}
	if _, _, _, ok := fp.Identity(DiscoveryRecord{Hostname: "h"}); ok {
		t.Error("must decline with no hardware/network signals")
	}
}

func TestAgentEnrolledHost_MACOrderIndependence(t *testing.T) {
	fp := AgentEnrolledHostFingerprinter{Type: model.AssetTypeServer}
	a, _, _, _ := fp.Identity(DiscoveryRecord{
		MACAddresses: []string{"aa:bb:cc:dd:ee:01", "AA:BB:CC:DD:EE:02"},
	})
	b, _, _, _ := fp.Identity(DiscoveryRecord{
		MACAddresses: []string{"AABB.CCDD.EE02", "aa-bb-cc-dd-ee-01"},
	})
	if a != b {
		t.Errorf("MAC order/case sensitivity: %x vs %x", a, b)
	}
}

func TestContainer_RequiresPlatformAndWorkload(t *testing.T) {
	fp := ContainerFingerprinter{}
	if _, _, _, ok := fp.Identity(DiscoveryRecord{PlatformID: "k8s"}); ok {
		t.Error("missing workload must decline")
	}
	if _, _, _, ok := fp.Identity(DiscoveryRecord{WorkloadName: "web"}); ok {
		t.Error("missing platform must decline")
	}
}

func TestContainer_CryptographicWithImageDigest(t *testing.T) {
	fp := ContainerFingerprinter{}
	good := "sha256:" + strings.Repeat("a", 64)
	_, _, conf, ok := fp.Identity(DiscoveryRecord{
		PlatformID:   "k8s",
		WorkloadName: "web",
		ImageDigest:  good,
	})
	if !ok || conf != ConfidenceCryptographic {
		t.Fatalf("ok=%v conf=%v", ok, conf)
	}
}

func TestContainer_RejectsTagOnlyImage(t *testing.T) {
	fp := ContainerFingerprinter{}
	_, _, conf, ok := fp.Identity(DiscoveryRecord{
		PlatformID:   "k8s",
		WorkloadName: "web",
		ImageDigest:  "nginx:latest",
	})
	if !ok || conf != ConfidenceNetwork {
		t.Fatalf("ok=%v conf=%v, want Network (tag is mutable)", ok, conf)
	}
}

func TestVCS_RootCommitUpgradesConfidence(t *testing.T) {
	fp := VCSRepositoryFingerprinter{Type: model.AssetTypeRepository}
	_, _, conf, ok := fp.Identity(DiscoveryRecord{VCSURL: "https://github.com/org/repo"})
	if !ok || conf != ConfidenceNetwork {
		t.Fatalf("ok=%v conf=%v, want Network", ok, conf)
	}
	_, _, conf, ok = fp.Identity(DiscoveryRecord{
		VCSURL:     "https://github.com/org/repo",
		RootCommit: strings.Repeat("a", 40),
	})
	if !ok || conf != ConfidenceCryptographic {
		t.Fatalf("ok=%v conf=%v, want Cryptographic", ok, conf)
	}
}

func TestVCS_URLNormalization(t *testing.T) {
	fp := VCSRepositoryFingerprinter{Type: model.AssetTypeRepository}
	a, _, _, _ := fp.Identity(DiscoveryRecord{VCSURL: "https://github.com/org/repo.git"})
	b, _, _, _ := fp.Identity(DiscoveryRecord{VCSURL: "git@github.com:org/repo"})
	if a != b {
		t.Errorf("URL normalization: %x vs %x", a, b)
	}
}

func TestCMDB_RequiresBothFields(t *testing.T) {
	fp := CMDBFingerprinter{Type: model.AssetTypeServer}
	if _, _, _, ok := fp.Identity(DiscoveryRecord{UpstreamSource: "netbox"}); ok {
		t.Error("missing UpstreamID must decline")
	}
	if _, _, _, ok := fp.Identity(DiscoveryRecord{UpstreamID: "device-42"}); ok {
		t.Error("missing UpstreamSource must decline")
	}
}

func TestCMDB_HappyPath(t *testing.T) {
	fp := CMDBFingerprinter{Type: model.AssetTypeServer}
	_, sigs, conf, ok := fp.Identity(DiscoveryRecord{
		UpstreamSource: "Netbox",
		UpstreamID:     "device-42",
	})
	if !ok || conf != ConfidenceCryptographic {
		t.Fatalf("ok=%v conf=%v", ok, conf)
	}
	if len(sigs) != 2 {
		t.Errorf("want 2 signals, got %d", len(sigs))
	}
}

func TestNetworkDevice_LLDPAlone(t *testing.T) {
	fp := NetworkDeviceFingerprinter{}
	_, _, conf, ok := fp.Identity(DiscoveryRecord{LLDPChassisID: "00:1a:2b:3c:4d:5e"})
	if !ok || conf != ConfidenceNetwork {
		t.Fatalf("ok=%v conf=%v", ok, conf)
	}
}

func TestNetworkDevice_SNMPPlusSerial(t *testing.T) {
	fp := NetworkDeviceFingerprinter{}
	_, _, conf, ok := fp.Identity(DiscoveryRecord{
		SNMPSysObjectID: "1.3.6.1.4.1.9.1.516",
		SerialNumber:    "FOC12345678",
	})
	if !ok || conf != ConfidenceCryptographic {
		t.Fatalf("ok=%v conf=%v", ok, conf)
	}
}

func TestLAN_SSHHostKeyDeterministic(t *testing.T) {
	fp := LANAgentlessFingerprinter{}
	a, _, _, _ := fp.Identity(DiscoveryRecord{SSHHostKeySHA256: strings.Repeat("a", 64)})
	b, _, _, _ := fp.Identity(DiscoveryRecord{SSHHostKeySHA256: strings.ToUpper(strings.Repeat("a", 64))})
	if a != b {
		t.Errorf("SSH host key not case-folded: %x vs %x", a, b)
	}
}

func TestLAN_DeclinesWithoutAnySignal(t *testing.T) {
	fp := LANAgentlessFingerprinter{}
	if _, _, _, ok := fp.Identity(DiscoveryRecord{Hostname: "h"}); ok {
		t.Error("LAN fingerprinter should not accept hostname-only records")
	}
}

func TestIOT_UPnPUUIDPreferred(t *testing.T) {
	fp := IOTDeviceFingerprinter{}
	_, _, conf, ok := fp.Identity(DiscoveryRecord{
		UPnPUUID: "00000000-0000-0000-0000-000000000001",
	})
	if !ok || conf != ConfidenceNetwork {
		t.Fatalf("ok=%v conf=%v", ok, conf)
	}
}

func TestIOT_HostnameFallbackIsNominal(t *testing.T) {
	fp := IOTDeviceFingerprinter{}
	_, _, conf, ok := fp.Identity(DiscoveryRecord{Hostname: "printer.local"})
	if !ok || conf != ConfidenceNominal {
		t.Fatalf("ok=%v conf=%v, want Nominal", ok, conf)
	}
}

func TestRegistry_DispatchByAssetType(t *testing.T) {
	r := DefaultRegistry()
	for _, tc := range []struct {
		t    model.AssetType
		want bool
	}{
		{model.AssetTypeCloudInstance, true},
		{model.AssetTypeServer, true},
		{model.AssetTypeWorkstation, true},
		{model.AssetTypeContainer, true},
		{model.AssetTypeNetworkDevice, true},
		{model.AssetTypeIOTDevice, true},
		{model.AssetTypeRepository, true},
		{model.AssetTypeSoftwareProject, true},
	} {
		_, ok := r.Get(tc.t)
		if ok != tc.want {
			t.Errorf("Get(%s) ok=%v, want %v", tc.t, ok, tc.want)
		}
	}
}

func TestRegistry_OverrideWins(t *testing.T) {
	r := NewRegistry()
	r.Register(CloudInstanceFingerprinter{})
	r.Register(stubFP{})
	got, _ := r.Get(model.AssetTypeCloudInstance)
	if _, isStub := got.(stubFP); !isStub {
		t.Error("second Register must overwrite first")
	}
}

type stubFP struct{}

func (stubFP) AssetType() model.AssetType { return model.AssetTypeCloudInstance }
func (stubFP) Identity(DiscoveryRecord) ([32]byte, []Signal, Confidence, bool) {
	return [32]byte{}, nil, ConfidenceUnknown, false
}
