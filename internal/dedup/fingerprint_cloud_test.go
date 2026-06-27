package dedup

import (
	"testing"

	"github.com/vulnertrack/kite-collector/internal/model"
)

func baseCloudRecord() DiscoveryRecord {
	return DiscoveryRecord{
		TenantID:   "t-acme",
		AssetType:  model.AssetTypeCloudInstance,
		Provider:   "aws",
		AccountID:  "123456789012",
		InstanceID: "i-0abcdef1234567890",
	}
}

func TestCloudInstanceFingerprinter_TableDriven(t *testing.T) {
	fp := CloudInstanceFingerprinter{}
	base, _, _, ok := fp.Identity(baseCloudRecord())
	if !ok {
		t.Fatal("base record must produce a fingerprint")
	}

	cases := []struct {
		mutate          func(*DiscoveryRecord)
		name            string
		wantOK          bool
		wantConf        Confidence
		equalsBase      bool
		differsFromBase bool
	}{
		{
			name:   "identical input is deterministic",
			wantOK: true, wantConf: ConfidenceCryptographic, equalsBase: true,
		},
		{
			name:   "provider case is normalized",
			mutate: func(r *DiscoveryRecord) { r.Provider = "AWS" },
			wantOK: true, equalsBase: true,
		},
		{
			name:   "different account → different digest",
			mutate: func(r *DiscoveryRecord) { r.AccountID = "000000000042" },
			wantOK: true, differsFromBase: true,
		},
		{
			name:   "instance_id case sensitivity preserved",
			mutate: func(r *DiscoveryRecord) { r.InstanceID = "I-0ABCDEF1234567890" },
			wantOK: true, differsFromBase: true,
		},
		{
			name:   "same instance_id, different provider → different digest",
			mutate: func(r *DiscoveryRecord) { r.Provider = "azure"; r.AccountID = "" },
			// Azure rejected this AWS-format account_id, so account_id is
			// dropped — but provider is still partitioned, so digests differ.
			wantOK: true, differsFromBase: true,
		},
		{
			name:   "tenant scope flip → different digest",
			mutate: func(r *DiscoveryRecord) { r.TenantID = "t-other" },
			wantOK: true, differsFromBase: true,
		},
		{
			name:   "empty tenant → different digest from scoped tenant",
			mutate: func(r *DiscoveryRecord) { r.TenantID = "" },
			wantOK: true, differsFromBase: true,
		},
		{
			name:   "missing provider declines",
			mutate: func(r *DiscoveryRecord) { r.Provider = "" },
			wantOK: false,
		},
		{
			name:   "unknown provider declines",
			mutate: func(r *DiscoveryRecord) { r.Provider = "mystery-cloud" },
			wantOK: false,
		},
		{
			name:   "missing instance_id declines",
			mutate: func(r *DiscoveryRecord) { r.InstanceID = "" },
			wantOK: false,
		},
		{
			name:   "missing account_id is tolerated, confidence stays Cryptographic",
			mutate: func(r *DiscoveryRecord) { r.AccountID = "" },
			wantOK: true, wantConf: ConfidenceCryptographic, differsFromBase: true,
		},
		{
			name:   "instance_id containing US byte does not collide via separator",
			mutate: func(r *DiscoveryRecord) { r.InstanceID = "i-abc\x1fdef" },
			wantOK: true, differsFromBase: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := baseCloudRecord()
			if tc.mutate != nil {
				tc.mutate(&rec)
			}
			d, sigs, conf, ok := fp.Identity(rec)
			if ok != tc.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tc.wantOK)
			}
			if !ok {
				return
			}
			if tc.wantConf != 0 && conf != tc.wantConf {
				t.Errorf("confidence = %v, want %v", conf, tc.wantConf)
			}
			if tc.equalsBase && d != base {
				t.Errorf("digest %x; want equal to base %x", d, base)
			}
			if tc.differsFromBase && d == base {
				t.Errorf("digest %x; want different from base", d)
			}
			if len(sigs) == 0 {
				t.Error("expected non-empty signals on ok=true")
			}
		})
	}
}

func TestCloudInstanceFingerprinter_Avalanche(t *testing.T) {
	fp := CloudInstanceFingerprinter{}
	a := baseCloudRecord()
	b := baseCloudRecord()
	// Single byte flip in instance_id.
	bytes := []byte(b.InstanceID)
	bytes[len(bytes)-1] ^= 0x01
	b.InstanceID = string(bytes)
	da, _, _, _ := fp.Identity(a)
	db, _, _, _ := fp.Identity(b)
	if da == db {
		t.Error("single-bit flip in instance_id must change digest")
	}
}

func TestCloudInstanceFingerprinter_NoCollisionsAcrossTenants(t *testing.T) {
	fp := CloudInstanceFingerprinter{}
	seen := make(map[[32]byte]string, 1000)
	for i := 0; i < 1000; i++ {
		rec := baseCloudRecord()
		rec.TenantID = randomTenant(i)
		rec.InstanceID = randomInstance(i)
		d, _, _, ok := fp.Identity(rec)
		if !ok {
			t.Fatalf("trial %d declined", i)
		}
		if prev, dup := seen[d]; dup {
			t.Fatalf("collision at trial %d: previous=%s", i, prev)
		}
		seen[d] = rec.InstanceID
	}
}

func randomTenant(i int) string {
	if i%2 == 0 {
		return "tenant-a"
	}
	return "tenant-b"
}

func randomInstance(i int) string {
	// Use i directly as the entropy source so trials are deterministic
	// and provably non-colliding: 1000 distinct integers → 1000 distinct
	// strings.
	const alphabet = "0123456789abcdef"
	out := make([]byte, 19)
	out[0] = 'i'
	out[1] = '-'
	x := uint64(i)
	for j := 2; j < 19; j++ {
		out[j] = alphabet[x&0xf]
		x >>= 4
		if x == 0 {
			// Pad the rest with a position-dependent byte so the full
			// 17-char tail is still distinct across trials. Without this,
			// small i values would all end in many zeroes.
			x = uint64(i)*0x9E3779B97F4A7C15 + uint64(j)
		}
	}
	return string(out)
}
