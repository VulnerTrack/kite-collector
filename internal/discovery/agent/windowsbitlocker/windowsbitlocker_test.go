package windowsbitlocker

import (
	"strings"
	"testing"
)

func TestPinnedSourceStrings(t *testing.T) {
	pairs := []struct{ got, want string }{
		{string(SourcePowerShellBitLocker), "powershell-bitlocker"},
		{string(SourceNoProbe), "no-probe"},
		{string(SourceUnknown), "unknown"},
	}
	for _, p := range pairs {
		if p.got != p.want {
			t.Fatalf("source drift: got %q want %q", p.got, p.want)
		}
	}
}

func TestHashContentsDeterministic(t *testing.T) {
	a := HashContents([]byte("ok"))
	b := HashContents([]byte("ok"))
	if a != b || len(a) != 64 {
		t.Fatalf("a=%q b=%q", a, b)
	}
}

func TestIsWeakCipher(t *testing.T) {
	hit := []string{"Aes128", "aes128", "Aes128_Diffuser", "XtsAes128", "XTSAES128"}
	for _, m := range hit {
		if !IsWeakCipher(m) {
			t.Fatalf("%q must flag weak", m)
		}
	}
	miss := []string{"Aes256", "XtsAes256", "None", "", "garbage"}
	for _, m := range miss {
		if IsWeakCipher(m) {
			t.Fatalf("%q must NOT flag weak", m)
		}
	}
}

func TestIsProtectionOff(t *testing.T) {
	if IsProtectionOff("On") || IsProtectionOff("on") || IsProtectionOff(" ON ") {
		t.Fatal("ON variants must NOT flag off")
	}
	for _, s := range []string{"Off", "Unknown", "", "InProgress"} {
		if !IsProtectionOff(s) {
			t.Fatalf("%q must flag off", s)
		}
	}
}

func TestIsFullyEncryptedStatus(t *testing.T) {
	if !IsFullyEncryptedStatus("FullyEncrypted") {
		t.Fatal("FullyEncrypted must flag")
	}
	for _, s := range []string{"EncryptionInProgress", "FullyDecrypted", ""} {
		if IsFullyEncryptedStatus(s) {
			t.Fatalf("%q must NOT flag", s)
		}
	}
}

func TestVolumeTypeClassifiers(t *testing.T) {
	if !IsSystemVolumeType("OperatingSystem") {
		t.Fatal("OperatingSystem must flag system")
	}
	if !IsRemovableVolumeType("Removable") {
		t.Fatal("Removable must flag removable")
	}
	if IsSystemVolumeType("FixedData") || IsRemovableVolumeType("FixedData") {
		t.Fatal("FixedData must NOT flag system OR removable")
	}
}

func TestHasProtectorKind(t *testing.T) {
	list := []string{"Tpm", "RecoveryPassword"}
	if !HasProtectorKind(list, "tpm") {
		t.Fatal("case-insensitive match required")
	}
	if HasProtectorKind(list, "StartupKey") {
		t.Fatal("StartupKey not present; must NOT flag")
	}
	if HasProtectorKind(nil, "Tpm") {
		t.Fatal("nil list must NOT flag")
	}
}

func TestEncodeStringList(t *testing.T) {
	if EncodeStringList(nil) != "[]" {
		t.Fatal("nil")
	}
	if got := EncodeStringList([]string{"Tpm", "RecoveryPassword"}); got != `["Tpm","RecoveryPassword"]` {
		t.Fatalf("got %q", got)
	}
}

// -- AnnotateSecurity end-to-end -------------------------------------

func TestAnnotateSystemDriveUnencrypted(t *testing.T) {
	v := Volume{
		MountPoint:       "C:",
		VolumeType:       "OperatingSystem",
		ProtectionStatus: "Off",
		VolumeStatus:     "FullyDecrypted",
		EncryptionMethod: "None",
	}
	AnnotateSecurity(&v)
	if !v.IsProtectionOff {
		t.Fatal("Off must flag")
	}
	if !v.IsSystemDrive {
		t.Fatal("OperatingSystem must flag system")
	}
	if !v.IsSystemDriveUnencrypted {
		t.Fatal("OS-drive + protection-off must flag the headline")
	}
	if v.IsHardened {
		t.Fatal("unencrypted system drive must NOT be hardened")
	}
}

func TestAnnotateHardenedSystemDrive(t *testing.T) {
	v := Volume{
		MountPoint:           "C:",
		VolumeType:           "OperatingSystem",
		ProtectionStatus:     "On",
		VolumeStatus:         "FullyEncrypted",
		EncryptionMethod:     "XtsAes256",
		EncryptionPercentage: 100,
		KeyProtectors:        []string{"Tpm", "RecoveryPassword"},
	}
	AnnotateSecurity(&v)
	if v.IsProtectionOff {
		t.Fatal("On must NOT flag off")
	}
	if !v.IsFullyEncrypted {
		t.Fatal("FullyEncrypted must propagate")
	}
	if v.IsWeakCipher {
		t.Fatal("XtsAes256 must NOT flag weak")
	}
	if !v.HasTPMProtector || !v.HasRecoveryProtector {
		t.Fatalf("protector flags: %+v", v)
	}
	if v.HasNoTPMProtector || v.HasNoRecoveryProtector {
		t.Fatal("both protectors present; must NOT flag missing")
	}
	if !v.IsHardened {
		t.Fatalf("baseline must be hardened: %+v", v)
	}
}

func TestAnnotateWeakCipherOnSystemDrive(t *testing.T) {
	v := Volume{
		VolumeType:       "OperatingSystem",
		ProtectionStatus: "On",
		VolumeStatus:     "FullyEncrypted",
		EncryptionMethod: "Aes128",
		KeyProtectors:    []string{"Tpm", "RecoveryPassword"},
	}
	AnnotateSecurity(&v)
	if !v.IsWeakCipher {
		t.Fatal("Aes128 with protection on must flag weak")
	}
	if v.IsHardened {
		t.Fatal("weak cipher must un-harden")
	}
}

func TestAnnotateNoTPMProtectorOnSystemDrive(t *testing.T) {
	v := Volume{
		VolumeType:       "OperatingSystem",
		ProtectionStatus: "On",
		VolumeStatus:     "FullyEncrypted",
		EncryptionMethod: "XtsAes256",
		KeyProtectors:    []string{"Password", "RecoveryPassword"},
	}
	AnnotateSecurity(&v)
	if v.HasTPMProtector {
		t.Fatal("Password ≠ TPM")
	}
	if !v.HasNoTPMProtector {
		t.Fatal("system drive without TPM protector must flag")
	}
	if v.IsHardened {
		t.Fatal("no TPM on OS drive must un-harden")
	}
}

func TestAnnotateNoRecoveryProtector(t *testing.T) {
	v := Volume{
		VolumeType:       "FixedData",
		ProtectionStatus: "On",
		VolumeStatus:     "FullyEncrypted",
		EncryptionMethod: "XtsAes256",
		KeyProtectors:    []string{"Tpm"},
	}
	AnnotateSecurity(&v)
	if !v.HasNoRecoveryProtector {
		t.Fatal("no RecoveryPassword must flag")
	}
	if v.IsHardened {
		t.Fatal("no recovery protector must un-harden")
	}
}

func TestAnnotateRemovableUnencrypted(t *testing.T) {
	v := Volume{
		VolumeType:       "Removable",
		ProtectionStatus: "Off",
	}
	AnnotateSecurity(&v)
	if !v.IsRemovableUnencrypted {
		t.Fatal("removable + off must flag")
	}
}

// -- ParsePowerShellOutput typical -----------------------------------

func TestParsePowerShellOutputTypical(t *testing.T) {
	body := []byte(`{
        "source": "powershell-bitlocker",
        "volumes": [
            {
                "mount_point": "C:",
                "volume_type": "OperatingSystem",
                "protection_status": "On",
                "lock_status": "Unlocked",
                "volume_status": "FullyEncrypted",
                "encryption_method": "XtsAes256",
                "encryption_percentage": 100,
                "auto_unlock_enabled": false,
                "key_protectors": ["Tpm", "RecoveryPassword"]
            },
            {
                "mount_point": "D:",
                "volume_type": "FixedData",
                "protection_status": "Off",
                "lock_status": "Unlocked",
                "volume_status": "FullyDecrypted",
                "encryption_method": "None",
                "encryption_percentage": 0,
                "auto_unlock_enabled": false,
                "key_protectors": []
            }
        ]
    }`)
	got, err := ParsePowerShellOutput(body)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("volumes=%d", len(got))
	}
	// SortVolumes is alphabetical, C: < D: — keep order.
	c := got[0]
	if c.MountPoint != "C:" || !c.IsHardened {
		t.Fatalf("C: not hardened as expected: %+v", c)
	}
	d := got[1]
	if d.MountPoint != "D:" || !d.IsProtectionOff {
		t.Fatalf("D: should flag off: %+v", d)
	}
}

func TestParsePowerShellOutputSingletonProtectorUnwrap(t *testing.T) {
	// PowerShell collapses one-element arrays to bare scalars.
	body := []byte(`{
        "source": "powershell-bitlocker",
        "volumes": [
            {
                "mount_point": "C:",
                "volume_type": "OperatingSystem",
                "protection_status": "On",
                "volume_status": "FullyEncrypted",
                "encryption_method": "XtsAes256",
                "key_protectors": "Tpm"
            }
        ]
    }`)
	got, err := ParsePowerShellOutput(body)
	if err != nil {
		t.Fatal(err)
	}
	if len(got[0].KeyProtectors) != 1 || got[0].KeyProtectors[0] != "Tpm" {
		t.Fatalf("singleton unwrap broken: %+v", got[0].KeyProtectors)
	}
}

func TestParsePowerShellOutputEmptyMountDropped(t *testing.T) {
	body := []byte(`{
        "source": "powershell-bitlocker",
        "volumes": [
            {"mount_point": "", "volume_type": "FixedData", "protection_status": "On"},
            {"mount_point": "C:", "volume_type": "OperatingSystem", "protection_status": "On", "volume_status": "FullyEncrypted", "encryption_method": "XtsAes256", "key_protectors": ["Tpm", "RecoveryPassword"]}
        ]
    }`)
	got, err := ParsePowerShellOutput(body)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].MountPoint != "C:" {
		t.Fatalf("empty mount must drop: %+v", got)
	}
}

func TestParsePowerShellOutputEmptyVolumeList(t *testing.T) {
	// Host without the BitLocker feature: shim returns `volumes: []`.
	body := []byte(`{"source":"powershell-bitlocker","volumes":[]}`)
	got, err := ParsePowerShellOutput(body)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("want empty, got %d", len(got))
	}
}

func TestParsePowerShellOutputEmpty(t *testing.T) {
	if _, err := ParsePowerShellOutput(nil); err == nil {
		t.Fatal("empty must error")
	}
}

func TestParsePowerShellOutputMalformed(t *testing.T) {
	if _, err := ParsePowerShellOutput([]byte("not json")); err == nil {
		t.Fatal("malformed must error")
	}
}

func TestParsePowerShellOutputBOMTolerance(t *testing.T) {
	body := append([]byte{0xEF, 0xBB, 0xBF}, []byte(`{"source":"powershell-bitlocker","volumes":[]}`)...)
	if _, err := ParsePowerShellOutput(body); err != nil {
		t.Fatalf("BOM should be tolerated: %v", err)
	}
}

// -- script shape spot-check ----------------------------------------

func TestPowerShellScriptShape(t *testing.T) {
	for _, must := range []string{
		"Get-BitLockerVolume",
		"ProtectionStatus",
		"VolumeStatus",
		"EncryptionMethod",
		"KeyProtector",
		"ConvertTo-Json",
	} {
		if !strings.Contains(PowerShellScript, must) {
			t.Fatalf("PowerShellScript missing %q", must)
		}
	}
}

// -- SortVolumes ---------------------------------------------------

func TestSortVolumesDeterministic(t *testing.T) {
	in := []Volume{
		{MountPoint: "D:"},
		{MountPoint: "C:"},
		{MountPoint: "B:"},
	}
	SortVolumes(in)
	if in[0].MountPoint != "B:" || in[2].MountPoint != "D:" {
		t.Fatalf("sort wrong: %+v", in)
	}
}
