package windowshardware

import (
	"strings"
	"testing"
)

func TestPinnedSourceStrings(t *testing.T) {
	pairs := []struct{ got, want string }{
		{string(SourcePowerShellCIM), "powershell-cim"},
		{string(SourcePowerShellWMI), "powershell-wmi"},
		{string(SourceUnknown), "unknown"},
	}
	for _, p := range pairs {
		if p.got != p.want {
			t.Fatalf("source drift: got %q want %q", p.got, p.want)
		}
	}
}

func TestEncodeIntList(t *testing.T) {
	if EncodeIntList(nil) != "[]" {
		t.Fatal("nil")
	}
	if got := EncodeIntList([]int{10}); got != "[10]" {
		t.Fatalf("got %q", got)
	}
}

func TestClassifyVMFamilyHyperV(t *testing.T) {
	fam, ok := ClassifyVMFamily(
		"Microsoft Corporation", // vendor
		"Virtual Machine",       // name
		"7.0",                   // version
		"Microsoft Corporation", // baseboard manufacturer
		"Virtual Machine",       // baseboard product
		"Microsoft Corporation", // BIOS manufacturer
	)
	if !ok {
		t.Fatal("Hyper-V signature must match")
	}
	if fam != "hyper-v" {
		t.Fatalf("vm_family=%q", fam)
	}
}

func TestClassifyVMFamilyVMware(t *testing.T) {
	fam, ok := ClassifyVMFamily("VMware, Inc.", "VMware20,1", "None",
		"Intel Corporation", "440BX Desktop Reference Platform",
		"Phoenix Technologies LTD")
	if !ok || fam != "vmware" {
		t.Fatalf("got fam=%q ok=%v", fam, ok)
	}
}

func TestClassifyVMFamilyVirtualBox(t *testing.T) {
	fam, ok := ClassifyVMFamily("innotek GmbH", "VirtualBox", "1.2",
		"Oracle Corporation", "VirtualBox", "innotek GmbH")
	if !ok || fam != "virtualbox" {
		t.Fatalf("got fam=%q ok=%v", fam, ok)
	}
}

func TestClassifyVMFamilyKVM(t *testing.T) {
	fam, ok := ClassifyVMFamily("QEMU", "Standard PC (i440FX + PIIX, 1996)",
		"pc-i440fx-7.2", "QEMU", "Standard PC", "SeaBIOS")
	if !ok || fam != "kvm" {
		t.Fatalf("got fam=%q ok=%v", fam, ok)
	}
}

func TestClassifyVMFamilyPhysical(t *testing.T) {
	_, ok := ClassifyVMFamily("Dell Inc.", "Latitude 7440", "1.0",
		"Dell Inc.", "0HK2VK", "Dell Inc.")
	if ok {
		t.Fatal("Dell laptop must NOT match any VM hint")
	}
}

func TestAnnotateSecuritySetsVMFields(t *testing.T) {
	h := Hardware{
		SystemVendor: "VMware, Inc.",
		SystemName:   "VMware20,1",
	}
	AnnotateSecurity(&h)
	if !h.IsVirtualMachine {
		t.Fatal("must flag VM")
	}
	if h.VMFamily != "vmware" {
		t.Fatalf("vm_family=%q", h.VMFamily)
	}
}

func TestAnnotateSecurityPhysicalHostStaysFalse(t *testing.T) {
	h := Hardware{
		SystemVendor: "Dell Inc.",
		SystemName:   "Latitude 7440",
	}
	AnnotateSecurity(&h)
	if h.IsVirtualMachine {
		t.Fatal("physical Dell host must NOT flag VM")
	}
}

// -- ParsePowerShellOutput ----------------------------------------------

func TestParsePowerShellOutputDellLaptop(t *testing.T) {
	body := []byte(`{
        "bios_manufacturer": "Dell Inc.",
        "bios_version": "1.18.0",
        "bios_release_date": "2024-04-12T00:00:00Z",
        "bios_serial": "ABCDEF1",
        "bios_smbios_version": "3.4",
        "baseboard_manufacturer": "Dell Inc.",
        "baseboard_product": "0HK2VK",
        "baseboard_version": "A00",
        "baseboard_serial": "/ABCDEF1/CN1234567890/",
        "system_uuid": "12345678-ABCD-1234-ABCD-1234567890AB",
        "system_identifying_number": "ABCDEF1",
        "system_vendor": "Dell Inc.",
        "system_version": "Latitude 7440",
        "system_name": "Latitude 7440",
        "chassis_serial": "ABCDEF1",
        "chassis_asset_tag": "ASSET-001234",
        "chassis_types": [10],
        "chassis_security_status": 3
    }`)
	got, err := ParsePowerShellOutput(body)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got.SystemUUID != "12345678-abcd-1234-abcd-1234567890ab" {
		t.Fatalf("UUID not lowercased: %q", got.SystemUUID)
	}
	if got.ChassisAssetTag != "ASSET-001234" {
		t.Fatalf("asset_tag=%q", got.ChassisAssetTag)
	}
	if len(got.ChassisTypes) != 1 || got.ChassisTypes[0] != 10 {
		t.Fatalf("chassis_types=%v", got.ChassisTypes)
	}
	if got.ChassisSecurityStatus != 3 {
		t.Fatalf("security_status=%d", got.ChassisSecurityStatus)
	}
	if got.IsVirtualMachine {
		t.Fatal("Dell physical laptop must NOT flag VM")
	}
	if got.BIOSReleaseDate != "2024-04-12T00:00:00Z" {
		t.Fatalf("bios_release_date=%q (not canonicalised)", got.BIOSReleaseDate)
	}
}

func TestParsePowerShellOutputHyperVGuest(t *testing.T) {
	body := []byte(`{
        "bios_manufacturer": "Microsoft Corporation",
        "bios_version": "Hyper-V UEFI Release v4.1",
        "bios_release_date": null,
        "bios_serial": "0000-0007-7820-8194-0795-3776-43",
        "bios_smbios_version": "3.1",
        "baseboard_manufacturer": "Microsoft Corporation",
        "baseboard_product": "Virtual Machine",
        "baseboard_version": "Hyper-V UEFI Release v4.1",
        "baseboard_serial": "0000-0007-7820-8194-0795-3776-43",
        "system_uuid": "ABCDEF12-3456-7890-ABCD-EF1234567890",
        "system_identifying_number": "0000-0007-7820-8194-0795-3776-43",
        "system_vendor": "Microsoft Corporation",
        "system_version": "Hyper-V UEFI Release v4.1",
        "system_name": "Virtual Machine",
        "chassis_serial": "0000-0007-7820-8194-0795-3776-43",
        "chassis_asset_tag": null,
        "chassis_types": [3],
        "chassis_security_status": 3
    }`)
	got, err := ParsePowerShellOutput(body)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !got.IsVirtualMachine {
		t.Fatal("Hyper-V guest must flag VM")
	}
	if got.VMFamily != "hyper-v" {
		t.Fatalf("vm_family=%q", got.VMFamily)
	}
}

func TestParsePowerShellOutputDegenerateUUIDDropped(t *testing.T) {
	body := []byte(`{
        "system_uuid": "FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF",
        "chassis_types": [],
        "chassis_security_status": 0
    }`)
	got, err := ParsePowerShellOutput(body)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got.SystemUUID != "" {
		t.Fatalf("degenerate uuid must be coerced to empty; got %q", got.SystemUUID)
	}
}

func TestParsePowerShellOutputSparseSMBIOS(t *testing.T) {
	body := []byte(`{
        "bios_manufacturer": "American Megatrends Inc.",
        "bios_version": "F.30",
        "bios_release_date": null,
        "bios_smbios_version": null,
        "baseboard_manufacturer": "HP",
        "baseboard_product": null,
        "baseboard_serial": null,
        "system_uuid": null,
        "chassis_types": null,
        "chassis_security_status": 0
    }`)
	got, err := ParsePowerShellOutput(body)
	if err != nil {
		t.Fatalf("sparse smbios must not error: %v", err)
	}
	if got.BIOSManufacturer != "American Megatrends Inc." {
		t.Fatalf("bios_manufacturer=%q", got.BIOSManufacturer)
	}
	if len(got.ChassisTypes) != 0 {
		t.Fatalf("chassis_types=%v (null must coerce to empty)", got.ChassisTypes)
	}
}

func TestParsePowerShellOutputEmptyError(t *testing.T) {
	if _, err := ParsePowerShellOutput(nil); err == nil {
		t.Fatal("empty must error")
	}
}

func TestParsePowerShellOutputMalformedError(t *testing.T) {
	if _, err := ParsePowerShellOutput([]byte("not json")); err == nil {
		t.Fatal("malformed must error")
	}
}

func TestParsePowerShellOutputBOMTolerated(t *testing.T) {
	body := append([]byte{0xEF, 0xBB, 0xBF}, []byte(`{
        "bios_manufacturer": "BOM Inc.",
        "chassis_types": [],
        "chassis_security_status": 0
    }`)...)
	got, err := ParsePowerShellOutput(body)
	if err != nil {
		t.Fatal(err)
	}
	if got.BIOSManufacturer != "BOM Inc." {
		t.Fatalf("bios_manufacturer=%q", got.BIOSManufacturer)
	}
}

func TestPowerShellScriptShape(t *testing.T) {
	for _, must := range []string{
		"Win32_BIOS",
		"Win32_BaseBoard",
		"Win32_ComputerSystemProduct",
		"Win32_SystemEnclosure",
		"ConvertTo-Json",
		"chassis_types",
		"system_uuid",
	} {
		if !strings.Contains(PowerShellScript, must) {
			t.Fatalf("PowerShellScript missing %q", must)
		}
	}
}

func TestSortHardwaresDeterministic(t *testing.T) {
	in := []Hardware{
		{SystemVendor: "Dell Inc.", ChassisSerial: "BBB"},
		{SystemVendor: "Apple Inc.", ChassisSerial: "AAA"},
		{SystemVendor: "Dell Inc.", ChassisSerial: "AAA"},
	}
	SortHardwares(in)
	if in[0].SystemVendor != "Apple Inc." {
		t.Fatalf("first=%+v", in[0])
	}
	if in[1].ChassisSerial != "AAA" || in[2].ChassisSerial != "BBB" {
		t.Fatalf("dell ordering wrong: %+v %+v", in[1], in[2])
	}
}
