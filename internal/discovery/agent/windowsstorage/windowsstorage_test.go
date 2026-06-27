package windowsstorage

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

func TestDriveTypeConstants(t *testing.T) {
	pairs := []struct {
		got, want int
	}{
		{DriveTypeUnknown, 0},
		{DriveTypeNoRoot, 1},
		{DriveTypeRemovable, 2},
		{DriveTypeLocal, 3},
		{DriveTypeNetwork, 4},
		{DriveTypeCDROM, 5},
		{DriveTypeRAMDisk, 6},
	}
	for _, p := range pairs {
		if p.got != p.want {
			t.Fatalf("drive-type drift: got %d want %d", p.got, p.want)
		}
	}
}

func TestIsFixedLocalDrive(t *testing.T) {
	if !IsFixedLocalDrive(DriveTypeLocal) {
		t.Fatal("3=local")
	}
	for _, dt := range []int{
		DriveTypeRemovable, DriveTypeNetwork,
		DriveTypeCDROM, DriveTypeRAMDisk, DriveTypeUnknown,
	} {
		if IsFixedLocalDrive(dt) {
			t.Fatalf("%d must NOT flag local", dt)
		}
	}
}

func TestIsRemovableDrive(t *testing.T) {
	if !IsRemovableDrive(DriveTypeRemovable) {
		t.Fatal("2=removable")
	}
	if IsRemovableDrive(DriveTypeLocal) {
		t.Fatal("local is not removable")
	}
}

func TestIsNetworkDrive(t *testing.T) {
	if !IsNetworkDrive(DriveTypeNetwork) {
		t.Fatal("4=network")
	}
	if IsNetworkDrive(DriveTypeLocal) {
		t.Fatal("local is not network")
	}
}

func TestIsBitLockerProtected(t *testing.T) {
	for _, s := range []string{"On", "ON", " on "} {
		if !IsBitLockerProtected(s) {
			t.Fatalf("%q must flag", s)
		}
	}
	for _, s := range []string{"Off", "Unknown", "NotApplicable", ""} {
		if IsBitLockerProtected(s) {
			t.Fatalf("%q must NOT flag", s)
		}
	}
}

func TestAnnotateVolumeUnencryptedFixed(t *testing.T) {
	v := Volume{DriveType: DriveTypeLocal, BitLockerProtectionStatus: "Off"}
	AnnotateVolume(&v)
	if !v.IsUnencryptedFixedDrive {
		t.Fatal("fixed local with BL off must flag")
	}

	v = Volume{DriveType: DriveTypeLocal, BitLockerProtectionStatus: "On"}
	AnnotateVolume(&v)
	if v.IsUnencryptedFixedDrive {
		t.Fatal("BL on must NOT flag")
	}

	v = Volume{DriveType: DriveTypeRemovable, BitLockerProtectionStatus: "Off"}
	AnnotateVolume(&v)
	if v.IsUnencryptedFixedDrive {
		t.Fatal("removable drive must NOT trigger the fixed-drive finding")
	}

	v = Volume{DriveType: DriveTypeNetwork, BitLockerProtectionStatus: ""}
	AnnotateVolume(&v)
	if v.IsUnencryptedFixedDrive {
		t.Fatal("network drive must NOT trigger")
	}
}

// -- ParsePowerShellOutput typical laptop with BitLocker ----------------

func TestParsePowerShellOutputLaptopBitLockerOn(t *testing.T) {
	body := []byte(`{
        "disks": [{
            "device_id": "\\\\.\\PHYSICALDRIVE0",
            "model": "Samsung SSD 990 PRO 1TB",
            "manufacturer": "(Standard disk drives)",
            "interface_type": "SCSI",
            "serial_number": "S6S2NJ0XA00001",
            "firmware_revision": "1B2QJXD7",
            "media_type": "Fixed hard disk media",
            "size_bytes": 1000204886016,
            "partition_count": 4,
            "bus_type": "NVMe",
            "health_status": "Healthy",
            "operational_status": "Online",
            "is_boot": true, "is_system": true,
            "is_offline": false, "is_read_only": false,
            "is_removable": false
        }],
        "volumes": [{
            "device_id": "C:",
            "drive_letter": "C:",
            "label": "OSDisk",
            "file_system": "NTFS",
            "capacity_bytes": 999999997952,
            "free_space_bytes": 421234567890,
            "serial_number": "ABCD1234",
            "drive_type": 3,
            "is_dirty": false,
            "is_boot_volume": true,
            "is_system_volume": true,
            "is_compressed": false,
            "bitlocker_protection_status": "On",
            "bitlocker_encryption_method": "XtsAes256",
            "bitlocker_volume_status": "FullyEncrypted"
        }]
    }`)
	got, err := ParsePowerShellOutput(body)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(got.Disks) != 1 {
		t.Fatalf("disks=%d", len(got.Disks))
	}
	d := got.Disks[0]
	if d.BusType != "NVMe" || d.HealthStatus != "Healthy" {
		t.Fatalf("disk join wrong: %+v", d)
	}
	if d.SizeBytes != 1000204886016 {
		t.Fatalf("size=%d", d.SizeBytes)
	}
	if len(got.Volumes) != 1 {
		t.Fatalf("volumes=%d", len(got.Volumes))
	}
	v := got.Volumes[0]
	if !IsFixedLocalDrive(v.DriveType) {
		t.Fatal("must flag fixed local")
	}
	if !IsBitLockerProtected(v.BitLockerProtectionStatus) {
		t.Fatal("BL on must be detected")
	}
	if v.IsUnencryptedFixedDrive {
		t.Fatal("BL on => not unencrypted")
	}
}

// -- ParsePowerShellOutput unencrypted laptop (CWE-311 finding) ---------

func TestParsePowerShellOutputUnencryptedLaptopFinding(t *testing.T) {
	body := []byte(`{
        "disks": [{
            "device_id": "\\\\.\\PHYSICALDRIVE0",
            "size_bytes": 500107862016,
            "bus_type": "SATA", "health_status": "Healthy",
            "is_boot": true, "is_system": true
        }],
        "volumes": [{
            "device_id": "C:",
            "drive_letter": "C:",
            "file_system": "NTFS",
            "capacity_bytes": 500107862016,
            "free_space_bytes": 100000000000,
            "drive_type": 3,
            "is_boot_volume": true,
            "bitlocker_protection_status": "Off",
            "bitlocker_volume_status": "FullyDecrypted"
        }]
    }`)
	got, err := ParsePowerShellOutput(body)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Volumes[0].IsUnencryptedFixedDrive {
		t.Fatal("fixed drive with BL off must flag IsUnencryptedFixedDrive")
	}
}

// -- ParsePowerShellOutput USB stick attached ----------------------------

func TestParsePowerShellOutputUSBStick(t *testing.T) {
	body := []byte(`{
        "disks": [{
            "device_id": "\\\\.\\PHYSICALDRIVE1",
            "model": "USB FLASH 3.0",
            "interface_type": "USB",
            "size_bytes": 32212254720,
            "media_type": "Removable Media",
            "bus_type": "USB",
            "is_removable": true
        }],
        "volumes": [{
            "device_id": "E:",
            "drive_letter": "E:",
            "label": "USB_STICK",
            "file_system": "exFAT",
            "capacity_bytes": 32212254720,
            "free_space_bytes": 12345678901,
            "drive_type": 2
        }]
    }`)
	got, err := ParsePowerShellOutput(body)
	if err != nil {
		t.Fatal(err)
	}
	d := got.Disks[0]
	if !d.IsRemovable {
		t.Fatal("USB must flag removable")
	}
	v := got.Volumes[0]
	if !IsRemovableDrive(v.DriveType) {
		t.Fatal("drive_type=2 must flag removable")
	}
	if v.IsUnencryptedFixedDrive {
		t.Fatal("USB drive must NOT trigger the fixed-drive finding")
	}
}

// -- ParsePowerShellOutput network drive mounted ------------------------

func TestParsePowerShellOutputNetworkDrive(t *testing.T) {
	body := []byte(`{
        "disks": [],
        "volumes": [{
            "device_id": "Z:",
            "drive_letter": "Z:",
            "label": "\\\\fileserver\\projects",
            "file_system": "NTFS",
            "capacity_bytes": 0,
            "free_space_bytes": 0,
            "drive_type": 4
        }]
    }`)
	got, err := ParsePowerShellOutput(body)
	if err != nil {
		t.Fatal(err)
	}
	v := got.Volumes[0]
	if !IsNetworkDrive(v.DriveType) {
		t.Fatal("drive_type=4 must flag network")
	}
}

// -- ParsePowerShellOutput singleton-object unwrap ----------------------

func TestParsePowerShellOutputSingletonUnwrap(t *testing.T) {
	body := []byte(`{
        "disks": {
            "device_id": "\\\\.\\PHYSICALDRIVE0",
            "model": "Solo Disk",
            "size_bytes": 1000000000
        },
        "volumes": {
            "device_id": "C:",
            "drive_letter": "C:",
            "drive_type": 3,
            "bitlocker_protection_status": "On"
        }
    }`)
	got, err := ParsePowerShellOutput(body)
	if err != nil {
		t.Fatalf("singleton parse: %v", err)
	}
	if len(got.Disks) != 1 || len(got.Volumes) != 1 {
		t.Fatalf("singleton unwrap broken: %+v", got)
	}
}

// -- ParsePowerShellOutput dirty bit + unhealthy disk -------------------

func TestParsePowerShellOutputDirtyAndUnhealthy(t *testing.T) {
	body := []byte(`{
        "disks": [{
            "device_id": "\\\\.\\PHYSICALDRIVE2",
            "health_status": "Unhealthy",
            "operational_status": "Failed"
        }],
        "volumes": [{
            "device_id": "D:",
            "drive_letter": "D:",
            "drive_type": 3,
            "is_dirty": true
        }]
    }`)
	got, err := ParsePowerShellOutput(body)
	if err != nil {
		t.Fatal(err)
	}
	if got.Disks[0].HealthStatus != "Unhealthy" {
		t.Fatalf("health=%q", got.Disks[0].HealthStatus)
	}
	if !got.Volumes[0].IsDirty {
		t.Fatal("dirty bit must propagate")
	}
}

// -- error paths --------------------------------------------------------

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

// -- script shape spot-check --------------------------------------------

func TestPowerShellScriptShape(t *testing.T) {
	for _, must := range []string{
		"Win32_DiskDrive",
		"MSFT_Disk",
		"Win32_LogicalDisk",
		"Win32_Volume",
		"Get-BitLockerVolume",
		"bitlocker_protection_status",
	} {
		if !strings.Contains(PowerShellScript, must) {
			t.Fatalf("PowerShellScript missing %q", must)
		}
	}
}

func TestSortDisksDeterministic(t *testing.T) {
	in := []Disk{
		{DeviceID: "\\\\.\\PHYSICALDRIVE2"},
		{DeviceID: "\\\\.\\PHYSICALDRIVE0"},
		{DeviceID: "\\\\.\\PHYSICALDRIVE1"},
	}
	SortDisks(in)
	if in[0].DeviceID != "\\\\.\\PHYSICALDRIVE0" {
		t.Fatalf("first=%+v", in[0])
	}
	if in[2].DeviceID != "\\\\.\\PHYSICALDRIVE2" {
		t.Fatalf("last=%+v", in[2])
	}
}

func TestSortVolumesDeterministic(t *testing.T) {
	in := []Volume{
		{DriveLetter: "Z:", DeviceID: "Z:"},
		{DriveLetter: "C:", DeviceID: "C:"},
		{DriveLetter: "C:", DeviceID: "Volume{...}"},
	}
	SortVolumes(in)
	if in[0].DriveLetter != "C:" || in[0].DeviceID != "C:" {
		t.Fatalf("first=%+v", in[0])
	}
	if in[2].DriveLetter != "Z:" {
		t.Fatalf("last=%+v", in[2])
	}
}
