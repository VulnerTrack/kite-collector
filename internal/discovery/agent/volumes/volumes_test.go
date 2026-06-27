package volumes

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestIsRemovableMount(t *testing.T) {
	cases := map[string]bool{
		"/":                     false,
		"/home":                 false,
		"/media/usb0":           true,
		"/run/media/user/STICK": true,
		"/mnt/usb1":             true,
		"/Volumes/External":     true,
		"/Volumes/Macintosh HD": false,
		"C:":                    false,
		`C:\`:                   false,
		"D:":                    true,
		`E:\`:                   true,
		"Z:":                    true,
	}
	for in, want := range cases {
		if got := IsRemovableMount(in); got != want {
			t.Fatalf("IsRemovableMount(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestIsBootable(t *testing.T) {
	cases := []struct {
		mp, fs string
		want   bool
	}{
		{"/", "ext4", true},
		{"/boot", "ext4", true},
		{"/boot/efi", "vfat", true},
		{"/home", "ext4", false},
		{`C:\`, "NTFS", true},
		{`D:\`, "NTFS", false},
		{"/System/Volumes/Data", "apfs", true},
		{"/Volumes/External", "exfat", false},
	}
	for _, tc := range cases {
		if got := IsBootable(tc.mp, tc.fs); got != tc.want {
			t.Fatalf("IsBootable(%q,%q) = %v, want %v", tc.mp, tc.fs, got, tc.want)
		}
	}
}

func TestSortVolumesLexical(t *testing.T) {
	in := []Volume{
		{MountPoint: "/var"},
		{MountPoint: "/"},
		{MountPoint: "/boot"},
		{MountPoint: "/home"},
	}
	SortVolumes(in)
	want := []string{"/", "/boot", "/home", "/var"}
	for i, v := range in {
		if v.MountPoint != want[i] {
			t.Fatalf("pos %d: %q want %q", i, v.MountPoint, want[i])
		}
	}
}

func TestPinnedEnumStrings(t *testing.T) {
	pairs := []struct{ got, want string }{
		{string(EncNone), "none"},
		{string(EncLUKS), "luks"},
		{string(EncLUKS2), "luks2"},
		{string(EncBitLocker), "bitlocker"},
		{string(EncFileVault2), "filevault2"},
		{string(EncAPFSEncrypted), "apfs-encrypted"},
		{string(EncUnknown), "unknown"},
		{string(EncStateLocked), "locked"},
		{string(EncStateUnlocked), "unlocked"},
		{string(EncStateUnknown), "unknown"},
	}
	for _, p := range pairs {
		if p.got != p.want {
			t.Fatalf("enum drift: got %q want %q (would break SQLite CHECK)",
				p.got, p.want)
		}
	}
}

func TestCollectMergesUsageAndProbe(t *testing.T) {
	src := &fakeSource{
		parts: []Partition{
			{Device: "/dev/nvme0n1p2", MountPoint: "/", Filesystem: "ext4", Opts: []string{"rw", "relatime"}},
			{Device: "/dev/nvme0n1p1", MountPoint: "/boot/efi", Filesystem: "vfat", Opts: []string{"ro"}},
			{Device: "/dev/sdb1", MountPoint: "/media/usb0", Filesystem: "exfat", Opts: []string{"rw"}},
		},
		usage: map[string]Usage{
			"/":           {Total: 500_000_000_000, Used: 100_000_000_000, InodesTotal: 30_000_000, InodesUsed: 1_000_000},
			"/boot/efi":   {Total: 500_000_000, Used: 50_000_000},
			"/media/usb0": {Total: 64_000_000_000, Used: 32_000_000_000},
		},
	}
	c := &gopsutilCollector{
		src: src,
		probe: stubProbe{
			byMount: map[string]struct {
				enc   Encryption
				state EncryptionState
			}{
				"/": {EncLUKS2, EncStateUnlocked},
			},
		},
	}
	got, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("want 3 volumes, got %d", len(got))
	}
	// Sorted lexically by mount point: /, /boot/efi, /media/usb0
	if got[0].MountPoint != "/" {
		t.Fatalf("first volume mount = %q", got[0].MountPoint)
	}

	root := got[0]
	if root.Encryption != EncLUKS2 || root.EncryptionState != EncStateUnlocked {
		t.Fatalf("/ encryption probe lost: %q / %q",
			root.Encryption, root.EncryptionState)
	}
	if !root.Bootable {
		t.Fatalf("/ should be bootable")
	}
	if root.ReadOnly {
		t.Fatalf("/ should not be read-only (opts=%q)", root.MountOpts)
	}
	if root.SizeBytes != 500_000_000_000 || root.UsedBytes != 100_000_000_000 {
		t.Fatalf("/ usage merge lost: size=%d used=%d", root.SizeBytes, root.UsedBytes)
	}
	if root.InodesTotal != 30_000_000 {
		t.Fatalf("/ inodes lost: %d", root.InodesTotal)
	}

	efi := got[1]
	if efi.MountPoint != "/boot/efi" {
		t.Fatalf("second mount = %q", efi.MountPoint)
	}
	if !efi.ReadOnly {
		t.Fatalf("/boot/efi should be read-only (opts=%q)", efi.MountOpts)
	}
	if !efi.Bootable {
		t.Fatalf("/boot/efi should be bootable")
	}
	if efi.Encryption != EncUnknown {
		t.Fatalf("/boot/efi has no probe → encryption=%q, want unknown", efi.Encryption)
	}

	usb := got[2]
	if !usb.Removable {
		t.Fatalf("/media/usb0 should be removable")
	}
	if usb.Bootable {
		t.Fatalf("/media/usb0 should not be bootable")
	}
}

func TestCollectCapsAtMaxVolumes(t *testing.T) {
	src := &fakeSource{parts: make([]Partition, MaxVolumes+5)}
	for i := range src.parts {
		src.parts[i] = Partition{
			Device:     "/dev/synthetic",
			MountPoint: "/synth" + itoa(i),
			Filesystem: "tmpfs",
		}
	}
	c := &gopsutilCollector{src: src, probe: noopProbe{}}
	got, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(got) != MaxVolumes {
		t.Fatalf("want %d volumes (cap), got %d", MaxVolumes, len(got))
	}
}

func TestCollectPropagatesPartitionsError(t *testing.T) {
	src := &fakeSource{partErr: errors.New("boom")}
	c := &gopsutilCollector{src: src, probe: noopProbe{}}
	_, err := c.Collect(context.Background())
	if err == nil {
		t.Fatalf("expected error from partitions, got nil")
	}
}

func TestCollectStampsTimestamps(t *testing.T) {
	src := &fakeSource{
		parts: []Partition{{Device: "/dev/sda1", MountPoint: "/", Filesystem: "ext4"}},
		usage: map[string]Usage{"/": {Total: 1, Used: 0}},
	}
	c := &gopsutilCollector{src: src, probe: noopProbe{}}
	before := time.Now().UTC()
	got, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	after := time.Now().UTC()
	if got[0].LastSeenAt.Before(before) || got[0].LastSeenAt.After(after) {
		t.Fatalf("last_seen_at out of window: %v", got[0].LastSeenAt)
	}
	if got[0].CollectedAt.Before(before) || got[0].CollectedAt.After(after) {
		t.Fatalf("collected_at out of window: %v", got[0].CollectedAt)
	}
}

func TestNoopProbeAlwaysUnknown(t *testing.T) {
	enc, state := noopProbe{}.Probe(context.Background(), "/", "/dev/sda1", "ext4")
	if enc != EncUnknown || state != EncStateUnknown {
		t.Fatalf("noopProbe returned (%q,%q), want (unknown,unknown)", enc, state)
	}
}

// -- fakes ------------------------------------------------------------------

type fakeSource struct {
	usage    map[string]Usage
	partErr  error
	usageErr error
	parts    []Partition
}

func (f *fakeSource) Partitions(_ context.Context, _ bool) ([]Partition, error) {
	if f.partErr != nil {
		return nil, f.partErr
	}
	return f.parts, nil
}

func (f *fakeSource) Usage(_ context.Context, mount string) (Usage, error) {
	if f.usageErr != nil {
		return Usage{}, f.usageErr
	}
	u, ok := f.usage[mount]
	if !ok {
		return Usage{}, errors.New("no usage")
	}
	return u, nil
}

type stubProbe struct {
	byMount map[string]struct {
		enc   Encryption
		state EncryptionState
	}
}

func (s stubProbe) Probe(_ context.Context, mp, _, _ string) (Encryption, EncryptionState) {
	if v, ok := s.byMount[mp]; ok {
		return v.enc, v.state
	}
	return EncUnknown, EncStateUnknown
}

// itoa avoids importing strconv just for the fork-bomb fixture.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [11]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}
