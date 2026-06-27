package mounts

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPinnedSourceStrings(t *testing.T) {
	pairs := []struct{ got, want string }{
		{string(SourceFstab), "fstab"},
		{string(SourceProcMounts), "proc-mounts"},
		{string(SourceMacOSMount), "macos-mount"},
		{string(SourceWindowsVolumes), "windows-volumes"},
		{string(SourceUnknown), "unknown"},
	}
	for _, p := range pairs {
		if p.got != p.want {
			t.Fatalf("source drift: got %q want %q", p.got, p.want)
		}
	}
}

func TestEncodeStringList(t *testing.T) {
	if EncodeStringList(nil) != "[]" {
		t.Fatal("nil")
	}
	if got := EncodeStringList([]string{"nodev", "noexec"}); got != `["nodev","noexec"]` {
		t.Fatalf("got %q", got)
	}
}

func TestHashContentsDeterministic(t *testing.T) {
	a := HashContents([]byte("/dev/sda1 / ext4 defaults 0 1\n"))
	b := HashContents([]byte("/dev/sda1 / ext4 defaults 0 1\n"))
	if a != b || len(a) != 64 {
		t.Fatalf("a=%q b=%q", a, b)
	}
}

func TestIsCriticalMountpoint(t *testing.T) {
	for _, p := range []string{
		"/tmp", "/var/tmp", "/home", "/dev/shm",
		"/var/log", "/var/log/audit", "/boot", "/var",
	} {
		if !IsCriticalMountpoint(p) {
			t.Fatalf("%q must be critical", p)
		}
	}
	for _, p := range []string{"/", "/etc", "/usr", "/foo", ""} {
		if IsCriticalMountpoint(p) {
			t.Fatalf("%q must NOT be critical", p)
		}
	}
}

func TestMeetsRecommendedOptions(t *testing.T) {
	// /tmp requires nodev+nosuid+noexec.
	met, ok := MeetsRecommendedOptions("/tmp",
		[]string{"defaults", "nodev", "nosuid", "noexec"})
	if !ok {
		t.Fatal("/tmp must be in critical set")
	}
	if !met {
		t.Fatal("all three options present → met")
	}

	met, ok = MeetsRecommendedOptions("/tmp",
		[]string{"defaults", "nodev"})
	if !ok {
		t.Fatal("/tmp must be in critical set")
	}
	if met {
		t.Fatal("nodev alone must NOT meet requirement")
	}

	// Non-critical mount: ok=false, met=false.
	met, ok = MeetsRecommendedOptions("/", []string{"defaults"})
	if ok {
		t.Fatal("/ must NOT be in critical set")
	}
	if met {
		t.Fatal("met must be false when not critical")
	}
}

func TestIsRemoteFSType(t *testing.T) {
	for _, f := range []string{
		"nfs", "nfs4", "cifs", "sshfs",
		"fuse.sshfs", "smb", "9p", "ceph",
	} {
		if !IsRemoteFSType(f) {
			t.Fatalf("%q must flag remote", f)
		}
	}
	for _, f := range []string{"ext4", "xfs", "btrfs", "tmpfs", "proc"} {
		if IsRemoteFSType(f) {
			t.Fatalf("%q must NOT flag remote", f)
		}
	}
}

func TestLooksEncryptedDevice(t *testing.T) {
	for _, d := range []string{
		"/dev/mapper/cryptroot",
		"/dev/mapper/luks-7f3b...",
		"/dev/dm-1",
	} {
		if !LooksEncryptedDevice(d) {
			t.Fatalf("%q must flag encrypted", d)
		}
	}
	for _, d := range []string{
		"/dev/sda1",
		"tmpfs",
		"",
		"UUID=12345",
	} {
		if LooksEncryptedDevice(d) {
			t.Fatalf("%q must NOT flag encrypted", d)
		}
	}
}

func TestIsRemovableMountpoint(t *testing.T) {
	for _, p := range []string{
		"/media/alice/USB", "/run/media/bob/SD",
		"/mnt/usb-stick",
	} {
		if !IsRemovableMountpoint(p) {
			t.Fatalf("%q must flag removable", p)
		}
	}
	for _, p := range []string{"/", "/home", "/tmp", "/mnt/data"} {
		if IsRemovableMountpoint(p) {
			t.Fatalf("%q must NOT flag removable", p)
		}
	}
}

func TestAnnotateSecurityCriticalMissingOpts(t *testing.T) {
	// /tmp without recommended options → finding.
	m := Mount{
		Source:     SourceFstab,
		Device:     "tmpfs",
		Mountpoint: "/tmp",
		FSType:     "tmpfs",
		Options:    []string{"defaults", "nosuid"},
	}
	AnnotateSecurity(&m)
	if !m.IsCriticalPath {
		t.Fatal("/tmp must be critical")
	}
	if !m.HasNosuid {
		t.Fatal("nosuid must be flagged present")
	}
	if m.HasNoexec || m.HasNodev {
		t.Fatal("noexec/nodev not in options; must NOT be flagged")
	}
	if m.HasRecommendedOptions {
		t.Fatal("missing noexec+nodev → must NOT meet recommended")
	}
}

func TestAnnotateSecurityCriticalMeetsOpts(t *testing.T) {
	m := Mount{
		Mountpoint: "/var/tmp",
		FSType:     "ext4",
		Options:    []string{"nodev", "nosuid", "noexec"},
	}
	AnnotateSecurity(&m)
	if !m.HasRecommendedOptions {
		t.Fatalf("all options present, must meet: %+v", m)
	}
}

func TestAnnotateSecurityRemoteAndRemovable(t *testing.T) {
	m := Mount{
		Mountpoint: "/mnt/nas", FSType: "nfs4",
		Device: "nfs-server:/share",
	}
	AnnotateSecurity(&m)
	if !m.IsRemote {
		t.Fatal("nfs4 must flag remote")
	}

	m = Mount{
		Mountpoint: "/media/usb", FSType: "vfat",
		Device: "/dev/sdc1",
	}
	AnnotateSecurity(&m)
	if !m.IsRemovable {
		t.Fatal("/media/* must flag removable")
	}
}

func TestAnnotateSecurityEncrypted(t *testing.T) {
	m := Mount{
		Mountpoint: "/", FSType: "ext4",
		Device: "/dev/mapper/cryptroot",
	}
	AnnotateSecurity(&m)
	if !m.IsEncrypted {
		t.Fatal("LUKS device must flag encrypted")
	}
}

// -- ParseFstab ---------------------------------------------------------

func TestParseFstabTypical(t *testing.T) {
	body := []byte(`# /etc/fstab: static file system information.
UUID=root-uuid / ext4 errors=remount-ro 0 1
UUID=boot-uuid /boot ext4 nodev,nosuid 0 2
tmpfs /tmp tmpfs defaults,nodev,nosuid,noexec 0 0
tmpfs /var/tmp tmpfs defaults,nodev 0 0
nfs-server:/share /mnt/nas nfs4 defaults 0 0
/dev/mapper/cryptdata /data ext4 defaults 0 2
`)
	got := ParseFstab(body, "/etc/fstab")
	if len(got) != 6 {
		t.Fatalf("len=%d, want 6: %+v", len(got), got)
	}

	byMP := map[string]Mount{}
	for _, m := range got {
		byMP[m.Mountpoint] = m
	}

	if !byMP["/tmp"].HasRecommendedOptions {
		t.Fatalf("/tmp meets all recommended; should flag has_recommended_options: %+v",
			byMP["/tmp"])
	}
	if byMP["/var/tmp"].HasRecommendedOptions {
		t.Fatal("/var/tmp only has nodev; must NOT flag has_recommended_options")
	}
	if !byMP["/mnt/nas"].IsRemote {
		t.Fatal("nfs4 mount must flag remote")
	}
	if !byMP["/data"].IsEncrypted {
		t.Fatal("dm-mapper cryptdata must flag encrypted")
	}
	if byMP["/boot"].FsckPass != 2 {
		t.Fatalf("/boot fsck_pass=%d", byMP["/boot"].FsckPass)
	}
	for _, m := range got {
		if m.FileHash == "" {
			t.Fatalf("file_hash missing on %+v", m)
		}
	}
}

func TestParseFstabSkipsCommentsAndBlanks(t *testing.T) {
	body := []byte("# comment\n\n# more\n")
	got := ParseFstab(body, "x")
	if len(got) != 0 {
		t.Fatalf("got %d, want 0: %+v", len(got), got)
	}
}

// -- ParseProcMounts ----------------------------------------------------

func TestParseProcMountsLegacyFormat(t *testing.T) {
	body := []byte(`tmpfs /tmp tmpfs rw,nodev,nosuid,noexec 0 0
/dev/sda1 / ext4 rw,relatime 0 0
nfs-server:/share /mnt/nas nfs4 rw,vers=4 0 0
`)
	got := ParseProcMounts(body, "/proc/mounts")
	if len(got) != 3 {
		t.Fatalf("len=%d", len(got))
	}
	for _, m := range got {
		if m.Source != SourceProcMounts {
			t.Fatalf("source=%q", m.Source)
		}
	}
}

func TestParseProcMountsMountinfoFormat(t *testing.T) {
	body := []byte(`25 0 8:1 / / rw,relatime shared:1 - ext4 /dev/sda1 rw,errors=remount-ro
30 25 0:21 / /tmp rw,nosuid,nodev,noexec shared:11 - tmpfs tmpfs rw,size=1638400k
`)
	got := ParseProcMounts(body, "/proc/self/mountinfo")
	if len(got) != 2 {
		t.Fatalf("len=%d: %+v", len(got), got)
	}
	var tmpMount Mount
	for _, m := range got {
		if m.Mountpoint == "/tmp" {
			tmpMount = m
		}
	}
	if tmpMount.FSType != "tmpfs" {
		t.Fatalf("/tmp fstype=%q", tmpMount.FSType)
	}
	if !tmpMount.HasRecommendedOptions {
		t.Fatalf("/tmp options=%v should meet CIS", tmpMount.Options)
	}
}

func TestParseProcMountsOctalUnescape(t *testing.T) {
	// "Space\ Path" → "Space Path"
	body := []byte("/dev/sda1 /mnt/Space\\040Path ext4 rw 0 0\n")
	got := ParseProcMounts(body, "/proc/mounts")
	if len(got) != 1 {
		t.Fatalf("len=%d", len(got))
	}
	if got[0].Mountpoint != "/mnt/Space Path" {
		t.Fatalf("mountpoint=%q (octal unescape broken)", got[0].Mountpoint)
	}
}

func TestParseProcMountsMaxCeiling(t *testing.T) {
	var sb strings.Builder
	for i := 0; i < MaxMounts+50; i++ {
		sb.WriteString("tmpfs /tmp tmpfs rw 0 0\n")
	}
	got := ParseProcMounts([]byte(sb.String()), "/proc/mounts")
	if len(got) > MaxMounts {
		t.Fatalf("got %d > MaxMounts %d", len(got), MaxMounts)
	}
}

// -- collector end-to-end -----------------------------------------------

func TestFileCollectorWalksFstabAndProcMounts(t *testing.T) {
	tmp := t.TempDir()
	fstab := filepath.Join(tmp, "fstab")
	mountinfo := filepath.Join(tmp, "mountinfo")
	mustWrite(t, fstab, "tmpfs /tmp tmpfs defaults,nodev,nosuid,noexec 0 0\n")
	mustWrite(t, mountinfo,
		`25 0 8:1 / / rw,relatime shared:1 - ext4 /dev/sda1 rw
30 25 0:21 / /tmp rw,nosuid,nodev,noexec shared:11 - tmpfs tmpfs rw
`)
	c := &fileCollector{
		fstab:         fstab,
		procMountinfo: mountinfo,
		procMounts:    "/nope",
		readFile:      os.ReadFile,
	}
	got, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	// 1 fstab + 2 mountinfo = 3.
	if len(got) != 3 {
		t.Fatalf("want 3, got %d: %+v", len(got), got)
	}
}

func TestFileCollectorFallsBackToProcMounts(t *testing.T) {
	tmp := t.TempDir()
	procMounts := filepath.Join(tmp, "mounts")
	mustWrite(t, procMounts, "tmpfs /tmp tmpfs rw,nodev,nosuid,noexec 0 0\n")

	c := &fileCollector{
		fstab:         "/nope",
		procMountinfo: "/nope-mountinfo",
		procMounts:    procMounts,
		readFile: func(p string) ([]byte, error) {
			if p == procMounts {
				return os.ReadFile(p)
			}
			return nil, errors.New("missing")
		},
	}
	got, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("want 1 (fallback used), got %d", len(got))
	}
}

func TestFileCollectorMissingPathsOK(t *testing.T) {
	c := &fileCollector{
		fstab:         "/nope",
		procMountinfo: "/nope",
		procMounts:    "/nope",
		readFile:      os.ReadFile,
	}
	got, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("missing must not error: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("want empty, got %d", len(got))
	}
}

func TestSortMountsDeterministic(t *testing.T) {
	in := []Mount{
		{Source: SourceProcMounts, Mountpoint: "/zz"},
		{Source: SourceFstab, Mountpoint: "/aa"},
		{Source: SourceFstab, Mountpoint: "/zz"},
	}
	SortMounts(in)
	if in[0].Source != SourceFstab || in[0].Mountpoint != "/aa" {
		t.Fatalf("first=%+v", in[0])
	}
	if in[2].Source != SourceProcMounts {
		t.Fatalf("last=%+v", in[2])
	}
}

// -- helpers ------------------------------------------------------------

func mustWrite(t *testing.T, p, body string) {
	t.Helper()
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}
