package driver

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vulnertrack/kite-collector/internal/discovery/agent/software"
)

// newFixtureProcModules assembles a ProcModules whose kernel interfaces all
// point at files under a temp dir: a /proc/modules fixture, a taint value,
// and a module tree holding one real (synthetic) .ko file.
func newFixtureProcModules(t *testing.T, procContent, taintContent string) (*ProcModules, string) {
	t.Helper()
	dir := t.TempDir()

	procPath := filepath.Join(dir, "modules")
	require.NoError(t, os.WriteFile(procPath, []byte(procContent), 0o644)) //#nosec G306 -- fixture

	taintPath := filepath.Join(dir, "tainted")
	if taintContent != "" {
		require.NoError(t, os.WriteFile(taintPath, []byte(taintContent), 0o644)) //#nosec G306 -- fixture
	}

	modulesDir := filepath.Join(dir, "lib-modules")
	require.NoError(t, os.MkdirAll(filepath.Join(modulesDir, "kernel"), 0o755))

	p := NewProcModules()
	p.procPath = procPath
	p.taintPath = taintPath
	p.modulesDir = modulesDir
	return p, modulesDir
}

func TestProcModulesCollect_FullEnrichment(t *testing.T) {
	t.Parallel()

	proc := "snd-fake 16384 2 snd_timer,snd, Live 0xffffffffc0000000\n" +
		"orphan_mod 8192 0 - Live 0xffffffffc0100000\n"
	// Taint 12288 = bit 12 (O, out-of-tree) + bit 13 (E, unsigned module).
	p, modulesDir := newFixtureProcModules(t, proc, "12288\n")

	// The module appears as "snd-fake" in /proc but is stored with an
	// underscore on disk — the resolver must bridge the spelling.
	elfBytes := buildModuleELF(t, fakeModinfoBlob, true)
	koPath := filepath.Join(modulesDir, "kernel", "snd_fake.ko")
	require.NoError(t, os.WriteFile(koPath, elfBytes, 0o644)) //#nosec G306 -- fixture
	wantHash := sha256.Sum256(elfBytes)

	collected := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	p.now = func() time.Time { return collected }

	res, err := p.Collect(context.Background())
	require.NoError(t, err)
	require.Empty(t, res.Errs)
	require.Len(t, res.Drivers, 2)

	snd := findByName(res.Drivers, "snd-fake")
	require.NotNil(t, snd)
	assert.Equal(t, koPath, snd.Path)
	assert.Equal(t, "1.2.3", snd.Version, "version must come from .modinfo")
	assert.Equal(t, "Fake sound driver", snd.Description,
		"modinfo description must replace the refcount placeholder")
	assert.Equal(t, "Acme Corp Kernel Signing Key", snd.Signer)
	assert.Equal(t, "Acme Corp Kernel Signing Key", snd.Vendor)
	assert.Equal(t, "sha512", snd.SignatureAlgo)
	assert.Equal(t, []string{"snd_timer", "snd"}, snd.Dependencies,
		"/proc used_by wins over modinfo depends")
	assert.Equal(t, hex.EncodeToString(wantHash[:]), snd.OnDiskSHA256)
	assert.Equal(t, SignatureValid, snd.SignatureState,
		"a signed module stays valid even with the E taint set")
	assert.Equal(t, []string{"E", "O"}, snd.TaintFlags)
	assert.Equal(t, collected, snd.CollectedAt)
	assert.Equal(t, runtime.GOARCH, snd.Architecture)
	assert.Equal(t, FrameworkLinuxModule, snd.DriverFramework)
	assert.Equal(t,
		software.BuildCPE23WithTargetSW(snd.Vendor, "snd-fake", "1.2.3", "linux"),
		snd.CPE23)

	orphan := findByName(res.Drivers, "orphan_mod")
	require.NotNil(t, orphan)
	assert.Empty(t, orphan.Path, "unresolvable modules carry no path")
	assert.Empty(t, orphan.OnDiskSHA256)
	assert.Equal(t, SignatureUnsigned, orphan.SignatureState,
		"unsigned module + E taint = unsigned verdict")
	assert.Equal(t, "loaded kernel module (refcount=0)", orphan.Description)
	assert.Empty(t, orphan.Dependencies)
}

func TestProcModulesCollect_NoTaintFile(t *testing.T) {
	t.Parallel()

	p, _ := newFixtureProcModules(t, "dm_mod 188416 1 dm_mirror, Live 0x0\n", "")

	res, err := p.Collect(context.Background())
	require.NoError(t, err)
	require.Len(t, res.Drivers, 1)
	assert.Empty(t, res.Drivers[0].TaintFlags)
	assert.Equal(t, SignatureUnknown, res.Drivers[0].SignatureState,
		"no signer and no E taint must degrade to unknown, not unsigned")
}

func TestProcModulesCollect_MissingProcFileErrors(t *testing.T) {
	t.Parallel()

	p := NewProcModules()
	p.procPath = filepath.Join(t.TempDir(), "no-proc-modules")

	res, err := p.Collect(context.Background())
	require.Error(t, err)
	assert.Nil(t, res)
	assert.Contains(t, err.Error(), "read "+p.procPath)
}

func TestResolveModulePath_SpellingVariants(t *testing.T) {
	t.Parallel()

	p, modulesDir := newFixtureProcModules(t, "", "")
	ko := filepath.Join(modulesDir, "kernel", "snd-fake.ko")
	require.NoError(t, os.WriteFile(ko, []byte("x"), 0o644)) //#nosec G306 -- fixture

	assert.Equal(t, ko, p.resolveModulePath("snd-fake"), "exact name must resolve")
	assert.Equal(t, ko, p.resolveModulePath("snd_fake"),
		"underscore spelling must resolve to the hyphenated file")
	assert.Empty(t, p.resolveModulePath("absent_module"))
}

func TestResolveModulePath_CompressedExtensions(t *testing.T) {
	t.Parallel()

	p, modulesDir := newFixtureProcModules(t, "", "")
	ko := filepath.Join(modulesDir, "kernel", "zram.ko.zst")
	require.NoError(t, os.WriteFile(ko, []byte("x"), 0o644)) //#nosec G306 -- fixture

	assert.Equal(t, ko, p.resolveModulePath("zram"),
		"compressed module files must be resolvable too")
}

func TestResolveModulePath_DefaultRootBestEffort(t *testing.T) {
	t.Parallel()

	p := NewProcModules() // modulesDir empty: falls back to /lib/modules/<uname -r>
	assert.Empty(t, p.resolveModulePath("kite-test-nonexistent-module-xyzzy"),
		"an impossible module name must never resolve, even against the real tree")
}

func TestUname_MatchesOSRelease(t *testing.T) {
	t.Parallel()

	raw, err := os.ReadFile("/proc/sys/kernel/osrelease")
	if err != nil {
		assert.Empty(t, uname(), "without procfs the release must be empty")
		return
	}
	assert.Equal(t, strings.TrimSpace(string(raw)), uname())
}

func TestReadFileOrEmpty(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "value")
	require.NoError(t, os.WriteFile(path, []byte("12288\n"), 0o644)) //#nosec G306 -- fixture
	assert.Equal(t, "12288\n", readFileOrEmpty(path))
	assert.Equal(t, "", readFileOrEmpty(filepath.Join(t.TempDir(), "missing")))
}

func TestSha256OfFile(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "blob")
	require.NoError(t, os.WriteFile(path, []byte("driver bytes"), 0o644)) //#nosec G306 -- fixture

	got, err := sha256OfFile(path)
	require.NoError(t, err)
	want := sha256.Sum256([]byte("driver bytes"))
	assert.Equal(t, hex.EncodeToString(want[:]), got)

	_, err = sha256OfFile(filepath.Join(t.TempDir(), "missing"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "open")
}

func TestProcModules_AvailableWithReadableFixture(t *testing.T) {
	t.Parallel()

	p, _ := newFixtureProcModules(t, "dm_mod 1 0 - Live 0x0\n", "")
	assert.Equal(t, runtime.GOOS == "linux", p.Available(),
		"a readable modules file makes the collector available on Linux only")
}
