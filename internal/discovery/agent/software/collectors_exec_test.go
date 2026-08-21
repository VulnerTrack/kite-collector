package software

// Exec-wrapper coverage for every package-manager collector: Available()
// PATH probing plus the Collect() runWithLimits pipeline, driven by fake
// tool binaries dropped on PATH via fakeToolOnPath (exec_stderr_test.go).
// Parser internals are covered by the per-collector Parse* tests; here each
// fake echoes one minimal valid fixture cribbed from those tests so the
// wrapper's success, non-zero-exit, and benign-exit paths are exercised
// end to end without touching the network or the host's real tools.
//
// Deliberately not in the table:
//   - brew and cocoapods Collect: covered by brew_root_test.go and
//     cocoapods_test.go root-refusal tests (only Available is probed here).
//   - swiftpm: Available requires a Package.swift manifest; covered by
//     swiftpm_manifest_test.go.
//   - npmscan: filesystem scanner with its own tests (npmscan_test.go).
//   - windows-registry: Available is GOOS-gated, not a PATH probe; the
//     non-Windows stub path is tested separately below.
//   - windows-os: Available is GOOS-gated; Collect is tested separately
//     below through a fake powershell.exe.

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// wantItem is the exact inventory tuple a Collect success case must yield.
type wantItem struct {
	name    string
	vendor  string
	version string
	arch    string
}

// collectorExecCases drives the Available and Collect table tests. The
// script is the fake tool's /bin/sh body; it ignores its arguments and
// emits a fixture in the exact shape the collector's parser documents.
// tolerant marks collectors that treat a non-zero exit with empty stdout
// as a benign "nothing installed here" condition instead of an error.
var collectorExecCases = []struct {
	binary   string
	mk       func() Collector
	script   string
	want     []wantItem
	tolerant bool
}{
	{
		binary: "apk",
		mk:     func() Collector { return NewAPK() },
		script: `cat <<'EOF'
musl-1.2.4-r2 x86_64 {musl} (MIT) [installed]
EOF
`,
		want: []wantItem{{name: "musl", vendor: "musl", version: "1.2.4-r2", arch: "x86_64"}},
	},
	{
		binary: "bun",
		mk:     func() Collector { return NewBun() },
		script: `cat <<'EOF'
/home/agent/.bun/install/global node_modules (1)
└── prettier@3.0.0
EOF
`,
		want: []wantItem{{name: "prettier", version: "3.0.0"}},
	},
	{
		binary: "ghc-pkg",
		mk:     func() Collector { return NewCabal() },
		script: `cat <<'EOF'
base-4.18.1.0 text-2.0.2
EOF
`,
		want: []wantItem{
			{name: "base", version: "4.18.1.0"},
			{name: "text", version: "2.0.2"},
		},
	},
	{
		binary: "cargo",
		mk:     func() Collector { return NewCargo() },
		script: `cat <<'EOF'
ripgrep v14.1.0:
    rg
EOF
`,
		want: []wantItem{{name: "ripgrep", version: "14.1.0"}},
	},
	{
		binary: "choco",
		mk:     func() Collector { return NewChocolatey() },
		script: `cat <<'EOF'
Chocolatey v1.4.0
git 2.42.0
1 packages installed.
EOF
`,
		want: []wantItem{{name: "git", version: "2.42.0"}},
	},
	{
		binary: "composer",
		mk:     func() Collector { return NewComposer() },
		script: `cat <<'EOF'
{"installed":[{"name":"monolog/monolog","version":"v3.5.0"}]}
EOF
`,
		want:     []wantItem{{name: "monolog", vendor: "monolog", version: "3.5.0"}},
		tolerant: true,
	},
	{
		binary: "conan",
		mk:     func() Collector { return NewConan() },
		script: `cat <<'EOF'
Local Cache
  zlib
    zlib/1.3.1
EOF
`,
		want: []wantItem{{name: "zlib", version: "1.3.1"}},
	},
	{
		binary: "conda",
		mk:     func() Collector { return NewConda() },
		script: `cat <<'EOF'
[{"name":"numpy","version":"1.26.4","channel":"defaults"}]
EOF
`,
		want: []wantItem{{name: "numpy", version: "1.26.4"}},
	},
	{
		binary: "cpan",
		mk:     func() Collector { return NewCPAN() },
		script: `printf 'JSON::PP\t4.16\n'
`,
		want: []wantItem{{name: "JSON::PP", version: "4.16"}},
	},
	{
		binary: "Rscript",
		mk:     func() Collector { return NewCRAN() },
		script: `cat <<'EOF'
"","Package","Version"
"jsonlite","jsonlite","1.8.8"
EOF
`,
		want: []wantItem{{name: "jsonlite", version: "1.8.8"}},
	},
	{
		binary: "dnf",
		mk:     func() Collector { return NewDnf() },
		script: `cat <<'EOF'
bash.x86_64 5.2.21-1.fc39 @updates
EOF
`,
		want: []wantItem{{name: "bash", version: "5.2.21-1.fc39", arch: "x86_64"}},
	},
	{
		binary: "dpkg-query",
		mk:     func() Collector { return NewDpkg() },
		script: `printf 'curl\t8.5.0\tamd64\n'
`,
		want: []wantItem{{name: "curl", version: "8.5.0", arch: "amd64"}},
	},
	{
		binary: "flatpak",
		mk:     func() Collector { return NewFlatpak() },
		script: `printf 'org.mozilla.firefox\t121.0\tflathub\n'
`,
		want: []wantItem{{name: "firefox", vendor: "mozilla", version: "121.0"}},
	},
	{
		binary: "pkg",
		mk:     func() Collector { return NewFreeBSDPkg() },
		script: `cat <<'EOF'
curl-8.5.0 Command line tool for transferring data
EOF
`,
		want: []wantItem{{name: "curl", version: "8.5.0"}},
	},
	{
		binary: "gem",
		mk:     func() Collector { return NewGem() },
		script: `cat <<'EOF'
*** LOCAL GEMS ***

rake (13.1.0)
EOF
`,
		want: []wantItem{{name: "rake", version: "13.1.0"}},
	},
	{
		binary: "go",
		mk:     func() Collector { return NewGoMod() },
		script: `cat <<'EOF'
{"Path":"github.com/stretchr/testify","Version":"v1.9.0","Main":false}
EOF
`,
		want:     []wantItem{{name: "testify", vendor: "stretchr", version: "1.9.0"}},
		tolerant: true,
	},
	{
		binary: "guix",
		mk:     func() Collector { return NewGuix() },
		script: `printf 'hello\t2.12.1\tout\t/gnu/store/abc-hello-2.12.1\n'
`,
		want: []wantItem{{name: "hello", version: "2.12.1"}},
	},
	{
		binary: "mix",
		mk:     func() Collector { return NewHex() },
		script: `cat <<'EOF'
* jason 1.4.1 (Hex package) (mix)
  locked at 1.4.1
EOF
`,
		want: []wantItem{{name: "jason", version: "1.4.1"}},
	},
	{
		binary: "julia",
		mk:     func() Collector { return NewJuliaPkg() },
		script: `cat <<'EOF'
JSON 0.21.4
EOF
`,
		want: []wantItem{{name: "JSON", version: "0.21.4"}},
	},
	{
		binary: "luarocks",
		mk:     func() Collector { return NewLuaRocks() },
		script: `printf 'luasocket\t3.1.0-1\tinstalled\t/usr/lib/luarocks/rocks\n'
`,
		want: []wantItem{{name: "luasocket", version: "3.1.0-1"}},
	},
	{
		binary: "port",
		mk:     func() Collector { return NewMacPorts() },
		script: `cat <<'EOF'
The following ports are currently installed:
  curl @8.5.0_0+ssl (active)
EOF
`,
		want: []wantItem{{name: "curl", vendor: "macports", version: "8.5.0"}},
	},
	{
		binary: "mamba",
		mk:     func() Collector { return NewMamba() },
		script: `cat <<'EOF'
[{"name":"numpy","version":"1.26.4","channel":"conda-forge"}]
EOF
`,
		want: []wantItem{{name: "numpy", version: "1.26.4"}},
	},
	{
		binary: "mvn",
		mk:     func() Collector { return NewMaven() },
		script: `cat <<'EOF'
The following files have been resolved:
   org.apache.commons:commons-lang3:jar:3.14.0:compile
EOF
`,
		want: []wantItem{{name: "commons-lang3", vendor: "org.apache.commons", version: "3.14.0"}},
	},
	{
		binary: "nix-env",
		mk:     func() Collector { return NewNix() },
		script: `cat <<'EOF'
hello-2.12.1
EOF
`,
		want: []wantItem{{name: "hello", version: "2.12.1"}},
	},
	{
		binary: "npm",
		mk:     func() Collector { return NewNpm() },
		script: `cat <<'EOF'
{"dependencies":{"prettier":{"version":"3.2.4"}}}
EOF
`,
		want: []wantItem{{name: "prettier", version: "3.2.4"}},
	},
	{
		binary: "dotnet",
		mk:     func() Collector { return NewNuGet() },
		script: `cat <<'EOF'
{"projects":[{"frameworks":[{"topLevelPackages":[{"id":"Newtonsoft.Json","resolvedVersion":"13.0.3"}]}]}]}
EOF
`,
		want:     []wantItem{{name: "Newtonsoft.Json", version: "13.0.3"}},
		tolerant: true,
	},
	{
		binary: "opkg",
		mk:     func() Collector { return NewOpkg() },
		script: `cat <<'EOF'
busybox - 1.36.1-r2
EOF
`,
		want: []wantItem{{name: "busybox", version: "1.36.1-r2"}},
	},
	{
		binary: "pacman",
		mk:     func() Collector { return NewPacman() },
		script: `cat <<'EOF'
bash 5.2.021-1
EOF
`,
		want: []wantItem{{name: "bash", version: "5.2.021-1"}},
	},
	{
		binary: "pip3",
		mk:     func() Collector { return NewPip() },
		script: `cat <<'EOF'
[{"name":"requests","version":"2.31.0"}]
EOF
`,
		want: []wantItem{{name: "requests", version: "2.31.0"}},
	},
	{
		binary: "pipx",
		mk:     func() Collector { return NewPipx() },
		script: `cat <<'EOF'
{"venvs":{"black":{"metadata":{"main_package":{"package":"black","package_version":"23.12.1"}}}}}
EOF
`,
		want:     []wantItem{{name: "black", version: "23.12.1"}},
		tolerant: true,
	},
	{
		binary: "pkg_info",
		mk:     func() Collector { return NewPkgsrc() },
		script: `cat <<'EOF'
curl-8.5.0 Client that groks URLs
EOF
`,
		want: []wantItem{{name: "curl", version: "8.5.0"}},
	},
	{
		binary: "pnpm",
		mk:     func() Collector { return NewPnpm() },
		script: `cat <<'EOF'
[{"dependencies":{"typescript":{"version":"5.3.3"}}}]
EOF
`,
		want:     []wantItem{{name: "typescript", version: "5.3.3"}},
		tolerant: true,
	},
	{
		binary: "qlist",
		mk:     func() Collector { return NewPortage() },
		script: `cat <<'EOF'
app-shells/bash-5.2_p21
EOF
`,
		want: []wantItem{{name: "bash", version: "5.2_p21"}},
	},
	{
		binary: "dart",
		mk:     func() Collector { return NewPub() },
		script: `cat <<'EOF'
{"packages":[{"name":"http","version":"1.1.2"}]}
EOF
`,
		want: []wantItem{{name: "http", version: "1.1.2"}},
	},
	{
		binary: "rpm",
		mk:     func() Collector { return NewRPM() },
		script: `printf 'bash\t5.2.15-1.el9\tRed Hat, Inc.\tx86_64\n'
`,
		want: []wantItem{{name: "bash", vendor: "Red Hat, Inc.", version: "5.2.15-1.el9", arch: "x86_64"}},
	},
	{
		binary: "scoop",
		mk:     func() Collector { return NewScoop() },
		script: `cat <<'EOF'
Installed apps:

Name  Version Source Updated
----  ------- ------ -------
git   2.43.0  main   2024-01-04
EOF
`,
		want: []wantItem{{name: "git", version: "2.43.0"}},
	},
	{
		binary: "snap",
		mk:     func() Collector { return NewSnap() },
		script: `cat <<'EOF'
Name    Version   Rev   Tracking       Publisher   Notes
core22  20240111  1122  latest/stable  canonical   base
EOF
`,
		want: []wantItem{{name: "core22", vendor: "canonical", version: "20240111"}},
	},
	{
		binary: "spack",
		mk:     func() Collector { return NewSpack() },
		script: `cat <<'EOF'
[{"name":"zlib","version":"1.3.1"}]
EOF
`,
		want: []wantItem{{name: "zlib", version: "1.3.1"}},
	},
	{
		binary: "uv",
		mk:     func() Collector { return NewUv() },
		script: `cat <<'EOF'
ruff v0.1.9
- ruff
EOF
`,
		want: []wantItem{{name: "ruff", version: "0.1.9"}},
	},
	{
		binary: "vcpkg",
		mk:     func() Collector { return NewVcpkg() },
		script: `cat <<'EOF'
zlib:x64-linux 1.3.1 A compression library
EOF
`,
		want: []wantItem{{name: "zlib", version: "1.3.1", arch: "x64-linux"}},
	},
	{
		binary: "winget",
		mk:     func() Collector { return NewWinget() },
		script: `cat <<'EOF'
Name       Id            Version
---------------------------------
Git        Git.Git       2.43.0
EOF
`,
		want: []wantItem{{name: "Git", vendor: "Git", version: "2.43.0"}},
	},
	{
		binary: "xbps-query",
		mk:     func() Collector { return NewXbps() },
		script: `cat <<'EOF'
ii curl-8.5.0_1 Client-side URL transfer tool
EOF
`,
		want: []wantItem{{name: "curl", version: "8.5.0_1"}},
	},
	{
		binary: "yarn",
		mk:     func() Collector { return NewYarn() },
		script: `cat <<'EOF'
{"type":"info","data":"prettier@3.2.4"}
EOF
`,
		want: []wantItem{{name: "prettier", version: "3.2.4"}},
	},
	{
		binary: "yay",
		mk:     func() Collector { return NewYay() },
		script: `cat <<'EOF'
paru 2.0.1-1
EOF
`,
		want: []wantItem{{name: "paru", version: "2.0.1-1"}},
	},
	{
		binary: "zypper",
		mk:     func() Collector { return NewZypper() },
		script: `cat <<'EOF'
S | Name | Type    | Version    | Arch   | Repository
--+------+---------+------------+--------+-----------
i | bash | package | 5.2.21-1.1 | x86_64 | repo-oss
EOF
`,
		want: []wantItem{{name: "bash", version: "5.2.21-1.1", arch: "x86_64"}},
	},
}

// Available must be false when PATH holds no matching binary and true once
// the binary exists on PATH. Also pins Name() for every collector, since a
// few (npm) are not registered anywhere else.
func TestCollectorAvailable_ProbesPath(t *testing.T) {
	type probe struct {
		binary string
		mk     func() Collector
	}
	probes := make([]probe, 0, len(collectorExecCases)+2)
	for _, c := range collectorExecCases {
		probes = append(probes, probe{binary: c.binary, mk: c.mk})
	}
	// brew and cocoapods Collect are covered by their root-refusal tests
	// (brew_root_test.go, cocoapods_test.go); probe only Available here.
	probes = append(probes,
		probe{binary: "brew", mk: func() Collector { return NewBrew() }},
		probe{binary: "pod", mk: func() Collector { return NewCocoaPods() }},
	)

	for _, p := range probes {
		collector := p.mk()
		t.Run(collector.Name(), func(t *testing.T) {
			assert.NotEmpty(t, collector.Name())

			t.Setenv("PATH", t.TempDir())
			assert.False(t, p.mk().Available(),
				"Available must be false with no %s on PATH", p.binary)

			fakeToolOnPath(t, p.binary, "exit 0\n")
			assert.True(t, p.mk().Available(),
				"Available must be true once %s is on PATH", p.binary)
		})
	}
}

// Collect must run the tool through runWithLimits and hand its stdout to
// the collector's parser: exact items, no error, no parse errors.
func TestCollectorCollect_ParsesValidOutput(t *testing.T) {
	for _, c := range collectorExecCases {
		collector := c.mk()
		t.Run(collector.Name(), func(t *testing.T) {
			fakeToolOnPath(t, c.binary, c.script)

			result, err := c.mk().Collect(context.Background())
			require.NoError(t, err)
			require.NotNil(t, result)
			assert.False(t, result.HasErrors(),
				"fixture must parse cleanly, got errs: %v", result.Errs)
			require.Len(t, result.Items, len(c.want))
			for i, w := range c.want {
				got := result.Items[i]
				assert.Equal(t, w.name, got.SoftwareName)
				assert.Equal(t, w.version, got.Version)
				assert.Equal(t, w.vendor, got.Vendor)
				assert.Equal(t, w.arch, got.Architecture)
				assert.Equal(t, collector.Name(), got.PackageManager)
			}
		})
	}
}

// Strict collectors must surface a non-zero exit as an error carrying the
// tool's stderr tail, so the failure is diagnosable from one log line.
func TestCollectorCollect_NonZeroExitSurfacesStderr(t *testing.T) {
	for _, c := range collectorExecCases {
		if c.tolerant {
			continue // covered by TestCollectorCollect_BenignNonZeroExit
		}
		collector := c.mk()
		t.Run(collector.Name(), func(t *testing.T) {
			fakeToolOnPath(t, c.binary,
				"echo 'inventory backend exploded' >&2\nexit 3\n")

			result, err := c.mk().Collect(context.Background())
			require.Error(t, err)
			assert.Nil(t, result)
			assert.Contains(t, err.Error(), "exit status 3")
			assert.Contains(t, err.Error(), "inventory backend exploded",
				"the tool's stderr must be folded into the error")
		})
	}
}

// Tolerant collectors (composer, gomod, nuget, pipx, pnpm) treat a
// non-zero exit with empty stdout as "nothing installed here": an empty
// inventory with no error, never a failure.
func TestCollectorCollect_BenignNonZeroExit(t *testing.T) {
	for _, c := range collectorExecCases {
		if !c.tolerant {
			continue
		}
		collector := c.mk()
		t.Run(collector.Name(), func(t *testing.T) {
			fakeToolOnPath(t, c.binary,
				"echo 'no project found here' >&2\nexit 1\n")

			result, err := c.mk().Collect(context.Background())
			require.NoError(t, err,
				"non-zero exit with empty stdout must be benign")
			require.NotNil(t, result)
			assert.Empty(t, result.Items)
			assert.Empty(t, result.Errs)
		})
	}
}

// Exit-tolerance never extends to fatal exec failures: with the binary
// vanished between Available and Collect, tolerant collectors must still
// return an error rather than a silently empty inventory.
func TestCollectorCollect_MissingBinaryIsFatal(t *testing.T) {
	for _, c := range collectorExecCases {
		if !c.tolerant {
			continue
		}
		collector := c.mk()
		t.Run(collector.Name(), func(t *testing.T) {
			if runtime.GOOS == "windows" {
				t.Skip("PATH semantics differ on windows")
			}
			t.Setenv("PATH", t.TempDir())

			result, err := c.mk().Collect(context.Background())
			require.Error(t, err)
			assert.Nil(t, result)
			assert.Contains(t, err.Error(), c.binary)
		})
	}
}

// Mamba reuses the conda parser but must relabel parse errors as its own.
func TestMambaCollect_RelabelsParseErrors(t *testing.T) {
	fakeToolOnPath(t, "mamba", "echo 'this is not json'\n")

	result, err := NewMamba().Collect(context.Background())
	require.NoError(t, err)
	require.Len(t, result.Errs, 1)
	assert.Equal(t, "mamba", result.Errs[0].Collector)
	assert.Empty(t, result.Items)
}

// A tool failing without writing stderr must still produce a diagnosable
// exit-status error, just without a stderr excerpt.
func TestRunWithLimits_NonZeroExitNoStderr(t *testing.T) {
	bin := writeFakeTool(t, "silent-failure", "exit 2\n")

	_, err := runWithLimits(context.Background(), bin)
	require.Error(t, err)
	assert.Equal(t, "wait "+bin+": exit status 2", err.Error())
}

// When the unscoped winget query fails (e.g. Store source agreements not
// accepted), Collect must retry with --source winget and use that output.
func TestWingetCollect_FallsBackToWingetSource(t *testing.T) {
	fakeToolOnPath(t, "winget", `if [ "$2" = "--source" ]; then
cat <<'EOF'
Name       Id            Version
---------------------------------
Git        Git.Git       2.43.0
EOF
exit 0
fi
echo 'store source agreements not accepted' >&2
exit 1
`)

	result, err := NewWinget().Collect(context.Background())
	require.NoError(t, err)
	require.Len(t, result.Items, 1)
	assert.Equal(t, "Git", result.Items[0].SoftwareName)
	assert.Equal(t, "2.43.0", result.Items[0].Version)
	assert.Equal(t, "Git", result.Items[0].Vendor)
	assert.Equal(t, "winget", result.Items[0].PackageManager)
}

// With no pip3 on PATH, Pip.Available must fall back to probing pip, and
// Collect must invoke the pip binary.
func TestPipCollect_FallsBackToPipBinary(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	assert.False(t, NewPip().Available())

	// PATH holds only the fake-tool dirs here, so the script must rely on
	// shell builtins (echo) rather than external commands like cat.
	fakeToolOnPath(t, "pip",
		`echo '[{"name":"requests","version":"2.31.0"}]'
`)
	assert.True(t, NewPip().Available())

	result, err := NewPip().Collect(context.Background())
	require.NoError(t, err)
	require.Len(t, result.Items, 1)
	assert.Equal(t, "requests", result.Items[0].SoftwareName)
	assert.Equal(t, "2.31.0", result.Items[0].Version)
	assert.Equal(t, "pip", result.Items[0].PackageManager)
}

// pipx exiting 1 while warning about broken venv interpreters is data loss
// worth a diagnostic, but never a collector failure: empty inventory, nil
// error (the stderr is summarised as a Warn record with a reinstall hint).
func TestPipxCollect_BrokenInterpreterDiagnosticIsBenign(t *testing.T) {
	fakeToolOnPath(t, "pipx",
		"echo 'invalid interpreter for venv black' >&2\nexit 1\n")

	result, err := NewPipx().Collect(context.Background())
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Empty(t, result.Items)
	assert.Empty(t, result.Errs)
}

// WindowsOS.Available is GOOS-gated: even with a powershell.exe binary on
// PATH it must stay false off Windows.
func TestWindowsOSAvailable_FalseOffWindows(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("this test asserts the non-Windows gate")
	}
	fakeToolOnPath(t, "powershell.exe", "exit 0\n")
	assert.False(t, NewWindowsOS().Available())
}

// WindowsOS.Collect runs the PowerShell inventory script and maps its JSON
// payload — name, version+build, architecture, edition, license state —
// into a single windows-os item.
func TestWindowsOSCollect_ParsesInventoryJSON(t *testing.T) {
	fakeToolOnPath(t, "powershell.exe", `cat <<'EOF'
{"name":"Windows 11 Pro","version":"23H2","build":"22631","architecture":"64-bit","edition":"Professional","license_status":1}
EOF
`)

	result, err := NewWindowsOS().Collect(context.Background())
	require.NoError(t, err)
	require.Len(t, result.Items, 1)
	item := result.Items[0]
	assert.Equal(t, "Windows 11 Pro", item.SoftwareName)
	assert.Equal(t, "Microsoft", item.Vendor)
	assert.Equal(t, "23H2 (build 22631)", item.Version)
	assert.Equal(t, "64-bit", item.Architecture)
	assert.Equal(t, "windows-os", item.PackageManager)
	assert.Equal(t, "licensed", item.License)
	assert.Equal(t, "Windows operating system; edition Professional", item.Description)
}

func TestWindowsOSCollect_NonZeroExitSurfacesStderr(t *testing.T) {
	fakeToolOnPath(t, "powershell.exe",
		"echo 'CIM query failed' >&2\nexit 3\n")

	result, err := NewWindowsOS().Collect(context.Background())
	require.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "exit status 3")
	assert.Contains(t, err.Error(), "CIM query failed")
}

// Off Windows the registry collector is unavailable and its Collect maps
// the stub inventory to an empty result without error.
func TestWindowsRegistryOffWindows_UnavailableAndEmptyInventory(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("this test asserts the non-Windows stub behavior")
	}
	w := NewWindowsRegistry()
	assert.False(t, w.Available())

	result, err := w.Collect(context.Background())
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Empty(t, result.Items)
	assert.Empty(t, result.Errs)
}

// cappedBuffer.Write must accept every byte (reporting len(p) per the
// io.Writer contract for a sink that drops overflow) while never storing
// more than max bytes.
func TestCappedBuffer_WriteEnforcesCap(t *testing.T) {
	buf := &cappedBuffer{max: 8}

	n, err := buf.Write([]byte("0123"))
	require.NoError(t, err)
	assert.Equal(t, 4, n)
	assert.Equal(t, "0123", buf.String())

	// Crosses the cap: only the remaining 4 bytes are stored.
	n, err = buf.Write([]byte("456789"))
	require.NoError(t, err)
	assert.Equal(t, 6, n)
	assert.Equal(t, "01234567", buf.String())

	// Already full: everything is dropped, nothing errors.
	n, err = buf.Write([]byte("beyond"))
	require.NoError(t, err)
	assert.Equal(t, 6, n)
	assert.Equal(t, "01234567", buf.String())
}

// dirExists must report true only for existing directories: not for
// missing paths and not for regular files.
func TestDirExists_ReportsOnlyDirectories(t *testing.T) {
	dir := t.TempDir()
	assert.True(t, dirExists(dir))
	assert.False(t, dirExists(filepath.Join(dir, "missing")))

	file := filepath.Join(dir, "regular-file")
	require.NoError(t, os.WriteFile(file, []byte("x"), 0o644))
	assert.False(t, dirExists(file))
}
