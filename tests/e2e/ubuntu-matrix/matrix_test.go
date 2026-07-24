//go:build e2e

// Ubuntu multi-version package-discovery matrix (RFC-0149).
//
// Each leg boots a real, unmodified Ubuntu image, seeds a deterministic set
// of packages, runs the *compiled* kite-collector binary's software.Dpkg
// collector inside that container, and compares the discovered
// name/version/architecture/cpe23/package_manager against the leg's fixture.
//
// Why the binary is injected into the stock image rather than baked into a
// derived one: R1 asks for real, unmodified ubuntu:X images, and the whole
// supply-chain claim in §6.5 rests on ContainerTestFixture.image_digest being
// the digest of the thing that actually ran. A Dockerfile would put a derived
// image in between, so the pinned digest would describe a FROM line rather
// than the tested artifact.
//
// Run with:
//
//	make test-ubuntu-matrix                          # all four legs
//	KITE_MATRIX_TARGET=ubuntu-22.04 make test-ubuntu-matrix
package ubuntumatrix

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
)

// Timeouts. The collector exec bound matches software/exec.go's own
// 60-second-per-invocation convention (§8.2); the seed gets far more room
// because it is an apt-get install over the public Ubuntu archive.
const (
	buildTimeout         = 5 * time.Minute
	containerBootTimeout = 120 * time.Second
	seedTimeout          = 10 * time.Minute
	collectorExecTimeout = 60 * time.Second
	digestLookupTimeout  = 60 * time.Second
)

// In-container paths. Everything lands at the filesystem root: a stock
// ubuntu image has no /etc/kite, and Docker's archive-put fails rather than
// creating a missing parent directory.
const (
	binaryPath = "/kite-collector"
	seedPath   = "/seed.sh"
	configPath = "/scan.yaml"
	outDir     = "/out"
	stdoutPath = outDir + "/scan.json"
	stderrPath = outDir + "/scan.err"
)

func TestUbuntuPackageMatrix(t *testing.T) {
	matrix, err := LoadMatrix()
	require.NoError(t, err, "targets.json must load and satisfy the coverage policy")

	targets := selectTargets(t, matrix)
	binary := buildCollector(t)
	version := collectorVersion(t)

	for _, target := range targets {
		t.Run(target.Slug, func(t *testing.T) {
			runLeg(t, target, binary, version, matrix.Policy)
		})
	}
}

// selectTargets honours KITE_MATRIX_TARGET, used by CI to give each matrix
// leg its own job. An unknown slug is fatal rather than a no-op: `go test
// -run` against a subtest name that matches nothing exits 0, and a matrix
// that silently runs zero legs while reporting green is worse than no matrix.
func selectTargets(t *testing.T, matrix Matrix) []Target {
	t.Helper()
	slug := os.Getenv("KITE_MATRIX_TARGET")
	if slug == "" {
		return matrix.Targets
	}
	target, ok := matrix.Target(slug)
	require.Truef(t, ok,
		"KITE_MATRIX_TARGET=%q is not a declared target; known targets: %s",
		slug, strings.Join(matrix.Slugs(), ", "),
	)
	return []Target{target}
}

func buildCollector(t *testing.T) string {
	t.Helper()
	out := filepath.Join(t.TempDir(), "kite-collector")

	ctx, cancel := context.WithTimeout(context.Background(), buildTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, "go", "build", "-trimpath", "-o", out, "./cmd/kite-collector")
	cmd.Dir = RepoRoot()
	cmd.Env = append(os.Environ(),
		"CGO_ENABLED=0",
		"GOOS=linux",
		"GOARCH="+runtime.GOARCH,
	)
	combined, err := cmd.CombinedOutput()
	require.NoErrorf(t, err, "build kite-collector:\n%s", combined)
	return out
}

// collectorVersion records which build was under test, so a
// PackageDiscoveryTestRun row can be traced back to a commit.
func collectorVersion(t *testing.T) string {
	t.Helper()
	cmd := exec.Command("git", "rev-parse", "--short", "HEAD")
	cmd.Dir = RepoRoot()
	out, err := cmd.Output()
	if err != nil {
		t.Logf("kite_collector_version unavailable (%v); reporting \"unknown\"", err)
		return "unknown"
	}
	return strings.TrimSpace(string(out))
}

func runLeg(t *testing.T, target Target, binary, version string, policy Policy) {
	t.Helper()

	// R3: a leg that can block a merge must name the exact image bytes it
	// was reviewed against, or fail loudly saying how to pin it.
	require.NoError(t, target.RequirePin())

	if target.Architecture != runtime.GOARCH {
		t.Skipf("target %s is %s; this host is %s", target.Slug, target.Architecture, runtime.GOARCH)
	}

	expectation, err := LoadExpectation(target)
	require.NoError(t, err)

	obs := Observation{
		Now:            time.Now().UTC(),
		Target:         target,
		Expectation:    expectation,
		ObservedDigest: currentDigest(t, target),
	}
	started := time.Now().UTC()

	ctr, err := startContainer(t, target, binary)
	if err != nil {
		reportInfraError(t, obs, version, policy, started, fmt.Sprintf("container start: %v", err))
		return
	}

	if err := seedContainer(t, ctr); err != nil {
		reportInfraError(t, obs, version, policy, started, fmt.Sprintf("seed: %v", err))
		return
	}

	stdout, stderr, err := runCollector(t, ctr)
	if err != nil {
		reportInfraError(t, obs, version, policy, started, fmt.Sprintf("collector exec: %v", err))
		return
	}

	packages, err := ParseScanOutput(stdout)
	require.NoErrorf(t, err, "scan stderr tail:\n%s", tail(stderr, 2000))
	obs.Packages = packages
	obs.ParseErrors = CountParseErrors(stderr)

	findings := Evaluate(obs)
	run := NewRun(obs, findings, started, time.Now().UTC())
	publish(t, target.Slug, run, version, policy)

	require.Equalf(t, StatusPass, run.Status,
		"parity findings for %s:\n%s", target.Slug, StepSummary(run, target.Slug),
	)
}

// currentDigest re-resolves the floating tag during the weekly scheduled
// drift-check only. Doing it on every PR would add a Docker Hub round trip —
// and its rate limit — to every push for a value that moves a few times a
// month (§6.1 Denial of Service).
func currentDigest(t *testing.T, target Target) string {
	t.Helper()
	if os.Getenv("KITE_MATRIX_DRIFT_CHECK") != "1" {
		return ""
	}
	ctx, cancel := context.WithTimeout(context.Background(), digestLookupTimeout)
	defer cancel()

	digest, err := NewRegistryClient().ResolveTagDigest(ctx, target.Repository(), target.Tag())
	if err != nil {
		// A registry hiccup must not masquerade as base-image drift.
		t.Logf("drift-check: could not resolve %s: %v", target.BaseImageRef, err)
		return ""
	}
	return digest
}

func startContainer(t *testing.T, target Target, binary string) (testcontainers.Container, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), containerBootTimeout)
	defer cancel()

	req := testcontainers.ContainerRequest{
		Image: target.PinnedRef(),
		// Keep the stock image alive so the collector can be exec'd into
		// it; nothing about the image itself is modified.
		Cmd: []string{"sleep", "infinity"},
		Files: []testcontainers.ContainerFile{
			{HostFilePath: binary, ContainerFilePath: binaryPath, FileMode: 0o755},
			{HostFilePath: Path(target.SeedScript), ContainerFilePath: seedPath, FileMode: 0o755},
			{HostFilePath: Path("fixtures/scan.yaml"), ContainerFilePath: configPath, FileMode: 0o644},
		},
	}

	ctr, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		return nil, err
	}
	t.Cleanup(func() {
		terminateCtx, terminateCancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer terminateCancel()
		_ = ctr.Terminate(terminateCtx)
	})
	return ctr, nil
}

func seedContainer(t *testing.T, ctr testcontainers.Container) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), seedTimeout)
	defer cancel()

	code, output, err := execInContainer(ctx, ctr, "mkdir -p "+outDir+" && "+seedPath)
	if err != nil {
		return err
	}
	if code != 0 {
		return fmt.Errorf("seed script exited %d:\n%s", code, tail(output, 4000))
	}
	return nil
}

// runCollector executes the compiled binary inside the container. Output is
// redirected to files rather than read off the exec stream: the scan writes
// JSON to stdout and slog records to stderr, and the Docker exec stream would
// interleave them into unparseable output.
func runCollector(t *testing.T, ctr testcontainers.Container) (stdout, stderr []byte, err error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), collectorExecTimeout)
	defer cancel()

	script := fmt.Sprintf(
		"%s scan --config %s --db %s/kite.db --output json >%s 2>%s",
		binaryPath, configPath, outDir, stdoutPath, stderrPath,
	)
	code, output, err := execInContainer(ctx, ctr, script)
	if err != nil {
		return nil, nil, err
	}

	stderr = copyOut(t, ctr, stderrPath)
	if code != 0 {
		return nil, nil, fmt.Errorf(
			"scan exited %d:\n%s\n%s", code, tail(output, 2000), tail(stderr, 4000),
		)
	}
	stdout = copyOut(t, ctr, stdoutPath)
	return stdout, stderr, nil
}

func execInContainer(
	ctx context.Context, ctr testcontainers.Container, script string,
) (int, []byte, error) {
	code, reader, err := ctr.Exec(ctx, []string{"/bin/sh", "-c", script})
	if err != nil {
		return code, nil, err
	}
	var buf bytes.Buffer
	if reader != nil {
		_, _ = io.Copy(&buf, reader)
	}
	return code, buf.Bytes(), nil
}

func copyOut(t *testing.T, ctr testcontainers.Container, path string) []byte {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	rc, err := ctr.CopyFileFromContainer(ctx, path)
	if err != nil {
		t.Logf("copy %s from container: %v", path, err)
		return nil
	}
	defer func() { _ = rc.Close() }()

	data, err := io.ReadAll(rc)
	if err != nil {
		t.Logf("read %s from container: %v", path, err)
		return nil
	}
	return data
}

// reportInfraError records a container/Docker-layer failure as infra_error
// and skips rather than fails. Classification is deliberately narrow: only
// failures before the collector produced output land here, never a non-zero
// assertion outcome, so a real parsing bug can never be retried away as a
// flake (§4.2.3 risk analysis).
func reportInfraError(
	t *testing.T,
	obs Observation,
	version string,
	policy Policy,
	started time.Time,
	reason string,
) {
	t.Helper()
	run := NewRun(obs, nil, started, time.Now().UTC()).AsInfraError(reason, time.Now().UTC())
	publish(t, obs.Target.Slug, run, version, policy)

	if os.Getenv("CI") != "" {
		t.Fatalf("infra_error on %s: %s", obs.Target.Slug, reason)
	}
	t.Skipf("infra_error on %s (set CI=1 to make this fatal): %s", obs.Target.Slug, reason)
}

// publish writes the leg's artifact and its PR step summary. Both are
// best-effort: RFC-0149's gating contract is that GitHub's own status check
// is the sole merge signal, so a reporting failure must never change a leg's
// pass/fail outcome.
func publish(t *testing.T, slug string, run Run, version string, policy Policy) {
	t.Helper()
	payload := NewPayload(version, policy, []Run{run})
	path := ReportPath(slug)
	if err := payload.WriteFile(path); err != nil {
		t.Logf("write matrix report: %v", err)
	} else {
		t.Logf("matrix report written to %s", path)
	}
	if err := AppendStepSummary(StepSummary(run, slug)); err != nil {
		t.Logf("append step summary: %v", err)
	}
}

func tail(b []byte, n int) string {
	if len(b) <= n {
		return string(b)
	}
	return "…" + string(b[len(b)-n:])
}
