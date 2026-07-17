//go:build smoke

// Package smoke is a docker-compose-driven smoke test for the per-host
// container discovery collector (internal/discovery/agent/containers).
//
// It is opt-in behind the `smoke` build tag so it never runs in the normal
// unit or `-tags e2e` suites — it requires a live Docker daemon reachable
// via KITE_DOCKER_HOST (or the default /var/run/docker.sock) with a set of
// known fixture containers already running. docker-compose.smoke.yml starts
// those fixtures; run.sh wires the two together.
//
// What it proves:
//
//   - CONNECTION: NewDockerCollector().Collect() reaches the daemon and
//     returns without error (KITE-E001 path is NOT hit).
//   - DATA QUALITY: every security-relevant field the CWE/CAPEC audit
//     pipeline depends on is extracted correctly from real containers —
//     image, state, published ports, read-only bind mounts, labels,
//     privileged (CWE-732), host network (CWE-668), non-root uid, and
//     exited state + exit code.
package smoke

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vulnertrack/kite-collector/internal/discovery/agent/containers"
)

const (
	// smokeLabel marks every fixture container so the collector output can be
	// filtered away from whatever else is running on the host daemon (the
	// test runner container itself, the CI agent, etc.).
	smokeLabel = "com.vulnertrack.smoke"
	// roleLabel identifies which fixture a container is, independent of the
	// compose-generated container name (which carries a project prefix).
	roleLabel = "com.vulnertrack.role"

	// waitForFixtures polling budget. Fixtures are tiny images; they are
	// normally all present within a couple of seconds, but the exited fixture
	// needs a moment to run its command and reach the exited state.
	fixtureWait = 60 * time.Second
	pollEvery   = 1 * time.Second
)

// expectedRoles is the full fixture set. All must be present (and the
// lifecycle-sensitive ones in the expected state) before assertions run.
var expectedRoles = []string{"web", "privileged", "hostnet", "nonroot", "exited"}

func TestContainersSmoke(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), fixtureWait+30*time.Second)
	defer cancel()

	c := containers.NewDockerCollector()

	byRole := waitForFixtures(ctx, t, c)

	t.Run("web: image/state/port/mount/labels", func(t *testing.T) {
		web := byRole["web"]
		require.Contains(t, web.Image, "nginx", "image name should be extracted")
		require.Equal(t, containers.StateRunning, web.State)
		require.Equal(t, "web", web.Labels[roleLabel], "labels must round-trip verbatim")

		require.True(t, hasPort(web, 80, 18080, "tcp"),
			"published port 18080->80/tcp not found; got %+v", web.Ports)

		m, ok := findMount(web, "/usr/share/nginx/html/index.html")
		require.True(t, ok, "read-only bind mount not found; got %+v", web.Mounts)
		require.Equal(t, "bind", m.Type)
		require.True(t, m.ReadOnly, "mount mounted :ro must report ReadOnly=true (CWE-732 posture)")
	})

	t.Run("privileged: CWE-732 flag", func(t *testing.T) {
		require.True(t, byRole["privileged"].Privileged,
			"--privileged container must be detected as privileged")
	})

	t.Run("hostnet: CWE-668 flag", func(t *testing.T) {
		require.True(t, byRole["hostnet"].HostNetwork,
			"--network=host container must be detected as host_network")
	})

	t.Run("nonroot: root_uid extraction", func(t *testing.T) {
		nr := byRole["nonroot"]
		require.NotNil(t, nr.RootUID, "root_uid must be resolved for a numeric user")
		require.Equal(t, 1000, *nr.RootUID, "user 1000:1000 must resolve to uid 1000")
	})

	t.Run("exited: state + exit code", func(t *testing.T) {
		ex := byRole["exited"]
		require.Equal(t, containers.StateExited, ex.State)
		require.Equal(t, 7, ex.ExitCode, "exit code must be captured from inspect")
	})
}

// waitForFixtures polls the collector until every expected fixture is present
// and the lifecycle-sensitive ones (web running, exited exited) have settled,
// then returns them keyed by role. A collect error fails immediately — that is
// the connection smoke signal.
func waitForFixtures(ctx context.Context, t *testing.T, c containers.Collector) map[string]containers.Container {
	t.Helper()
	deadline := time.Now().Add(fixtureWait)
	var last map[string]containers.Container
	for {
		got, err := c.Collect(ctx)
		require.NoError(t, err,
			"collector could not reach the Docker daemon — is the socket mounted and KITE_DOCKER_HOST set?")

		last = map[string]containers.Container{}
		for _, cn := range got {
			if cn.Labels[smokeLabel] == "" {
				continue // not one of ours
			}
			if role := cn.Labels[roleLabel]; role != "" {
				last[role] = cn
			}
		}

		if fixturesReady(last) {
			require.NotEmpty(t, got, "connected but zero containers returned")
			return last
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out after %s waiting for fixtures; have roles %v (need %v, web=running, exited=exited)",
				fixtureWait, roles(last), expectedRoles)
		}
		time.Sleep(pollEvery)
	}
}

func fixturesReady(byRole map[string]containers.Container) bool {
	for _, r := range expectedRoles {
		if _, ok := byRole[r]; !ok {
			return false
		}
	}
	return byRole["web"].State == containers.StateRunning &&
		byRole["exited"].State == containers.StateExited
}

func hasPort(c containers.Container, containerPort, hostPort uint16, proto string) bool {
	for _, p := range c.Ports {
		if p.ContainerPort == containerPort && p.HostPort == hostPort && p.Proto == proto {
			return true
		}
	}
	return false
}

func findMount(c containers.Container, dst string) (containers.Mount, bool) {
	for _, m := range c.Mounts {
		if m.Destination == dst {
			return m, true
		}
	}
	return containers.Mount{}, false
}

func roles(byRole map[string]containers.Container) []string {
	out := make([]string, 0, len(byRole))
	for r := range byRole {
		out = append(out, r)
	}
	return out
}
