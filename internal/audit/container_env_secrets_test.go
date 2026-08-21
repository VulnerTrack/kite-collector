package audit

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	dockerdisc "github.com/vulnertrack/kite-collector/internal/discovery/docker"
	"github.com/vulnertrack/kite-collector/internal/model"
)

// fakeEnvLister scripts ListContainerEnvs and counts invocations so cache
// behaviour is observable.
type fakeEnvLister struct {
	envs  []dockerdisc.ContainerEnv
	err   error
	calls int
}

func (f *fakeEnvLister) ListContainerEnvs(_ context.Context, _ map[string]any) ([]dockerdisc.ContainerEnv, error) {
	f.calls++
	return f.envs, f.err
}

const testFullID = "0123456789abcdef0123456789abcdef"

func containerMachine(shortID string) model.Machine {
	return model.Machine{
		ID:          uuid.MustParse("018f0000-0000-7000-8000-0000000000aa"),
		Hostname:    "web-1",
		MachineType: model.MachineTypeContainer,
		Tags:        fmt.Sprintf(`{"container_id":%q}`, shortID),
	}
}

// The AWS access-key pattern (sec-001) is the canonical happy path: one
// finding, every field pinned, and the secret value itself never stored.
func TestContainerEnvSecrets_HappyPathFindingShape(t *testing.T) {
	lister := &fakeEnvLister{envs: []dockerdisc.ContainerEnv{{
		ID:   testFullID,
		Name: "api",
		Env:  []string{"AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE"},
	}}}
	aud := NewContainerEnvSecrets(lister, nil, nil)
	m := containerMachine(testFullID[:12])

	got, err := aud.Audit(context.Background(), m)
	require.NoError(t, err)
	require.Len(t, got, 1)

	f := got[0]
	assert.Equal(t, "container_env_secrets", f.Auditor)
	assert.Equal(t, "sec-001", f.CheckID)
	assert.Equal(t, m.ID, f.MachineID)
	assert.Equal(t, "No credentials in container environment variables", f.Expected)
	assert.Equal(t, "CIS 3.11, CIS 14.8", f.CISControl)
	assert.Contains(t, f.Evidence, "ENV[AWS_ACCESS_KEY_ID]=<redacted>")
	assert.Contains(t, f.Evidence, testFullID[:12], "evidence names the short container id")
	assert.Contains(t, f.Evidence, "(api)")
	assert.NotContains(t, f.Evidence, "AKIAIOSFODNN7EXAMPLE",
		"the secret value must never appear anywhere in the finding")
	assert.NotEmpty(t, f.Title)
	assert.NotEmpty(t, f.Remediation)
	assert.False(t, f.Timestamp.IsZero())
}

// Finding IDs are deterministic (UUIDv5 over machine+pattern+var) so
// re-scans upsert instead of duplicating.
func TestContainerEnvSecrets_FindingIDDeterministic(t *testing.T) {
	newAud := func() *ContainerEnvSecrets {
		return NewContainerEnvSecrets(&fakeEnvLister{envs: []dockerdisc.ContainerEnv{{
			ID:  testFullID,
			Env: []string{"AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE"},
		}}}, nil, nil)
	}
	m := containerMachine(testFullID[:12])

	first, err := newAud().Audit(context.Background(), m)
	require.NoError(t, err)
	second, err := newAud().Audit(context.Background(), m)
	require.NoError(t, err)
	require.Len(t, first, 1)
	require.Len(t, second, 1)
	assert.Equal(t, first[0].ID, second[0].ID,
		"same machine+pattern+var must always yield the same finding ID")
}

func TestContainerEnvSecrets_SkipsNonContainerMachines(t *testing.T) {
	lister := &fakeEnvLister{}
	aud := NewContainerEnvSecrets(lister, nil, nil)

	got, err := aud.Audit(context.Background(),
		model.Machine{MachineType: model.MachineTypeServer})
	require.NoError(t, err)
	assert.Nil(t, got)
	assert.Equal(t, 0, lister.calls, "non-container machines must not touch Docker")
}

func TestContainerEnvSecrets_NilListerAndMissingTag(t *testing.T) {
	aud := NewContainerEnvSecrets(nil, nil, nil)
	got, err := aud.Audit(context.Background(), containerMachine(testFullID[:12]))
	require.NoError(t, err)
	assert.Nil(t, got, "nil lister is a configured-off no-op")

	lister := &fakeEnvLister{}
	aud = NewContainerEnvSecrets(lister, nil, nil)
	got, err = aud.Audit(context.Background(),
		model.Machine{MachineType: model.MachineTypeContainer, Tags: `{"other":"x"}`})
	require.NoError(t, err)
	assert.Nil(t, got)
	assert.Equal(t, 0, lister.calls, "no container_id tag → no Docker call")

	// Unparseable tags degrade identically.
	got, err = aud.Audit(context.Background(),
		model.Machine{MachineType: model.MachineTypeContainer, Tags: `not-json`})
	require.NoError(t, err)
	assert.Nil(t, got)
}

// One ListContainerEnvs call serves every subsequent Audit — including
// after a lister failure, which caches an empty set rather than retrying
// on every machine of the scan.
func TestContainerEnvSecrets_CachesSingleListCall(t *testing.T) {
	lister := &fakeEnvLister{envs: []dockerdisc.ContainerEnv{{
		ID:  testFullID,
		Env: []string{"AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE"},
	}}}
	aud := NewContainerEnvSecrets(lister, nil, nil)
	m := containerMachine(testFullID[:12])

	for i := 0; i < 3; i++ {
		_, err := aud.Audit(context.Background(), m)
		require.NoError(t, err)
	}
	assert.Equal(t, 1, lister.calls, "the env listing must be fetched exactly once")

	failing := &fakeEnvLister{err: errors.New("docker down")}
	aud = NewContainerEnvSecrets(failing, nil, nil)
	got, err := aud.Audit(context.Background(), m)
	require.NoError(t, err, "lister failure skips the scan, it does not fail the audit")
	assert.Nil(t, got)
	_, _ = aud.Audit(context.Background(), m)
	assert.Equal(t, 1, failing.calls, "a failed listing must not be retried per machine")
}

func TestContainerEnvSecrets_MaxScanCapDropsRemainder(t *testing.T) {
	first := strings.Repeat("a", 32)
	third := strings.Repeat("c", 32)
	lister := &fakeEnvLister{envs: []dockerdisc.ContainerEnv{
		{ID: first, Env: []string{"AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE"}},
		{ID: strings.Repeat("b", 32), Env: []string{"X=1"}},
		{ID: third, Env: []string{"AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE"}},
	}}
	aud := NewContainerEnvSecrets(lister, nil, nil)
	aud.maxScan = 2

	got, err := aud.Audit(context.Background(), containerMachine(first[:12]))
	require.NoError(t, err)
	assert.Len(t, got, 1, "containers under the cap are scanned")

	got, err = aud.Audit(context.Background(), containerMachine(third[:12]))
	require.NoError(t, err)
	assert.Nil(t, got, "containers beyond the cap are skipped, not scanned late")
}

// Deny prefixes: defaults (PATH, TERM, …) and operator extras, both
// case-insensitive; empty extras ignored.
func TestContainerEnvSecrets_DenyPrefixes(t *testing.T) {
	secret := "AKIAIOSFODNN7EXAMPLE"
	lister := &fakeEnvLister{envs: []dockerdisc.ContainerEnv{{
		ID: testFullID,
		Env: []string{
			"PATH=" + secret,        // default deny
			"path_extra=" + secret,  // default deny is case-insensitive + prefix
			"MYAPP_FAKE=" + secret,  // denied via extraDeny
			"myapp_low=" + secret,   // extraDeny case-insensitive
			"REAL_KEY_A=" + secret,  // must be reported
		},
	}}}
	aud := NewContainerEnvSecrets(lister, nil, []string{"MYAPP_", ""})

	got, err := aud.Audit(context.Background(), containerMachine(testFullID[:12]))
	require.NoError(t, err)
	require.Len(t, got, 1, "only the non-denied var may produce a finding")
	assert.Contains(t, got[0].Evidence, "ENV[REAL_KEY_A]")
}

// Dedup is per (pattern, var name): the same var never yields two findings
// for one pattern, while two vars matching the same pattern yield two.
func TestScanContainerEnv_DedupBoundary(t *testing.T) {
	m := containerMachine(testFullID[:12])
	env := dockerdisc.ContainerEnv{ID: testFullID, Name: "db", Env: []string{
		"KEY_ONE=AKIAIOSFODNN7EXAMPLE",
		"KEY_TWO=AKIAIOSFODNN7EXAMPLE",
	}}
	got := scanContainerEnv(m, env, defaultEnvDenyPrefixes, time.Now().UTC())
	names := make([]string, 0, len(got))
	for _, f := range got {
		if f.CheckID == "sec-001" {
			names = append(names, f.Evidence[:strings.Index(f.Evidence, "]")+1])
		}
	}
	assert.ElementsMatch(t, []string{"ENV[KEY_ONE]", "ENV[KEY_TWO]"}, names)
}

func TestScanContainerEnv_EmptyEnvAndValuelessVars(t *testing.T) {
	m := containerMachine(testFullID[:12])
	assert.Nil(t, scanContainerEnv(m, dockerdisc.ContainerEnv{ID: testFullID}, nil, time.Now()))

	env := dockerdisc.ContainerEnv{ID: testFullID, Env: []string{
		"NOVALUE=", "NOEQUALS", "=leadingequals",
	}}
	assert.Empty(t, scanContainerEnv(m, env, nil, time.Now()),
		"valueless and malformed entries must be ignored, not crash")
}

// Stress: thousands of env vars across the cap boundary scan quickly and
// dedup keeps findings bounded by (patterns × distinct names).
func TestScanContainerEnv_StressLargeEnvironment(t *testing.T) {
	m := containerMachine(testFullID[:12])
	env := dockerdisc.ContainerEnv{ID: testFullID, Name: "big"}
	for i := 0; i < 5000; i++ {
		// Every var carries the same AWS-shaped value; only 100 distinct names.
		env.Env = append(env.Env,
			fmt.Sprintf("VAR_%03d=AKIAIOSFODNN7EXAMPLE", i%100))
	}
	start := time.Now()
	got := scanContainerEnv(m, env, defaultEnvDenyPrefixes, time.Now().UTC())
	elapsed := time.Since(start)

	count := 0
	for _, f := range got {
		if f.CheckID == "sec-001" {
			count++
		}
	}
	assert.Equal(t, 100, count, "dedup must collapse repeats to distinct names")
	assert.Less(t, elapsed, 10*time.Second, "5k-var scan must stay interactive")
}

func TestSplitEnvKV(t *testing.T) {
	name, value, ok := splitEnvKV("A=b")
	assert.True(t, ok)
	assert.Equal(t, "A", name)
	assert.Equal(t, "b", value)

	name, value, ok = splitEnvKV("A=b=c")
	assert.True(t, ok)
	assert.Equal(t, "A", name)
	assert.Equal(t, "b=c", value, "only the first '=' splits")

	_, _, ok = splitEnvKV("NOEQUALS")
	assert.False(t, ok)
	_, _, ok = splitEnvKV("=v")
	assert.False(t, ok, "empty name is malformed")
	_, value, ok = splitEnvKV("A=")
	assert.True(t, ok)
	assert.Empty(t, value)
}

func TestTruncateID(t *testing.T) {
	assert.Equal(t, "abc", truncateID("abc", 12), "shorter than n stays whole")
	assert.Equal(t, "0123456789ab", truncateID(testFullID, 12))
	assert.Equal(t, "ab", truncateID("ab", 2), "exact length stays whole")
	assert.Equal(t, "", truncateID("", 12))
}

func TestMatchesAnyPrefix(t *testing.T) {
	assert.True(t, matchesAnyPrefix("PATH", []string{"PATH"}))
	assert.True(t, matchesAnyPrefix("path_extra", []string{"PATH"}), "case-insensitive")
	assert.True(t, matchesAnyPrefix("LC_ALL", []string{"LC_"}))
	assert.False(t, matchesAnyPrefix("XPATH", []string{"PATH"}), "prefix, not substring")
	assert.False(t, matchesAnyPrefix("ANY", []string{""}), "empty prefix is ignored")
	assert.False(t, matchesAnyPrefix("ANY", nil))
}
