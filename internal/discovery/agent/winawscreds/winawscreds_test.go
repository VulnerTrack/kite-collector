package winawscreds

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// -- enum strings pinned to host_aws_profiles.file_kind CHECK enum --

func TestFileKindEnumStrings(t *testing.T) {
	assert.Equal(t, "credentials", string(FileCredentials))
	assert.Equal(t, "config", string(FileConfig))
	assert.Equal(t, "unknown", string(FileUnknown))
	assert.Equal(t, 4096, MaxProfiles)
	assert.Equal(t, []string{".aws"}, AWSDirRelComponents)
}

func TestDefaultUsersBases(t *testing.T) {
	assert.Equal(t, []string{`C:\Users`, "/home", "/Users"}, DefaultUsersBases())
}

// -- HashContents -------------------------------------------------

func TestHashContents(t *testing.T) {
	// SHA-256 of "" and of "abc" are well-known vectors.
	assert.Equal(t,
		"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		HashContents(nil))
	assert.Equal(t,
		"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
		HashContents([]byte("abc")))
	// Distinct inputs hash differently; 64 hex chars always.
	assert.NotEqual(t, HashContents([]byte("a")), HashContents([]byte("b")))
	assert.Len(t, HashContents([]byte("anything")), 64)
}

// -- AccessKeyIDPrefix --------------------------------------------

func TestAccessKeyIDPrefix(t *testing.T) {
	assert.Equal(t, "AKIA", AccessKeyIDPrefix("AKIAIOSFODNN7EXAMPLE"))
	assert.Equal(t, "ASIA", AccessKeyIDPrefix("ASIAIOSFODNN7EXAMPLE"))
	assert.Equal(t, "AKIA", AccessKeyIDPrefix("akiaiosfodnn7example")) // uppercased
	assert.Equal(t, "AKIA", AccessKeyIDPrefix("  AKIAxyz  "))          // trimmed first
	assert.Equal(t, "", AccessKeyIDPrefix(""))                         // empty
	assert.Equal(t, "", AccessKeyIDPrefix("AKI"))                      // < 4 chars
	assert.Equal(t, "", AccessKeyIDPrefix("  AK  "))                   // < 4 after trim
}

// -- AnnotateSecurity ---------------------------------------------

func TestAnnotateSecurity(t *testing.T) {
	t.Run("world+group readable static key = risk", func(t *testing.T) {
		p := Profile{FileMode: 0o644, HasAccessKey: true}
		AnnotateSecurity(&p)
		assert.True(t, p.IsWorldReadable)
		assert.True(t, p.IsGroupReadable)
		assert.True(t, p.IsCredentialExposureRisk)
	})

	t.Run("group-only readable static key = risk", func(t *testing.T) {
		p := Profile{FileMode: 0o640, HasAccessKey: true}
		AnnotateSecurity(&p)
		assert.False(t, p.IsWorldReadable)
		assert.True(t, p.IsGroupReadable)
		assert.True(t, p.IsCredentialExposureRisk)
	})

	t.Run("locked-down static key = no risk", func(t *testing.T) {
		p := Profile{FileMode: 0o600, HasAccessKey: true}
		AnnotateSecurity(&p)
		assert.False(t, p.IsWorldReadable)
		assert.False(t, p.IsGroupReadable)
		assert.False(t, p.IsCredentialExposureRisk)
	})

	t.Run("role without MFA = risk regardless of mode", func(t *testing.T) {
		p := Profile{FileMode: 0o600, HasRoleARN: true, HasMFASerial: false}
		AnnotateSecurity(&p)
		assert.True(t, p.IsCredentialExposureRisk)
	})

	t.Run("role with MFA and locked file = no risk", func(t *testing.T) {
		p := Profile{FileMode: 0o600, HasRoleARN: true, HasMFASerial: true}
		AnnotateSecurity(&p)
		assert.False(t, p.IsCredentialExposureRisk)
	})

	t.Run("zero mode leaves readability booleans false", func(t *testing.T) {
		p := Profile{FileMode: 0, HasAccessKey: true}
		AnnotateSecurity(&p)
		assert.False(t, p.IsWorldReadable)
		assert.False(t, p.IsGroupReadable)
		assert.False(t, p.IsCredentialExposureRisk)
	})

	t.Run("world-readable but no access key and no role = no risk", func(t *testing.T) {
		p := Profile{FileMode: 0o644, HasSecretAccessKey: true}
		AnnotateSecurity(&p)
		assert.True(t, p.IsWorldReadable)
		assert.False(t, p.IsCredentialExposureRisk)
	})
}

// -- SortProfiles -------------------------------------------------

func TestSortProfiles(t *testing.T) {
	ps := []Profile{
		{FilePath: "/b", ProfileName: "a"},
		{FilePath: "/a", ProfileName: "z"},
		{FilePath: "/a", ProfileName: "a"},
	}
	SortProfiles(ps)
	assert.Equal(t, "/a", ps[0].FilePath)
	assert.Equal(t, "a", ps[0].ProfileName)
	assert.Equal(t, "/a", ps[1].FilePath)
	assert.Equal(t, "z", ps[1].ProfileName)
	assert.Equal(t, "/b", ps[2].FilePath)
}

// -- isSystemPseudoProfile ----------------------------------------

func TestIsSystemPseudoProfile(t *testing.T) {
	for _, n := range []string{"Public", "public", "Default", "Default User", "All Users", "all users"} {
		assert.Truef(t, isSystemPseudoProfile(n), "expected pseudo: %q", n)
	}
	assert.False(t, isSystemPseudoProfile("alice"))
	assert.False(t, isSystemPseudoProfile(""))
}

// -- ParseFile ----------------------------------------------------

func TestParseFileEmpty(t *testing.T) {
	assert.Empty(t, ParseFile(nil, FileCredentials))
	assert.Empty(t, ParseFile([]byte{}, FileCredentials))
}

func TestParseFileCredentials(t *testing.T) {
	body := []byte("; leading comment\n" +
		"# hash comment\n" +
		"orphan = ignored-before-section\n" +
		"[default]\n" +
		"aws_access_key_id = AKIAIOSFODNN7EXAMPLE\n" +
		"aws_secret_access_key = wJalrXUtsecret\n" +
		"\n" +
		"[staging]\n" +
		"aws_access_key_id=ASIAIOSFODNN7EXAMPLE\n" +
		"aws_session_token = FQoGZXsessiontoken\n" +
		"malformed-line-no-equals\n" +
		"=novalue\n" +
		"[secretonly]\n" +
		"aws_secret_access_key = onlysecret\n")

	got := ParseFile(body, FileCredentials)
	require.Len(t, got, 3)

	assert.Equal(t, "default", got[0].ProfileName)
	assert.Equal(t, FileCredentials, got[0].FileKind)
	assert.True(t, got[0].HasAccessKey)
	assert.Equal(t, "AKIA", got[0].AccessKeyIDFingerprint)
	assert.True(t, got[0].HasSecretAccessKey)
	assert.False(t, got[0].HasSessionToken)

	assert.Equal(t, "staging", got[1].ProfileName)
	assert.Equal(t, "ASIA", got[1].AccessKeyIDFingerprint)
	assert.True(t, got[1].HasSessionToken)

	assert.Equal(t, "secretonly", got[2].ProfileName)
	assert.False(t, got[2].HasAccessKey)
	assert.True(t, got[2].HasSecretAccessKey)
}

func TestParseFileConfigStripsProfilePrefix(t *testing.T) {
	body := []byte("[default]\n" +
		"region = us-east-1\n" +
		"output = json\n" +
		"\n" +
		"[profile prod]\n" +
		"role_arn = arn:aws:iam::123456789012:role/Prod\n" +
		"mfa_serial = arn:aws:iam::123456789012:mfa/alice\n" +
		"source_profile = default\n" +
		"region = us-west-2\n" +
		"\n" +
		"[profile ssoacct]\n" +
		"sso_account_id = 111122223333\n" +
		"sso_role_name = AdminRole\n" +
		"sso_start_url = https://corp.awsapps.com/start\n" +
		"sso_region = us-east-1\n")

	got := ParseFile(body, FileConfig)
	require.Len(t, got, 3)

	assert.Equal(t, "default", got[0].ProfileName)
	assert.Equal(t, "us-east-1", got[0].Region)
	assert.Equal(t, "json", got[0].Output)

	prod := got[1]
	assert.Equal(t, "prod", prod.ProfileName) // "profile " prefix stripped
	assert.Equal(t, "arn:aws:iam::123456789012:role/Prod", prod.RoleARN)
	assert.True(t, prod.HasRoleARN)
	assert.Equal(t, "arn:aws:iam::123456789012:mfa/alice", prod.MFASerial)
	assert.True(t, prod.HasMFASerial)
	assert.Equal(t, "default", prod.SourceProfile)
	assert.Equal(t, "us-west-2", prod.Region)

	sso := got[2]
	assert.Equal(t, "ssoacct", sso.ProfileName)
	assert.Equal(t, "111122223333", sso.SSOAccountID)
	assert.Equal(t, "AdminRole", sso.SSORoleName)
	assert.True(t, sso.HasSSO)
}

func TestParseFileStripsBOM(t *testing.T) {
	body := append([]byte{0xEF, 0xBB, 0xBF}, []byte("[default]\nregion = eu-west-1\n")...)
	got := ParseFile(body, FileConfig)
	require.Len(t, got, 1)
	assert.Equal(t, "default", got[0].ProfileName)
	assert.Equal(t, "eu-west-1", got[0].Region)
}

func TestParseFileEmptyAccessKeyValue(t *testing.T) {
	// A present-but-empty access key must NOT flip HasAccessKey.
	got := ParseFile([]byte("[default]\naws_access_key_id = \n"), FileCredentials)
	require.Len(t, got, 1)
	assert.False(t, got[0].HasAccessKey)
	assert.Equal(t, "", got[0].AccessKeyIDFingerprint)
}

// -- applyKey (direct routing) ------------------------------------

func TestApplyKey(t *testing.T) {
	p := &Profile{}
	applyKey(p, "AWS_ACCESS_KEY_ID", "AKIAEXAMPLE1234") // case-insensitive key
	applyKey(p, "aws_secret_access_key", "s")
	applyKey(p, "aws_session_token", "t")
	applyKey(p, "region", "ap-south-1")
	applyKey(p, "output", "text")
	applyKey(p, "source_profile", "base")
	applyKey(p, "role_arn", "arn:role")
	applyKey(p, "mfa_serial", "arn:mfa")
	applyKey(p, "sso_account_id", "999")
	applyKey(p, "sso_role_name", "Reader")
	applyKey(p, "unknown_vendor_key", "whatever") // flows past, no effect

	assert.True(t, p.HasAccessKey)
	assert.Equal(t, "AKIA", p.AccessKeyIDFingerprint)
	assert.True(t, p.HasSecretAccessKey)
	assert.True(t, p.HasSessionToken)
	assert.Equal(t, "ap-south-1", p.Region)
	assert.Equal(t, "text", p.Output)
	assert.Equal(t, "base", p.SourceProfile)
	assert.Equal(t, "arn:role", p.RoleARN)
	assert.True(t, p.HasRoleARN)
	assert.Equal(t, "arn:mfa", p.MFASerial)
	assert.True(t, p.HasMFASerial)
	assert.Equal(t, "999", p.SSOAccountID)
	assert.Equal(t, "Reader", p.SSORoleName)
	assert.True(t, p.HasSSO)
}

func TestSplitKV(t *testing.T) {
	k, v, ok := splitKV("region = us-east-1")
	assert.True(t, ok)
	assert.Equal(t, "region", k)
	assert.Equal(t, "us-east-1", v)

	k, v, ok = splitKV("key=value")
	assert.True(t, ok)
	assert.Equal(t, "key", k)
	assert.Equal(t, "value", v)

	_, _, ok = splitKV("no-equals-here")
	assert.False(t, ok)

	_, _, ok = splitKV("=orphan") // '=' at index 0 → not ok
	assert.False(t, ok)
}

func TestNormalizeProfileName(t *testing.T) {
	assert.Equal(t, "prod", normalizeProfileName("profile prod"))
	assert.Equal(t, "prod", normalizeProfileName("PROFILE prod")) // case-insensitive prefix
	assert.Equal(t, "default", normalizeProfileName("default"))
	assert.Equal(t, "profileless", normalizeProfileName("profileless")) // no space → not a prefix
}

// -- fileCollector.Collect (fixture tree) -------------------------

func TestNewCollector(t *testing.T) {
	c := NewCollector()
	require.NotNil(t, c)
	assert.Equal(t, "winawscreds", c.Name())
}

func writeFile(t *testing.T, path, body string) {
	t.Helper()
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
	require.NoError(t, os.WriteFile(path, []byte(body), 0o644))
}

func TestCollectPerUserTree(t *testing.T) {
	base := t.TempDir()
	credPath := filepath.Join(base, "alice", ".aws", "credentials")
	cfgPath := filepath.Join(base, "alice", ".aws", "config")
	writeFile(t, credPath,
		"[default]\n"+
			"aws_access_key_id = AKIAIOSFODNN7EXAMPLE\n"+
			"aws_secret_access_key = secret\n")
	writeFile(t, cfgPath,
		"[profile prod]\n"+
			"role_arn = arn:aws:iam::1:role/Prod\n")

	// System pseudo-profile + dot dir + a plain file are all skipped.
	writeFile(t, filepath.Join(base, "Public", ".aws", "credentials"),
		"[default]\naws_access_key_id = AKIAPUBLIC0000000000\n")
	require.NoError(t, os.MkdirAll(filepath.Join(base, ".hidden", ".aws"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(base, "notadir.txt"), []byte("x"), 0o644))

	c := &fileCollector{
		usersBases: []string{base},
		getenv:     func(string) string { return "" },
		readFile:   os.ReadFile,
		readDir:    os.ReadDir,
		statFile:   os.Stat,
	}
	got, err := c.Collect(context.Background())
	require.NoError(t, err)
	require.Len(t, got, 2) // alice default (creds) + alice prod (config); Public skipped

	// Sorted by file path then profile name → config sorts before credentials.
	assert.Equal(t, cfgPath, got[0].FilePath)
	assert.Equal(t, "prod", got[0].ProfileName)
	assert.Equal(t, "alice", got[0].UserProfile)
	assert.True(t, got[0].HasRoleARN)
	assert.True(t, got[0].IsCredentialExposureRisk) // role w/o MFA

	assert.Equal(t, credPath, got[1].FilePath)
	assert.Equal(t, "default", got[1].ProfileName)
	assert.NotEmpty(t, got[1].FileHash)
	assert.Equal(t, 0o644, got[1].FileMode)
	if runtime.GOOS != "windows" {
		assert.Equal(t, os.Getuid(), got[1].FileOwnerUID)
	}
}

func TestCollectEnvVarOverrides(t *testing.T) {
	base := t.TempDir()
	sharedCreds := filepath.Join(base, "shared-creds")
	altConfig := filepath.Join(base, "alt-config")
	require.NoError(t, os.WriteFile(sharedCreds,
		[]byte("[default]\naws_access_key_id = AKIAENVEXAMPLE00000\n"), 0o644))
	require.NoError(t, os.WriteFile(altConfig,
		[]byte("[profile ci]\nregion = us-east-2\n"), 0o644))

	env := map[string]string{
		"AWS_SHARED_CREDENTIALS_FILE": sharedCreds,
		"AWS_CONFIG_FILE":             altConfig,
	}
	c := &fileCollector{
		usersBases: []string{filepath.Join(base, "no-such-users-dir")},
		getenv:     func(k string) string { return env[k] },
		readFile:   os.ReadFile,
		readDir:    os.ReadDir,
		statFile:   os.Stat,
	}
	got, err := c.Collect(context.Background())
	require.NoError(t, err)
	require.Len(t, got, 2)

	by := map[string]Profile{}
	for _, p := range got {
		by[p.FilePath] = p
	}
	assert.Equal(t, FileCredentials, by[sharedCreds].FileKind)
	assert.True(t, by[sharedCreds].HasAccessKey)
	assert.Equal(t, "", by[sharedCreds].UserProfile) // env override has no user
	assert.Equal(t, FileConfig, by[altConfig].FileKind)
	assert.Equal(t, "us-east-2", by[altConfig].Region)
}

func TestCollectMissingBasesOK(t *testing.T) {
	c := &fileCollector{
		usersBases: []string{filepath.Join(t.TempDir(), "does-not-exist")},
		getenv:     func(string) string { return "" },
		readFile:   os.ReadFile,
		readDir:    os.ReadDir,
		statFile:   os.Stat,
	}
	got, err := c.Collect(context.Background())
	require.NoError(t, err)
	assert.Empty(t, got)
}

func TestCollectSkipsUnparseableAndMissingFiles(t *testing.T) {
	base := t.TempDir()
	// A .aws dir whose credentials file has no sections (all comments) → skipped.
	writeFile(t, filepath.Join(base, "bob", ".aws", "credentials"),
		"# nothing but a comment\n")
	c := &fileCollector{
		usersBases: []string{base},
		getenv:     func(string) string { return "" },
		readFile:   os.ReadFile,
		readDir:    os.ReadDir,
		statFile:   os.Stat,
	}
	got, err := c.Collect(context.Background())
	require.NoError(t, err)
	assert.Empty(t, got)
}

// Stress: a single env file carrying more than MaxProfiles sections is
// capped at MaxProfiles by harvestFile's early return.
func TestCollectCapsAtMaxProfiles(t *testing.T) {
	base := t.TempDir()
	var sb strings.Builder
	for i := 0; i < MaxProfiles+50; i++ {
		sb.WriteString("[p")
		sb.WriteString(strconv.Itoa(i))
		sb.WriteString("]\nregion = us-east-1\n")
	}
	credFile := filepath.Join(base, "creds")
	require.NoError(t, os.WriteFile(credFile, []byte(sb.String()), 0o644))

	env := map[string]string{"AWS_SHARED_CREDENTIALS_FILE": credFile}
	c := &fileCollector{
		usersBases: []string{filepath.Join(base, "none")},
		getenv:     func(k string) string { return env[k] },
		readFile:   os.ReadFile,
		readDir:    os.ReadDir,
		statFile:   os.Stat,
	}
	got, err := c.Collect(context.Background())
	require.NoError(t, err)
	assert.Len(t, got, MaxProfiles)
}
