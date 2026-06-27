//go:build linux

package phpprojects

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func writeFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestLinuxSourceEnumerateClassifiesLaravelUnderWebRoot(t *testing.T) {
	root := t.TempDir()
	webRoot := filepath.Join(root, "var", "www", "html", "myapp")
	writeFile(t, filepath.Join(webRoot, "artisan"), "#!/usr/bin/env php\n<?php")
	writeFile(t, filepath.Join(webRoot, "bootstrap", "app.php"), "<?php\n$app = require ...;\nreturn $app;")
	writeFile(t, filepath.Join(webRoot, ".env"), "APP_KEY=base64:abcdef\nDB_PASSWORD=secret\n")
	// Pretend it's a git repo.
	if err := os.MkdirAll(filepath.Join(webRoot, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}

	src := NewLinuxSource([]string{filepath.Join(root, "var", "www", "html")}, filepath.Join(root, "home"))
	got, err := src.Enumerate(context.Background())
	if err != nil {
		t.Fatalf("Enumerate: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("want 1 project, got %d: %+v", len(got), got)
	}
	p := got[0]
	if p.Framework != FwLaravel {
		t.Fatalf("fw=%q", p.Framework)
	}
	if !p.HasDotenv || !p.HasDotenvSecret {
		t.Fatalf("dotenv flags wrong: %+v", p)
	}
	if !p.IsGitRepo {
		t.Fatal(".git presence missed")
	}
	if !p.IsUnderWebRoot {
		t.Fatalf("not flagged under web root: root=%q webRoots=%v", p.ProjectRoot, WebRootPrefixes)
	}
}

func TestLinuxSourceClassifiesPhpMyAdminUnderUsrShare(t *testing.T) {
	root := t.TempDir()
	pmaRoot := filepath.Join(root, "usr", "share", "phpmyadmin")
	writeFile(t, filepath.Join(pmaRoot, "libraries", "classes", "Config.php"), "<?php\nclass Config {}")

	src := NewLinuxSource([]string{pmaRoot}, filepath.Join(root, "home"))
	got, err := src.Enumerate(context.Background())
	if err != nil {
		t.Fatalf("Enumerate: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("want 1, got %d", len(got))
	}
	if got[0].Framework != FwPhpMyAdmin {
		t.Fatalf("fw=%q", got[0].Framework)
	}
}

func TestLinuxSourceDescendsIntoSubdirsToFindProjects(t *testing.T) {
	root := t.TempDir()
	// Two projects at depth 2 under the search root.
	site1 := filepath.Join(root, "var", "www", "html", "site1")
	site2 := filepath.Join(root, "var", "www", "html", "site2")
	writeFile(t, filepath.Join(site1, "wp-config.php"), "<?php define('DB_NAME','x');")
	writeFile(t, filepath.Join(site2, "artisan"), "<?php")
	writeFile(t, filepath.Join(site2, "bootstrap", "app.php"), "<?php // laravel")

	src := NewLinuxSource([]string{filepath.Join(root, "var", "www", "html")}, filepath.Join(root, "home"))
	got, err := src.Enumerate(context.Background())
	if err != nil {
		t.Fatalf("Enumerate: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("want 2 projects, got %d: %+v", len(got), got)
	}
}

func TestLinuxSourcePerUserPublicHtml(t *testing.T) {
	root := t.TempDir()
	userHome := filepath.Join(root, "home", "alice", "public_html", "blog")
	writeFile(t, filepath.Join(userHome, "wp-config.php"), "<?php")

	src := NewLinuxSource(nil, filepath.Join(root, "home"))
	got, err := src.Enumerate(context.Background())
	if err != nil {
		t.Fatalf("Enumerate: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("want 1, got %d", len(got))
	}
	if got[0].UserProfile != "alice" {
		t.Fatalf("user=%q", got[0].UserProfile)
	}
}

func TestLinuxSourceMissingRootReturnsEmpty(t *testing.T) {
	src := NewLinuxSource([]string{filepath.Join(t.TempDir(), "nope")}, "")
	got, err := src.Enumerate(context.Background())
	if err != nil {
		t.Fatalf("missing must not error: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("want empty, got %d", len(got))
	}
}

func TestLinuxSourceDoesNotDescendIntoMatchedProject(t *testing.T) {
	// If we match a project at /var/www/html/parent, we must NOT
	// then descend into /var/www/html/parent/{some-subdir} hunting
	// for nested projects — one project per subtree.
	root := t.TempDir()
	parent := filepath.Join(root, "var", "www", "html", "wordpress-instance")
	writeFile(t, filepath.Join(parent, "wp-config.php"), "<?php")
	// Nested look-alike that would normally classify but must NOT
	// be returned because the parent already matched.
	nested := filepath.Join(parent, "subdir", "innersite")
	writeFile(t, filepath.Join(nested, "wp-config.php"), "<?php")

	src := NewLinuxSource([]string{filepath.Join(root, "var", "www", "html")}, "")
	got, err := src.Enumerate(context.Background())
	if err != nil {
		t.Fatalf("Enumerate: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("want 1 project (one-per-subtree), got %d: %+v", len(got), got)
	}
}

func TestHasSecretShapedKey(t *testing.T) {
	cases := map[string]bool{
		"DB_PASSWORD=secret\n":          true,
		"APP_KEY=base64:abc\n":          true,
		"STRIPE_SECRET_KEY=sk_test_x\n": true,
		"AWS_ACCESS_KEY=AKIA...\n":      true,
		"NOTHING_INTERESTING=value\n":   false,
		"":                              false,
		"# DB_PASSWORD=secret":          false, // commented out
		"DB_PASSWORD=\n":                false, // no value
	}
	for body, want := range cases {
		got := HasSecretShapedKey([]byte(body))
		if got != want {
			t.Fatalf("HasSecretShapedKey(%q)=%v want %v", body, got, want)
		}
	}
}

func TestPathIsUnderWebRoot(t *testing.T) {
	cases := map[string]bool{
		"/var/www/html/site":           true,
		"/srv/www/myapp":               true,
		"/usr/share/nginx/html/x":      true,
		"/home/alice/public_html/blog": true,
		"/home/alice/www/site":         true,
		"/home/alice/projects/x":       false,
		"/opt/something":               false,
		"/tmp/scratch":                 false,
	}
	for in, want := range cases {
		got := pathIsUnderWebRoot(in)
		if got != want {
			t.Fatalf("pathIsUnderWebRoot(%q)=%v want %v", in, got, want)
		}
	}
}

func TestIsSkipDir(t *testing.T) {
	skip := []string{
		".git", "node_modules", "vendor", ".cache", "build",
		".vscode", ".env.d",
	}
	for _, s := range skip {
		if !isSkipDir(s) {
			t.Fatalf("should skip: %q", s)
		}
	}
	keep := []string{"src", "app", "config", "public", "wp-content"}
	for _, k := range keep {
		if isSkipDir(k) {
			t.Fatalf("should NOT skip: %q", k)
		}
	}
}

func TestCollectorEndToEndOnLinuxSource(t *testing.T) {
	root := t.TempDir()
	// Laravel under web root + .env with secret + outdated version.
	site := filepath.Join(root, "var", "www", "html", "legacyapp")
	writeFile(t, filepath.Join(site, "artisan"), "<?php")
	writeFile(t, filepath.Join(site, "bootstrap", "app.php"), "<?php")
	writeFile(t, filepath.Join(site, ".env"), "DB_PASSWORD=hunter2\n")
	// Force the env file world-readable so the credential-exposure
	// risk fires regardless of secret shape.
	if err := os.Chmod(filepath.Join(site, ".env"), 0o644); err != nil {
		t.Fatal(err)
	}

	src := NewLinuxSource([]string{filepath.Join(root, "var", "www", "html")}, "")
	got, err := NewCollectorWith(src).Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("len=%d", len(got))
	}
	p := got[0]
	if p.Framework != FwLaravel {
		t.Fatalf("fw=%q", p.Framework)
	}
	if !p.IsCredentialExposureRisk {
		t.Fatalf("credential exposure risk missing (dotenv with secret): %+v", p)
	}
}
