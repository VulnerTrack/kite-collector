package polkit

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestPinnedSourceStrings(t *testing.T) {
	pairs := []struct{ got, want string }{
		{string(SourceActionPolicy), "action-policy"},
		{string(SourceLocalRules), "local-rules"},
		{string(SourceVendorRules), "vendor-rules"},
		{string(SourceAuthorityStore), "authority-store"},
		{string(SourceUnknown), "unknown"},
	}
	for _, p := range pairs {
		if p.got != p.want {
			t.Fatalf("source drift: got %q want %q (breaks SQLite CHECK)",
				p.got, p.want)
		}
	}
}

func TestHashContentsDeterministic(t *testing.T) {
	a := HashContents([]byte("<policyconfig/>"))
	b := HashContents([]byte("<policyconfig/>"))
	if a != b || len(a) != 64 {
		t.Fatalf("a=%q b=%q", a, b)
	}
}

func TestIsCriticalAction(t *testing.T) {
	for _, a := range []string{
		"org.freedesktop.systemd1.manage-units",
		"org.freedesktop.systemd1.manage-unit-files",
		"org.freedesktop.policykit.exec",
		"org.freedesktop.udisks2.filesystem-mount",
		"org.freedesktop.NetworkManager.settings.modify.system",
		"org.libvirt.unix.manage",
	} {
		if !IsCriticalAction(a) {
			t.Fatalf("%q must be critical", a)
		}
	}
	for _, a := range []string{
		"org.gnome.controlcenter.theme",
		"com.example.benign",
		"",
	} {
		if IsCriticalAction(a) {
			t.Fatalf("%q must NOT be critical", a)
		}
	}
}

func TestIsPasswordlessSlot(t *testing.T) {
	if !IsPasswordlessSlot("yes") {
		t.Fatal("yes must flag passwordless")
	}
	if !IsPasswordlessSlot(" YES ") {
		t.Fatal("case+whitespace must flag passwordless")
	}
	for _, v := range []string{
		"no", "auth_self", "auth_self_keep",
		"auth_admin", "auth_admin_keep", "",
	} {
		if IsPasswordlessSlot(v) {
			t.Fatalf("%q must NOT flag passwordless", v)
		}
	}
}

func TestAnnotateActionPolicyCriticalPasswordless(t *testing.T) {
	r := Rule{
		ActionID:    "org.freedesktop.systemd1.manage-units",
		AllowActive: "yes",
	}
	AnnotateActionPolicy(&r)
	if !r.IsCritical || !r.IsPasswordless {
		t.Fatalf("flags: %+v", r)
	}
}

func TestAnnotateActionPolicyBenign(t *testing.T) {
	r := Rule{
		ActionID:    "org.gnome.controlcenter.theme",
		AllowActive: "auth_admin_keep",
		AllowAny:    "auth_admin",
	}
	AnnotateActionPolicy(&r)
	if r.IsCritical {
		t.Fatal("non-critical action")
	}
	if r.IsPasswordless {
		t.Fatal("auth_admin_keep must NOT be passwordless")
	}
}

func TestAnnotateJSRuleGrantsYESPasswordless(t *testing.T) {
	r := Rule{
		ActionID:  "org.libvirt.unix.manage",
		GrantsYES: true,
	}
	AnnotateJSRule(&r)
	if !r.IsCritical || !r.IsPasswordless {
		t.Fatalf("YES on critical must flag passwordless: %+v", r)
	}
}

func TestAnnotateJSRuleNoYESNoPasswordless(t *testing.T) {
	r := Rule{
		ActionID:  "org.libvirt.unix.manage",
		GrantsYES: false,
	}
	AnnotateJSRule(&r)
	if r.IsPasswordless {
		t.Fatal("no YES → not passwordless")
	}
}

// -- ParseActionPolicy XML --------------------------------------------

func TestParseActionPolicyTypical(t *testing.T) {
	body := []byte(`<?xml version="1.0" encoding="UTF-8"?>
<policyconfig>
  <action id="org.freedesktop.policykit.exec">
    <description>Run a program as another user</description>
    <defaults>
      <allow_any>auth_admin</allow_any>
      <allow_inactive>auth_admin</allow_inactive>
      <allow_active>auth_admin</allow_active>
    </defaults>
  </action>
  <action id="org.freedesktop.systemd1.manage-units">
    <description>Manage system services</description>
    <defaults>
      <allow_any>auth_admin_keep</allow_any>
      <allow_inactive>auth_admin_keep</allow_inactive>
      <allow_active>yes</allow_active>
    </defaults>
  </action>
</policyconfig>`)
	got := ParseActionPolicy(body, "/usr/share/polkit-1/actions/x.policy")
	if len(got) != 2 {
		t.Fatalf("len=%d, want 2: %+v", len(got), got)
	}

	// pkexec action — critical but auth_admin not passwordless.
	pkexec := got[0]
	if pkexec.ActionID != "org.freedesktop.policykit.exec" {
		t.Fatalf("action_id=%q", pkexec.ActionID)
	}
	if !pkexec.IsCritical {
		t.Fatal("pkexec must be critical")
	}
	if pkexec.IsPasswordless {
		t.Fatal("auth_admin must NOT be passwordless")
	}

	// systemd-manage-units with allow_active=yes → finding.
	mu := got[1]
	if !mu.IsCritical {
		t.Fatal("systemd1.manage-units must be critical")
	}
	if !mu.IsPasswordless {
		t.Fatal("allow_active=yes must flag passwordless")
	}
	if mu.AllowActive != "yes" {
		t.Fatalf("AllowActive=%q", mu.AllowActive)
	}
	if mu.FileHash == "" {
		t.Fatal("file_hash missing")
	}
}

func TestParseActionPolicyMalformedXMLEmpty(t *testing.T) {
	body := []byte("<not-actually-xml>")
	if got := ParseActionPolicy(body, "x.policy"); len(got) != 0 {
		t.Fatalf("malformed xml should yield empty, got %d", len(got))
	}
}

// -- ParseJSRules -----------------------------------------------------

func TestParseJSRulesGrantYESOnCritical(t *testing.T) {
	body := []byte(`polkit.addRule(function(action, subject) {
    if (action.id == "org.libvirt.unix.manage" &&
        subject.isInGroup("libvirt")) {
        return polkit.Result.YES;
    }
});
`)
	got := ParseJSRules(body, "/etc/polkit-1/rules.d/10-libvirt.rules", SourceLocalRules)
	if len(got) != 1 {
		t.Fatalf("len=%d", len(got))
	}
	r := got[0]
	if r.ActionID != "org.libvirt.unix.manage" {
		t.Fatalf("action_id=%q", r.ActionID)
	}
	if !r.GrantsYES {
		t.Fatal("must flag GrantsYES")
	}
	if !r.IsCritical {
		t.Fatal("libvirt manage must flag critical")
	}
	if !r.IsPasswordless {
		t.Fatal("YES on critical must flag passwordless")
	}
}

func TestParseJSRulesMultipleActionIDs(t *testing.T) {
	body := []byte(`polkit.addRule(function(action, subject) {
    if (action.id == "org.freedesktop.systemd1.manage-units" ||
        action.id == "org.freedesktop.systemd1.manage-unit-files") {
        return polkit.Result.YES;
    }
});
`)
	got := ParseJSRules(body, "x.rules", SourceLocalRules)
	if len(got) != 2 {
		t.Fatalf("len=%d, want 2 (both action.ids): %+v", len(got), got)
	}
	for _, r := range got {
		if !r.IsPasswordless || !r.IsCritical {
			t.Fatalf("each row must flag: %+v", r)
		}
	}
}

func TestParseJSRulesNoYESNoPasswordless(t *testing.T) {
	body := []byte(`polkit.addRule(function(action, subject) {
    if (action.id == "org.libvirt.unix.manage") {
        return polkit.Result.AUTH_ADMIN;
    }
});
`)
	got := ParseJSRules(body, "x.rules", SourceLocalRules)
	if len(got) != 1 {
		t.Fatalf("len=%d", len(got))
	}
	if got[0].IsPasswordless || got[0].GrantsYES {
		t.Fatalf("AUTH_ADMIN return must NOT flag: %+v", got[0])
	}
}

func TestParseJSRulesNoActionIDFallback(t *testing.T) {
	// Rule without a recognised action.id check still produces a row.
	body := []byte(`polkit.addRule(function(action, subject) {
    return polkit.Result.NO;
});
`)
	got := ParseJSRules(body, "x.rules", SourceLocalRules)
	if len(got) != 1 {
		t.Fatalf("len=%d", len(got))
	}
	if got[0].ActionID != "" {
		t.Fatalf("expected empty action_id, got %q", got[0].ActionID)
	}
	if got[0].RuleSnippet == "" {
		t.Fatal("rule snippet must be captured")
	}
}

func TestParseJSRulesIndexOfPattern(t *testing.T) {
	body := []byte(`polkit.addRule(function(action, subject) {
    if (action.id.indexOf("org.freedesktop.NetworkManager.") == 0) {
        return polkit.Result.YES;
    }
});
`)
	got := ParseJSRules(body, "x.rules", SourceLocalRules)
	if len(got) != 1 {
		t.Fatalf("len=%d", len(got))
	}
	if got[0].ActionID != "org.freedesktop.NetworkManager." {
		t.Fatalf("action_id=%q", got[0].ActionID)
	}
	if !got[0].IsCritical {
		t.Fatal("NetworkManager prefix must be critical")
	}
	if !got[0].IsPasswordless {
		t.Fatal("YES must flag passwordless")
	}
}

func TestParseJSRulesSkipsLineComments(t *testing.T) {
	body := []byte(`// allow libvirt
polkit.addRule(function(action, subject) {
    // comment inside
    if (action.id == "org.libvirt.unix.manage") {
        return polkit.Result.YES;
    }
});
`)
	got := ParseJSRules(body, "x.rules", SourceLocalRules)
	if len(got) != 1 {
		t.Fatalf("len=%d (comments must not break parsing)", len(got))
	}
	if !got[0].GrantsYES {
		t.Fatal("YES inside rule must be detected")
	}
}

// -- collector end-to-end ---------------------------------------------

func TestFileCollectorWalksAllSources(t *testing.T) {
	tmp := t.TempDir()
	actions := filepath.Join(tmp, "actions")
	local := filepath.Join(tmp, "local-rules")
	vendor := filepath.Join(tmp, "vendor-rules")
	for _, d := range []string{actions, local, vendor} {
		must(t, os.MkdirAll(d, 0o755))
	}
	mustWrite(t, filepath.Join(actions, "x.policy"),
		`<policyconfig><action id="org.freedesktop.policykit.exec"><defaults><allow_active>auth_admin</allow_active></defaults></action></policyconfig>`)
	mustWrite(t, filepath.Join(local, "10-libvirt.rules"),
		`polkit.addRule(function(action, subject) {
    if (action.id == "org.libvirt.unix.manage") return polkit.Result.YES;
});`)
	mustWrite(t, filepath.Join(vendor, "50-default.rules"),
		`polkit.addRule(function(action, subject) {
    if (action.id == "org.freedesktop.locale1.set-locale") return polkit.Result.AUTH_ADMIN;
});`)
	// Backup file — must be skipped.
	mustWrite(t, filepath.Join(local, "evil.bak"),
		`polkit.addRule(function(action) { return polkit.Result.YES; });`)

	c := &fileCollector{
		actionsDir:     actions,
		localRulesDir:  local,
		vendorRulesDir: vendor,
		readFile:       os.ReadFile,
		readDir:        os.ReadDir,
	}
	got, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	// 1 action-policy + 1 local + 1 vendor = 3.
	if len(got) != 3 {
		t.Fatalf("want 3, got %d: %+v", len(got), got)
	}
	// Confirm the libvirt rule landed as passwordless+critical.
	var libvirt Rule
	for _, r := range got {
		if r.Source == SourceLocalRules && r.ActionID == "org.libvirt.unix.manage" {
			libvirt = r
		}
	}
	if !libvirt.IsPasswordless || !libvirt.IsCritical {
		t.Fatalf("libvirt rule flags wrong: %+v", libvirt)
	}
}

func TestFileCollectorMissingPathsOK(t *testing.T) {
	c := &fileCollector{
		actionsDir:     "/nope",
		localRulesDir:  "/nope",
		vendorRulesDir: "/nope",
		readFile:       os.ReadFile,
		readDir:        os.ReadDir,
	}
	got, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("missing must not error: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("want empty, got %d", len(got))
	}
}

func TestSortRulesDeterministic(t *testing.T) {
	in := []Rule{
		{FilePath: "/etc/polkit-1/rules.d/zzz.rules", LineNo: 1},
		{FilePath: "/etc/polkit-1/rules.d/aaa.rules", LineNo: 5},
		{FilePath: "/etc/polkit-1/rules.d/aaa.rules", LineNo: 2},
	}
	SortRules(in)
	if in[0].FilePath != "/etc/polkit-1/rules.d/aaa.rules" || in[0].LineNo != 2 {
		t.Fatalf("first=%+v", in[0])
	}
	if in[2].FilePath != "/etc/polkit-1/rules.d/zzz.rules" {
		t.Fatalf("last=%+v", in[2])
	}
}

// -- helpers ----------------------------------------------------------

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func mustWrite(t *testing.T, p, body string) {
	t.Helper()
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}
