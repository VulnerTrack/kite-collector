package windowsiis

import (
	"strings"
	"testing"
)

func TestPinnedSourceStrings(t *testing.T) {
	pairs := []struct{ got, want string }{
		{string(SourcePowerShellIISAdmin), "powershell-iisadmin"},
		{string(SourcePowerShellWebAdmin), "powershell-webadmin"},
		{string(SourceUnknown), "unknown"},
	}
	for _, p := range pairs {
		if p.got != p.want {
			t.Fatalf("source drift: got %q want %q", p.got, p.want)
		}
	}
}

func TestIsPrivilegedIdentity(t *testing.T) {
	if !IsPrivilegedIdentity("LocalSystem") {
		t.Fatal("LocalSystem must flag")
	}
	if !IsPrivilegedIdentity("localsystem") {
		t.Fatal("case-insensitive")
	}
	for _, s := range []string{
		"ApplicationPoolIdentity", "NetworkService",
		"LocalService", "SpecificUser", "",
	} {
		if IsPrivilegedIdentity(s) {
			t.Fatalf("%q must NOT flag", s)
		}
	}
}

func TestIsHTTPProtocol(t *testing.T) {
	if !IsHTTPProtocol("http") {
		t.Fatal("http")
	}
	if !IsHTTPProtocol("HTTP") {
		t.Fatal("HTTP case")
	}
	for _, p := range []string{"https", "ftp", "net.tcp", ""} {
		if IsHTTPProtocol(p) {
			t.Fatalf("%q must NOT flag", p)
		}
	}
}

func TestIsHTTPSProtocol(t *testing.T) {
	if !IsHTTPSProtocol("https") {
		t.Fatal("https")
	}
	if IsHTTPSProtocol("http") {
		t.Fatal("http must NOT")
	}
}

func TestAnnotateSiteBindingDerivation(t *testing.T) {
	s := Site{
		State: "Started",
		Bindings: []Binding{
			{Protocol: "http", Port: 80},
			{Protocol: "https", Port: 443},
		},
	}
	AnnotateSite(&s)
	if !s.HasHTTPBinding || !s.HasHTTPSBinding {
		t.Fatalf("flags: %+v", s)
	}
	if !s.IsRunning {
		t.Fatal("Started must flag running")
	}
}

func TestAnnotateSiteHTTPOnly(t *testing.T) {
	s := Site{
		State:    "Started",
		Bindings: []Binding{{Protocol: "http", Port: 80}},
	}
	AnnotateSite(&s)
	if !s.HasHTTPBinding || s.HasHTTPSBinding {
		t.Fatalf("flags: %+v", s)
	}
}

func TestAnnotateAppPoolPrivilegedAndRunning(t *testing.T) {
	p := AppPool{State: "Started", IdentityType: "LocalSystem"}
	AnnotateAppPool(&p)
	if !p.IsRunning || !p.IsPrivilegedIdentity {
		t.Fatalf("flags: %+v", p)
	}
}

func TestAnnotateAppPoolNonPrivileged(t *testing.T) {
	p := AppPool{State: "Stopped", IdentityType: "ApplicationPoolIdentity"}
	AnnotateAppPool(&p)
	if p.IsRunning || p.IsPrivilegedIdentity {
		t.Fatalf("flags: %+v", p)
	}
}

func TestEncodeBindings(t *testing.T) {
	if EncodeBindings(nil) != "[]" {
		t.Fatal("nil")
	}
	got := EncodeBindings([]Binding{{Protocol: "http", Port: 80}})
	if !strings.Contains(got, `"protocol":"http"`) {
		t.Fatalf("got %q", got)
	}
}

// -- ParsePowerShellOutput typical fixture (Default Web Site + admin) ---

func TestParsePowerShellOutputTypicalSites(t *testing.T) {
	body := []byte(`{
        "source": "powershell-iisadmin",
        "sites": [
            {
                "site_id": 1,
                "site_name": "Default Web Site",
                "state": "Started",
                "physical_path": "%SystemDrive%\\inetpub\\wwwroot",
                "app_pool_name": "DefaultAppPool",
                "enabled_protocols": "http",
                "log_directory": "%SystemDrive%\\inetpub\\logs\\LogFiles",
                "bindings": [
                    {
                        "protocol": "http",
                        "binding_information": "*:80:",
                        "ip_address": "*",
                        "port": 80,
                        "hostname": "",
                        "certificate_hash": "",
                        "certificate_store_name": ""
                    },
                    {
                        "protocol": "https",
                        "binding_information": "*:443:secure.corp.local",
                        "ip_address": "*",
                        "port": 443,
                        "hostname": "secure.corp.local",
                        "certificate_hash": "ABCDEF1234567890",
                        "certificate_store_name": "WebHosting"
                    }
                ]
            },
            {
                "site_id": 2,
                "site_name": "InternalAdmin",
                "state": "Stopped",
                "physical_path": "C:\\inetpub\\admin",
                "app_pool_name": "AdminPool",
                "enabled_protocols": "http",
                "bindings": [
                    {
                        "protocol": "http",
                        "binding_information": "127.0.0.1:8080:admin",
                        "ip_address": "127.0.0.1",
                        "port": 8080,
                        "hostname": "admin",
                        "certificate_hash": "",
                        "certificate_store_name": ""
                    }
                ]
            }
        ],
        "app_pools": [
            {
                "pool_name": "DefaultAppPool",
                "state": "Started",
                "managed_runtime_version": "v4.0",
                "managed_pipeline_mode": "Integrated",
                "identity_type": "ApplicationPoolIdentity",
                "identity_username": "",
                "enable_32bit_on_64bit": false,
                "idle_timeout_minutes": 20,
                "start_mode": "OnDemand",
                "auto_start": true
            },
            {
                "pool_name": "AdminPool",
                "state": "Stopped",
                "managed_runtime_version": "v4.0",
                "managed_pipeline_mode": "Integrated",
                "identity_type": "LocalSystem",
                "identity_username": "",
                "enable_32bit_on_64bit": true,
                "idle_timeout_minutes": 0,
                "start_mode": "AlwaysRunning",
                "auto_start": true
            }
        ]
    }`)
	got, err := ParsePowerShellOutput(body)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(got.Sites) != 2 {
		t.Fatalf("sites=%d", len(got.Sites))
	}
	if len(got.AppPools) != 2 {
		t.Fatalf("pools=%d", len(got.AppPools))
	}

	// Parser preserves input order; sort is collector-side. The
	// fixture has "Default Web Site" first.
	def := got.Sites[0]
	if def.SiteName != "Default Web Site" {
		t.Fatalf("input-order wrong: %q", def.SiteName)
	}
	if !def.IsRunning {
		t.Fatal("Default Web Site must flag running")
	}
	if !def.HasHTTPBinding || !def.HasHTTPSBinding {
		t.Fatalf("binding flags: %+v", def)
	}
	if len(def.Bindings) != 2 {
		t.Fatalf("bindings=%d", len(def.Bindings))
	}
	if def.Bindings[1].Hostname != "secure.corp.local" {
		t.Fatalf("hostname=%q", def.Bindings[1].Hostname)
	}
	if def.Bindings[1].CertHash != "ABCDEF1234567890" {
		t.Fatalf("cert_hash=%q", def.Bindings[1].CertHash)
	}
	if def.Source != SourcePowerShellIISAdmin {
		t.Fatalf("source=%q", def.Source)
	}

	admin := got.Sites[1]
	if admin.IsRunning {
		t.Fatal("Stopped state must not be running")
	}
	if !admin.HasHTTPBinding || admin.HasHTTPSBinding {
		t.Fatal("admin = http-only")
	}

	// Parser preserves input order; collector calls SortInventory.
	// Find AdminPool explicitly by name.
	var adminPool AppPool
	for _, p := range got.AppPools {
		if p.PoolName == "AdminPool" {
			adminPool = p
		}
	}
	if adminPool.PoolName == "" {
		t.Fatalf("AdminPool missing: %+v", got.AppPools)
	}
	if !adminPool.IsPrivilegedIdentity {
		t.Fatal("LocalSystem pool must flag privileged")
	}
	if adminPool.IsRunning {
		t.Fatal("Stopped pool must NOT flag running")
	}
	if !adminPool.Enable32BitOn64Bit {
		t.Fatal("32-bit flag must propagate")
	}
}

// -- ParsePowerShellOutput webadmin fallback source --------------------

func TestParsePowerShellOutputWebAdminSource(t *testing.T) {
	body := []byte(`{
        "source": "powershell-webadmin",
        "sites": [{"site_id":1,"site_name":"X","state":"Started","bindings":[]}],
        "app_pools": []
    }`)
	got, err := ParsePowerShellOutput(body)
	if err != nil {
		t.Fatal(err)
	}
	if got.Sites[0].Source != SourcePowerShellWebAdmin {
		t.Fatalf("source=%q", got.Sites[0].Source)
	}
}

// -- ParsePowerShellOutput unknown-source coercion ---------------------

func TestParsePowerShellOutputUnknownSource(t *testing.T) {
	body := []byte(`{
        "source": "garbage",
        "sites": [{"site_id":1,"site_name":"X","state":"Started","bindings":[]}],
        "app_pools": []
    }`)
	got, err := ParsePowerShellOutput(body)
	if err != nil {
		t.Fatal(err)
	}
	if got.Sites[0].Source != SourceUnknown {
		t.Fatalf("unknown source must coerce: %q", got.Sites[0].Source)
	}
}

// -- ParsePowerShellOutput singleton object unwrap ---------------------

func TestParsePowerShellOutputSingletonUnwrap(t *testing.T) {
	body := []byte(`{
        "source": "powershell-iisadmin",
        "sites": {"site_id":1,"site_name":"Solo","state":"Started","bindings":{"protocol":"http","binding_information":"*:80:","port":80}},
        "app_pools": {"pool_name":"Solo","state":"Started","identity_type":"ApplicationPoolIdentity"}
    }`)
	got, err := ParsePowerShellOutput(body)
	if err != nil {
		t.Fatalf("singleton parse: %v", err)
	}
	if len(got.Sites) != 1 || len(got.AppPools) != 1 {
		t.Fatalf("singleton unwrap broken: %+v", got)
	}
	if len(got.Sites[0].Bindings) != 1 {
		t.Fatalf("nested singleton binding unwrap broken: %+v", got.Sites[0])
	}
}

// -- ParsePowerShellOutput empty-name drop -----------------------------

func TestParsePowerShellOutputSkipEmptyNames(t *testing.T) {
	body := []byte(`{
        "source": "powershell-iisadmin",
        "sites": [
            {"site_id":1,"site_name":"","state":"Started","bindings":[]},
            {"site_id":2,"site_name":"real","state":"Started","bindings":[]}
        ],
        "app_pools": [
            {"pool_name":"","state":"Started","identity_type":"ApplicationPoolIdentity"},
            {"pool_name":"real","state":"Started","identity_type":"ApplicationPoolIdentity"}
        ]
    }`)
	got, err := ParsePowerShellOutput(body)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Sites) != 1 || got.Sites[0].SiteName != "real" {
		t.Fatalf("empty site_name must drop: %+v", got.Sites)
	}
	if len(got.AppPools) != 1 || got.AppPools[0].PoolName != "real" {
		t.Fatalf("empty pool_name must drop: %+v", got.AppPools)
	}
}

// -- error paths -----------------------------------------------------

func TestParsePowerShellOutputEmptyError(t *testing.T) {
	if _, err := ParsePowerShellOutput(nil); err == nil {
		t.Fatal("empty must error")
	}
}

func TestParsePowerShellOutputMalformedError(t *testing.T) {
	if _, err := ParsePowerShellOutput([]byte("not json")); err == nil {
		t.Fatal("malformed must error")
	}
}

// -- script shape spot-check ----------------------------------------

func TestPowerShellScriptShape(t *testing.T) {
	for _, must := range []string{
		"Get-IISSite",
		"Get-Website",
		"Get-IISAppPool",
		"WebAdministration",
		"bindings",
		"certificateHash",
		"identity_type",
	} {
		if !strings.Contains(PowerShellScript, must) {
			t.Fatalf("PowerShellScript missing %q", must)
		}
	}
}
