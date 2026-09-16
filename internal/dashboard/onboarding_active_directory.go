package dashboard

import (
	"context"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/vulnertrack/kite-collector/internal/config"
	"github.com/vulnertrack/kite-collector/internal/scan"
	"github.com/vulnertrack/kite-collector/internal/secretstore"
)

const (
	ldapPasswordEnv    = "KITE_LDAP_BIND_PASSWORD" // #nosec G101 -- environment variable name, not a credential value
	ldapPasswordSecret = "kite/integrations/active-directory/password"
)

func hydrateIntegrationSecrets(deps onboardingDeps) {
	if deps.SecretStore == nil {
		return
	}
	// One-time compatibility migration: deployments that previously injected
	// the LDAP password through an environment variable are moved into the
	// secure backend at startup. The environment value remains available to
	// the current process because existing connectors resolve *_env lazily.
	if legacy := os.Getenv(ldapPasswordEnv); legacy != "" {
		if _, err := deps.SecretStore.Get(ldapPasswordSecret); errors.Is(err, secretstore.ErrNotFound) {
			if putErr := deps.SecretStore.Put(ldapPasswordSecret, []byte(legacy)); putErr != nil && deps.Logger != nil {
				deps.Logger.Warn("could not migrate Active Directory credential", "backend", deps.SecretStore.Backend(), "error", putErr)
			}
		}
		return
	}
	value, err := deps.SecretStore.Get(ldapPasswordSecret)
	if err != nil {
		if !errors.Is(err, secretstore.ErrNotFound) && deps.Logger != nil {
			deps.Logger.Warn("could not load Active Directory credential", "backend", deps.SecretStore.Backend(), "error", err)
		}
		return
	}
	defer clear(value)
	if err := os.Setenv(ldapPasswordEnv, string(value)); err != nil && deps.Logger != nil {
		deps.Logger.Warn("could not activate Active Directory credential", "error", err)
	}
}

// onboardingServiceAdapter is the extension point for credentialed services
// discovered during onboarding. Adding a service does not change the base
// Install → Connect → Stream flow; it registers a detector and setup fragment
// here. The first adapter is LDAP/Active Directory.
type onboardingServiceAdapter struct {
	Key         string
	SourceKey   string
	Label       string
	Description string
	FragmentURL string
}

type onboardingServicesView struct {
	Services []onboardingServiceView
}

type onboardingServiceView struct {
	onboardingServiceAdapter
	Configured bool
	Available  bool
}

type integrationAPIView struct {
	Key              string `json:"key"`
	Name             string `json:"name"`
	Description      string `json:"description"`
	Account          string `json:"account,omitempty"`
	DomainController string `json:"domain_controller,omitempty"`
	BaseDN           string `json:"base_dn,omitempty"`
	TLSMode          string `json:"tls_mode,omitempty"`
	Status           string `json:"status"`
}

var onboardingServiceAdapters = []onboardingServiceAdapter{
	{Key: "ldap", SourceKey: "ldap", Label: "Active Directory", Description: "Users, computers, groups, policies, and relationships through LDAP.", FragmentURL: "/fragments/active-directory-setup"},
}

var onboardingServicesTmpl = template.Must(template.New("services-setup").Parse(`
<div class="service-setup-list integration-catalog">
  {{range .Services}}
    <section class="service-setup-card integration-card{{if not .Available}} integration-card-unavailable{{end}}">
      <div class="service-setup-head">
        <div class="integration-identity">
          <span class="integration-logo" aria-hidden="true">AD</span>
          <div><strong>{{.Label}}</strong><p class="muted small">{{.Description}}</p></div>
        </div>
        <span class="badge {{if .Configured}}badge-green{{else if .Available}}badge-blue{{else}}badge-gray{{end}}">{{if .Configured}}Configured{{else if .Available}}Integration available{{else}}Integration unavailable{{end}}</span>
      </div>
      <div class="integration-card-actions">
        {{if .Configured}}
          <button class="btn btn-outline" type="button" data-integration-key="{{.Key}}" disabled>Connected</button>
        {{else if .Available}}
          <button class="btn integration-settings-toggle" type="button"
                  data-integration-key="{{.Key}}"
                  data-fragment-url="{{.FragmentURL}}"
                  data-target-selector="#{{.Key}}-setup-fragment"
                  aria-controls="{{.Key}}-setup-fragment"
                  aria-expanded="false"
                  onclick="toggleIntegrationSettings(this)">Connect</button>
        {{else}}
          <button class="btn btn-outline integration-unavailable-connect" type="button" data-integration-key="{{.Key}}" data-integration="{{.Label}}" onclick="showUnavailableIntegration(this)">Connect</button>
        {{end}}
      </div>
      <div id="{{.Key}}-setup-fragment"></div>
    </section>
  {{end}}
</div>
<div id="integration-unavailable-modal" class="integration-modal-backdrop" hidden>
  <section class="integration-modal" role="dialog" aria-modal="true" aria-labelledby="integration-unavailable-title">
    <span class="integration-modal-icon" aria-hidden="true">!</span>
    <h2 id="integration-unavailable-title">Integration unavailable</h2>
    <p><strong id="unavailable-integration-name">This integration</strong> was not detected on this network.</p>
    <button class="btn" type="button" onclick="closeUnavailableIntegration()">Close</button>
  </section>
</div>
<script>
window.showUnavailableIntegration = function(button) {
  var modal = document.getElementById('integration-unavailable-modal');
  var name = document.getElementById('unavailable-integration-name');
  if (name) name.textContent = button.getAttribute('data-integration') || 'This integration';
  if (modal) modal.hidden = false;
};
window.closeUnavailableIntegration = function() {
  var modal = document.getElementById('integration-unavailable-modal');
  if (modal) modal.hidden = true;
};
window.toggleIntegrationSettings = function(button) {
  var target = document.querySelector(button.getAttribute('data-target-selector'));
  if (!target) return;
  var isOpen = button.getAttribute('aria-expanded') === 'true';
  if (isOpen) {
    target.innerHTML = '';
    button.setAttribute('aria-expanded', 'false');
    button.hidden = false;
    button.textContent = 'Connect';
    button.className = 'btn integration-settings-toggle';
    return;
  }
  button.setAttribute('aria-expanded', 'true');
  button.hidden = true;
  var fragmentURL = button.getAttribute('data-fragment-url');
  if (fragmentURL && window.htmx) {
    window.htmx.ajax('GET', fragmentURL, {target: target, swap: 'innerHTML'});
  }
};
window.hideIntegrationSettings = function(key) {
  var buttons = document.querySelectorAll('[data-integration-key]');
  for (var i = 0; i < buttons.length; i++) {
    if (buttons[i].getAttribute('data-integration-key') === key) {
      toggleIntegrationSettings(buttons[i]);
      break;
    }
  }
};
(function connectRequestedIntegration() {
  var currentURL = new URL(window.location.href);
  var requestedKey = currentURL.searchParams.get('connect');
  if (!requestedKey) return;
  currentURL.searchParams.delete('connect');
  window.history.replaceState(window.history.state, '', currentURL.pathname + currentURL.search + currentURL.hash);
  window.setTimeout(function() {
    var buttons = document.querySelectorAll('[data-integration-key]');
    for (var i = 0; i < buttons.length; i++) {
      if (buttons[i].getAttribute('data-integration-key') === requestedKey) {
        buttons[i].click();
        break;
      }
    }
  }, 0);
})();
</script>`))

const integrationsBody = `<div class="onboarding-layout integrations-layout">
  <header class="onb-page-hero integrations-page-hero">
    <span class="onb-page-hero-icon" aria-hidden="true">
      <svg width="26" height="26" viewBox="0 0 24 24" fill="none"><path d="M8 8V5.5a2.5 2.5 0 015 0V8m-5 8v2.5a2.5 2.5 0 005 0V16M5 12h14" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/><rect x="3" y="8" width="7" height="8" rx="2" stroke="currentColor" stroke-width="1.8"/><rect x="14" y="8" width="7" height="8" rx="2" stroke="currentColor" stroke-width="1.8"/></svg>
    </span>
    <div class="onb-page-hero-copy">
      <span class="onb-page-eyebrow">Extend discovery</span>
      <h2>Integrations</h2>
      <p>Connect additional services to enrich your inventory. Integrations are optional and can be configured at any time.</p>
    </div>
    <span class="badge badge-blue onb-page-optional">Optional</span>
  </header>
  <section class="integrations-surface" id="integrations-card">
    <div id="services-fragment" hx-get="/fragments/services-setup" hx-trigger="load" hx-swap="innerHTML">
      <div class="htmx-indicator">Detecting integrations&hellip;</div>
    </div>
  </section>
</div>`

// serveIntegrationsPage exposes credentialed service setup as a first-class
// dashboard destination. The same fragment remains in onboarding so existing
// setup flows and deep links continue to work.
func serveIntegrationsPage(w http.ResponseWriter, r *http.Request, deps onboardingDeps) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if r.Header.Get("HX-Request") == "true" {
		_, _ = io.WriteString(w, integrationsBody)
		return
	}

	var buf strings.Builder
	if err := renderIndexPage(&buf, "integrations", func(fragBuf io.Writer) error {
		if _, err := io.WriteString(fragBuf, integrationsBody); err != nil {
			return fmt.Errorf("write integrations body: %w", err)
		}
		return nil
	}); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	_, _ = io.WriteString(w, buf.String())
}

func renderDiscoveredServicesSetup(w io.Writer, ctx context.Context, deps onboardingDeps) error {
	view := onboardingServicesView{}
	for _, adapter := range onboardingServiceAdapters {
		configured := integrationConfigured(ctx, deps, adapter)
		view.Services = append(view.Services, onboardingServiceView{
			onboardingServiceAdapter: adapter,
			Configured:               configured,
			Available:                configured || integrationDetected(ctx, deps, adapter),
		})
	}
	if err := onboardingServicesTmpl.Execute(w, view); err != nil {
		return fmt.Errorf("render onboarding services: %w", err)
	}
	return nil
}

func discoveredIntegrationsAPI(ctx context.Context, deps onboardingDeps) []integrationAPIView {
	out := make([]integrationAPIView, 0, len(onboardingServiceAdapters))
	for _, adapter := range onboardingServiceAdapters {
		item := integrationAPIView{Key: adapter.Key, Name: adapter.Label, Description: adapter.Description, Status: "unavailable"}
		if integrationConfigured(ctx, deps, adapter) {
			item.Status = "configured"
		} else if integrationDetected(ctx, deps, adapter) {
			item.Status = "detected"
		}
		if adapter.Key == "ldap" {
			defaults := activeDirectorySetupDefaults(deps.BaseConfig)
			item.Account, item.DomainController, item.BaseDN, item.TLSMode = defaults.BindDN, defaults.DomainController, defaults.BaseDN, defaults.TLSMode
		}
		out = append(out, item)
	}
	return out
}

func servicesOnboardingComplete(ctx context.Context, deps onboardingDeps) bool {
	for _, adapter := range onboardingServiceAdapters {
		if adapter.Key == "ldap" && !directoryOnboardingComplete(ctx, deps) {
			return false
		}
	}
	return true
}

func hasAvailableOnboardingServices(ctx context.Context, deps onboardingDeps) bool {
	return len(onboardingServiceAdapters) > 0
}

func integrationConfigured(ctx context.Context, deps onboardingDeps, adapter onboardingServiceAdapter) bool {
	if adapter.Key == "ldap" {
		return directoryOnboardingComplete(ctx, deps)
	}
	if deps.BaseConfig == nil {
		return false
	}
	source, ok := deps.BaseConfig.Discovery.Sources[adapter.SourceKey]
	return ok && source.Enabled
}

func integrationDetected(ctx context.Context, deps onboardingDeps, adapter onboardingServiceAdapter) bool {
	if adapter.Key != "ldap" {
		return false
	}
	if directoryOnboardingComplete(ctx, deps) {
		return true
	}
	if deps.Store != nil {
		if services, err := deps.Store.ListDirectorySoftware(ctx); err == nil && len(services) > 0 {
			return true
		}
	}

	defaults := activeDirectorySetupDefaults(deps.BaseConfig)
	if strings.TrimSpace(defaults.DomainController) != "" {
		return true
	}
	if strings.TrimSpace(defaults.BaseDN) == "" && strings.TrimSpace(os.Getenv("USERDNSDOMAIN")) == "" {
		return false
	}
	lookupCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	return discoverDomainController(lookupCtx, defaults.BindDN, defaults.BaseDN) != ""
}

// startBaseOnboardingScan inventories the collector host immediately after
// enrollment while leaving credentialed service integrations opt-in. Service
// scans start from their own setup cards after credentials are validated.
func startBaseOnboardingScan(ctx context.Context, coordinator *scan.Coordinator, cfg *config.Config, logger *slog.Logger) {
	if coordinator == nil || cfg == nil {
		return
	}
	base := *cfg
	base.Discovery.Sources = make(map[string]config.SourceConfig, len(cfg.Discovery.Sources))
	for key, source := range cfg.Discovery.Sources {
		for _, adapter := range onboardingServiceAdapters {
			if adapter.FragmentURL != "" && key == adapter.SourceKey {
				source.Enabled = false
				break
			}
		}
		base.Discovery.Sources[key] = source
	}
	if _, err := coordinator.Start(ctx, scan.StartRequest{Config: &base, TriggerSource: "onboarding", TriggeredBy: "collector-enrollment"}); err != nil {
		var running *scan.AlreadyRunningError
		if !errors.As(err, &running) && logger != nil {
			logger.Warn("could not start automatic post-enrollment scan", "error", err)
		}
	}
}

type activeDirectorySetupView struct {
	DomainController string
	BaseDN           string
	BindDN           string
	TLSMode          string
	Configured       bool
	ReadOnly         bool
	Message          string
	Error            string
}

func ldapOnboardingConfigured(cfg *config.Config) bool {
	if cfg != nil {
		if ldap, ok := cfg.Discovery.Sources["ldap"]; ok && ldap.Enabled && ldap.BindDN != "" && ldap.BaseDN != "" && len(ldap.DomainControllers) > 0 && os.Getenv(ldapPasswordEnv) != "" {
			return true
		}
	}
	return os.Getenv("KITE_LDAP_DOMAIN_CONTROLLER") != "" && os.Getenv("KITE_LDAP_BASE_DN") != "" && os.Getenv("KITE_LDAP_BIND_DN") != "" && os.Getenv(ldapPasswordEnv) != ""
}

func activeDirectorySetupDefaults(cfg *config.Config) activeDirectorySetupView {
	v := activeDirectorySetupView{
		DomainController: os.Getenv("KITE_LDAP_DOMAIN_CONTROLLER"),
		BaseDN:           os.Getenv("KITE_LDAP_BASE_DN"), BindDN: os.Getenv("KITE_LDAP_BIND_DN"),
		TLSMode: os.Getenv("KITE_LDAP_TLS_MODE"), Configured: ldapOnboardingConfigured(cfg),
	}
	if v.TLSMode == "" {
		v.TLSMode = "ldaps"
	}
	if cfg != nil {
		if ldap, ok := cfg.Discovery.Sources["ldap"]; ok {
			if v.DomainController == "" && len(ldap.DomainControllers) > 0 {
				v.DomainController = ldap.DomainControllers[0]
			}
			if v.BaseDN == "" {
				v.BaseDN = ldap.BaseDN
			}
			if v.BindDN == "" {
				v.BindDN = ldap.BindDN
			}
			if os.Getenv("KITE_LDAP_TLS_MODE") == "" && ldap.TLSMode != "" {
				v.TLSMode = ldap.TLSMode
			}
		}
	}
	return v
}

var activeDirectorySetupTmpl = template.Must(template.New("ad-setup").Parse(`
{{if .Configured}}<p><span class="badge badge-green">configured</span> Active Directory is ready.</p>{{end}}
{{if .Message}}<p class="badge badge-green">{{.Message}}</p>{{end}}
{{if .Error}}<p class="enroll-error badge-red" role="alert">{{.Error}}</p>{{end}}
{{if .ReadOnly}}<p class="muted small">Scan coordinator unavailable in read-only dashboard mode.</p><button class="btn btn-outline" type="button" onclick="hideIntegrationSettings('ldap')">Hide settings</button>{{else}}
<form hx-post="/api/v1/onboarding/active-directory" hx-target="#ldap-setup-fragment" hx-swap="innerHTML" hx-disabled-elt="find button" hx-indicator="find .service-scan-indicator">
  <div class="form-grid">
    <label>Active Directory account<input name="bind_dn" required value="{{.BindDN}}" placeholder="user@example.com"></label>
    <label>Password<input type="password" name="password" {{if not .Configured}}required{{end}} autocomplete="new-password" placeholder="{{if .Configured}}Leave blank to keep current password{{else}}Active Directory password{{end}}"></label>
  </div>
  <details class="trust-panel">
    <summary>Advanced connection settings</summary>
    <p class="muted small">Optional overrides. Leave them unchanged or empty to let Kite determine the connection automatically.</p>
    <div class="form-grid ad-connection-grid">
      <label><span>Domain Controller</span><input name="domain_controller" value="{{.DomainController}}" placeholder="Automatically detected"></label>
      <label><span>Base DN</span><input name="base_dn" value="{{.BaseDN}}" placeholder="Automatically derived"></label>
      <label><span>TLS mode</span>
        <select name="tls_mode">
          <option value="" {{if eq .TLSMode ""}}selected{{end}}>Automatic</option>
          <option value="ldaps" {{if eq .TLSMode "ldaps"}}selected{{end}}>LDAPS</option>
          <option value="starttls" {{if eq .TLSMode "starttls"}}selected{{end}}>StartTLS</option>
          <option value="none" {{if eq .TLSMode "none"}}selected{{end}}>LDAP (no TLS)</option>
        </select>
      </label>
    </div>
  </details>
  <p class="muted small">Use any Active Directory account that can read directory objects. Kite accepts user@example.com, DOMAIN\user, a full DN, or a simple username when the domain is detected.</p>
  <div class="service-scan-actions">
    <button class="btn" type="submit">Save, test and scan</button>
    <button class="btn btn-outline" type="button" onclick="hideIntegrationSettings('ldap')">Hide settings</button>
    <span class="htmx-indicator service-scan-indicator muted small">Testing connection and scanning&hellip;</span>
  </div>
</form>{{end}}`))

func renderActiveDirectorySetup(w io.Writer, deps onboardingDeps, message, formError string) error {
	v := activeDirectorySetupDefaults(deps.BaseConfig)
	v.Configured = directoryOnboardingComplete(context.Background(), deps)
	v.ReadOnly = deps.Coordinator == nil || deps.BaseConfig == nil
	v.Message, v.Error = message, formError
	if err := activeDirectorySetupTmpl.Execute(w, v); err != nil {
		return fmt.Errorf("render Active Directory setup: %w", err)
	}
	return nil
}

func handleActiveDirectorySetup(w http.ResponseWriter, r *http.Request, deps onboardingDeps) {
	if deps.Coordinator == nil || deps.BaseConfig == nil {
		http.Error(w, "scan coordinator unavailable", http.StatusServiceUnavailable)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	dc, bindDN := strings.TrimSpace(r.FormValue("domain_controller")), strings.TrimSpace(r.FormValue("bind_dn"))
	baseDNOverride, tlsModeOverride := strings.TrimSpace(r.FormValue("base_dn")), strings.TrimSpace(r.FormValue("tls_mode"))
	password := r.FormValue("password")
	if bindDN == "" || (password == "" && os.Getenv(ldapPasswordEnv) == "") {
		_ = renderActiveDirectorySetup(w, deps, "", "Active Directory account and password are required.")
		return
	}
	ldap := deps.BaseConfig.Discovery.Sources["ldap"]
	baseDN := baseDNOverride
	if baseDN == "" {
		baseDN = strings.TrimSpace(os.Getenv("KITE_LDAP_BASE_DN"))
	}
	if baseDN == "" {
		baseDN = strings.TrimSpace(ldap.BaseDN)
	}
	if baseDN == "" {
		baseDN = inferBaseDN(bindDN, dc)
	}
	if dc == "" {
		dc = discoverDomainController(r.Context(), bindDN, baseDN)
	}
	if baseDN == "" {
		baseDN = inferBaseDN(bindDN, dc)
	}
	if baseDN == "" {
		_ = renderActiveDirectorySetup(w, deps, "", "Kite could not determine the directory domain. Use an account such as user@example.com or open Advanced connection settings.")
		return
	}
	if dc == "" {
		_ = renderActiveDirectorySetup(w, deps, "", "Kite could not discover a Domain Controller from DNS. Open Advanced connection settings and enter its hostname.")
		return
	}
	bindDN = normalizeADAccount(bindDN, baseDN)
	tlsMode := tlsModeOverride
	if tlsMode == "" {
		tlsMode = strings.TrimSpace(os.Getenv("KITE_LDAP_TLS_MODE"))
	}
	if tlsMode == "" {
		tlsMode = strings.TrimSpace(ldap.TLSMode)
	}
	if tlsMode == "" {
		tlsMode = "ldaps"
	}
	if tlsMode != "ldaps" && tlsMode != "starttls" && tlsMode != "none" {
		_ = renderActiveDirectorySetup(w, deps, "", "TLS mode must be Automatic, LDAPS, StartTLS, or LDAP (no TLS).")
		return
	}
	var previousSecret []byte
	secretWasPresent := false
	if deps.SecretStore != nil {
		if old, getErr := deps.SecretStore.Get(ldapPasswordSecret); getErr == nil {
			previousSecret, secretWasPresent = old, true
		}
	}
	if password != "" {
		if deps.SecretStore == nil {
			_ = renderActiveDirectorySetup(w, deps, "", "Secure credential storage is unavailable; the password was not saved.")
			return
		}
		if err := deps.SecretStore.Put(ldapPasswordSecret, []byte(password)); err != nil {
			http.Error(w, "store LDAP credential securely", http.StatusInternalServerError)
			return
		}
		if err := os.Setenv(ldapPasswordEnv, password); err != nil {
			http.Error(w, "store LDAP credential", http.StatusInternalServerError)
			return
		}
	}
	_ = os.Setenv("KITE_LDAP_DOMAIN_CONTROLLER", dc)
	_ = os.Setenv("KITE_LDAP_BASE_DN", baseDN)
	_ = os.Setenv("KITE_LDAP_BIND_DN", bindDN)
	_ = os.Setenv("KITE_LDAP_TLS_MODE", tlsMode)
	if deps.BaseConfig.Discovery.Sources == nil {
		deps.BaseConfig.Discovery.Sources = make(map[string]config.SourceConfig)
	}
	ldap.Enabled, ldap.DomainControllers, ldap.BaseDN, ldap.BindDN, ldap.TLSMode, ldap.BindPasswordEnv = true, []string{dc}, baseDN, bindDN, tlsMode, ldapPasswordEnv
	ldap.CollectUsers, ldap.CollectGroups, ldap.CollectOUs, ldap.CollectGPOs = true, true, true, true
	deps.BaseConfig.Discovery.Sources["ldap"] = ldap
	scanID, err := deps.Coordinator.Start(r.Context(), scan.StartRequest{Config: deps.BaseConfig, TriggerSource: "onboarding", TriggeredBy: "active-directory-setup"})
	if err != nil {
		var running *scan.AlreadyRunningError
		if !errors.As(err, &running) {
			restoreLDAPSecret(deps.SecretStore, previousSecret, secretWasPresent)
			_ = renderActiveDirectorySetup(w, deps, "", fmt.Sprintf("Could not start LDAP scan: %v", err))
			return
		}
		scanID = running.ActiveID
	}

	// Do not redirect while the inventory is still being written. A full-page
	// redirect rendered the AD cards and sidebar from the pre-scan snapshot,
	// leaving every count at zero until the operator manually refreshed.
	// Coordinator events are replayed, so even a very fast scan cannot race
	// this subscription.
	events, unsubscribe := deps.Coordinator.Subscribe()
	defer unsubscribe()
	timer := time.NewTimer(5 * time.Minute)
	defer timer.Stop()
	for {
		select {
		case event, open := <-events:
			if !open {
				_ = renderActiveDirectorySetup(w, deps, "", "LDAP scan status became unavailable.")
				return
			}
			if event.ScanRunID != scanID || event.Type != scan.EventDone {
				continue
			}
			if event.Error != "" {
				restoreLDAPSecret(deps.SecretStore, previousSecret, secretWasPresent)
				_ = renderActiveDirectorySetup(w, deps, "", "LDAP scan failed: "+event.Error)
				return
			}
			w.Header().Set("HX-Trigger", `{"refresh-agent-state":{},"refresh-sidebar":{}}`)
			w.Header().Set("HX-Redirect", "/active-directory")
			_ = renderActiveDirectorySetup(w, deps, "Active Directory saved and scanned successfully.", "")
			return
		case <-timer.C:
			_ = renderActiveDirectorySetup(w, deps, "", "LDAP scan is still running. Please try again shortly.")
			return
		case <-r.Context().Done():
			return
		}
	}
}

func restoreLDAPSecret(store secretstore.Store, previous []byte, existed bool) {
	if store == nil {
		return
	}
	if existed {
		_ = store.Put(ldapPasswordSecret, previous)
		_ = os.Setenv(ldapPasswordEnv, string(previous))
		clear(previous)
		return
	}
	_ = store.Delete(ldapPasswordSecret)
	_ = os.Unsetenv(ldapPasswordEnv)
}

func discoverDomainController(ctx context.Context, bindDN, baseDN string) string {
	domain := domainFromAccount(bindDN)
	if domain == "" {
		domain = strings.ToLower(strings.TrimSpace(os.Getenv("USERDNSDOMAIN")))
	}
	if domain == "" {
		domain = domainFromBaseDN(baseDN)
	}
	if domain == "" {
		return ""
	}
	for _, name := range []string{"dc._msdcs." + domain, domain} {
		_, records, err := net.DefaultResolver.LookupSRV(ctx, "ldap", "tcp", name)
		if err == nil && len(records) > 0 {
			return net.JoinHostPort(strings.TrimSuffix(records[0].Target, "."), fmt.Sprint(records[0].Port))
		}
	}
	return ""
}

func normalizeADAccount(account, baseDN string) string {
	account = strings.TrimSpace(account)
	if strings.ContainsAny(account, "@=\\") {
		return account
	}
	if domain := domainFromBaseDN(baseDN); domain != "" {
		return account + "@" + domain
	}
	return account
}

func domainFromAccount(account string) string {
	if at := strings.LastIndex(account, "@"); at >= 0 && at+1 < len(account) {
		return strings.ToLower(strings.TrimSpace(account[at+1:]))
	}
	return ""
}

func domainFromBaseDN(baseDN string) string {
	parts := make([]string, 0, 3)
	for _, component := range strings.Split(baseDN, ",") {
		key, value, ok := strings.Cut(strings.TrimSpace(component), "=")
		if ok && strings.EqualFold(key, "DC") && strings.TrimSpace(value) != "" {
			parts = append(parts, strings.TrimSpace(value))
		}
	}
	return strings.ToLower(strings.Join(parts, "."))
}

func inferBaseDN(bindDN, domainController string) string {
	domain := ""
	if at := strings.LastIndex(bindDN, "@"); at >= 0 && at+1 < len(bindDN) {
		domain = bindDN[at+1:]
	}
	if domain == "" {
		host := domainController
		if colon := strings.LastIndex(host, ":"); colon > 0 {
			host = host[:colon]
		}
		if dot := strings.Index(host, "."); dot >= 0 && dot+1 < len(host) {
			domain = host[dot+1:]
		}
	}
	parts := strings.Split(strings.Trim(domain, "."), ".")
	if len(parts) < 2 {
		return ""
	}
	for i := range parts {
		if strings.TrimSpace(parts[i]) == "" {
			return ""
		}
		parts[i] = "DC=" + strings.TrimSpace(parts[i])
	}
	return strings.Join(parts, ",")
}
