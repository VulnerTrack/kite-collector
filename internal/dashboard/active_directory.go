package dashboard

import (
	"context"
	"fmt"
	"html/template"
	"io"

	"github.com/vulnertrack/kite-collector/internal/store"
)

// renderActiveDirectoryFragment is the directory inventory landing page.  It
// deliberately links to the live tables rather than keeping a separate,
// hand-maintained AD summary: every number comes from the last LDAP scan.
func renderActiveDirectoryFragment(w io.Writer, ctx context.Context, ts store.TableSource) error {
	sections := []adDirectorySection{
		{Label: "Domain", Table: "ad_directory_domains", Description: "Domain DNS, NetBIOS identity, SID and creation metadata."},
		{Label: "Computers", Table: "ad_directory_computers", Description: "Domain computer accounts, operating system, SPNs and logon state."},
		{Label: "Users", Table: "ad_directory_users", Description: "Accounts, identifiers, mail and enabled state."},
		{Label: "Groups", Table: "ad_directory_groups", Description: "Security and distribution groups discovered from LDAP."},
		{Label: "Organizational units", Table: "ad_directory_ous", Description: "OU hierarchy and linked Group Policy objects."},
		{Label: "Group Policy", Table: "ad_directory_gpos", Description: "GPO names, GUIDs, versions and flags."},
		{Label: "Relationships", Table: "ad_directory_relationships", Description: "Membership edges between directory objects."},
	}
	for i := range sections {
		_, total, err := ts.ListRows(ctx, store.RowsFilter{Table: sections[i].Table, Limit: 1})
		if err != nil {
			return fmt.Errorf("count %s: %w", sections[i].Table, err)
		}
		sections[i].Count = total
	}

	tmpl := template.Must(template.New("active-directory").Parse(activeDirectoryTemplate))
	if err := tmpl.Execute(w, map[string]any{"Sections": sections}); err != nil {
		return fmt.Errorf("render active directory overview: %w", err)
	}
	return nil
}

type adDirectorySection struct {
	Label       string
	Table       string
	Description string
	Count       int64
}

const activeDirectoryTemplate = `
<section class="ad-directory-overview">
  <div class="page-heading">
    <div>
      <h1>Active Directory</h1>
      <p class="muted">Logical inventory dynamically collected during the most recent LDAP scan.</p>
    </div>
    <a href="/software" hx-get="/software" hx-target="#content" hx-push-url="true" class="btn btn-outline">View Active Directory as software</a>
  </div>
  <div class="ad-directory-grid">
    {{range .Sections}}
    <a class="ad-directory-card" href="/tables/{{.Table}}" hx-get="/tables/{{.Table}}" hx-target="#content" hx-push-url="true">
      <span class="ad-directory-count">{{.Count}}</span>
      <strong>{{.Label}}</strong>
      <span>{{.Description}}</span>
      <small>View table &rarr;</small>
    </a>
    {{end}}
  </div>
  <p class="muted small">Default accounts and groups depend on the AD image. Machine, operating system, and network data are shown in <a href="/machines" hx-get="/machines" hx-target="#content" hx-push-url="true">Machines</a>; the domain service appears in <a href="/software" hx-get="/software" hx-target="#content" hx-push-url="true">Software</a>.</p>
</section>`
