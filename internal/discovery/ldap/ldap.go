// Package ldap implements a discovery.Source that enumerates Windows
// Active Directory / generic LDAP computer accounts, organisational units,
// and security groups as kite assets per RFC-0121.
//
// Phase 0 (this file) establishes the package and pulls in the
// github.com/go-ldap/ldap/v3 dependency so subsequent phases can layer the
// actual bind/search/parse logic on top without re-tidying the module
// graph. The Discover method intentionally returns an empty slice — the
// telemetry contract already declares "ldap" as an allowed
// security.asset.discovery.source so the wiring compiles end-to-end.
package ldap

import (
	"context"

	ldapv3 "github.com/go-ldap/ldap/v3"

	"github.com/vulnertrack/kite-collector/internal/model"
)

// SourceName is the stable identifier emitted on the
// security.asset.discovery.source attribute and the discover.<source>
// span suffix per RFC-0115.
const SourceName = "ldap"

// LDAP implements discovery.Source for Active Directory / LDAP.
type LDAP struct{}

// New returns a new LDAP discovery source.
func New() *LDAP { return &LDAP{} }

// Name returns the stable identifier for this source.
func (l *LDAP) Name() string { return SourceName }

// Discover is a Phase 0 stub. Future phases will bind to the configured
// directory using ldapv3.DialURL, run paged searches against the
// Computer / OrganizationalUnit / Group object classes, and translate
// the results into model.Asset values plus the AD-specific tags declared
// in contract.AttrAD*.
func (l *LDAP) Discover(_ context.Context, _ map[string]any) ([]model.Asset, error) {
	// Reference the dependency so the Phase 0 scaffold compiles and
	// `go mod tidy` retains the module in go.mod. The constant is the
	// LDAP scope code for a base-object search and is harmless to read.
	_ = ldapv3.ScopeBaseObject
	return nil, nil
}
