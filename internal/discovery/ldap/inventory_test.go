package ldap

import (
	"context"
	"errors"
	"testing"

	ldapv3 "github.com/go-ldap/ldap/v3"
)

const (
	testDomainDN = "DC=corp,DC=acme,DC=com"
	testConfigNC = "CN=Configuration,DC=corp,DC=acme,DC=com"
)

func domainOnlyConfig() *ldapConfig {
	return &ldapConfig{baseDN: testDomainDN, pageSize: 1000, timeoutSeconds: 30}
}

// directoryFake answers the searches collectDirectoryInventory issues for a
// directory holding one domain. rootDSE/crossRef override those two lookups.
func directoryFake(rootDSE, crossRef func() (*ldapv3.SearchResult, error)) *fakeConn {
	return &fakeConn{searchFn: func(req *ldapv3.SearchRequest) (*ldapv3.SearchResult, error) {
		switch {
		case req.BaseDN == "" && req.Scope == ldapv3.ScopeBaseObject:
			return rootDSE()
		case req.BaseDN == "CN=Partitions,"+testConfigNC:
			if req.Scope != ldapv3.ScopeSingleLevel || req.Filter != crossRefSearchFilter {
				return nil, errors.New("unexpected crossRef search shape")
			}
			return crossRef()
		case req.Filter == domainSearchFilter:
			return &ldapv3.SearchResult{Entries: []*ldapv3.Entry{
				newComputerEntry(testDomainDN, map[string][]string{"whenCreated": {"20260101000000.0Z"}}, nil),
			}}, nil
		default:
			return &ldapv3.SearchResult{}, nil
		}
	}}
}

func TestCollectDirectoryInventory_DomainIdentityFromCrossRef(t *testing.T) {
	conn := directoryFake(
		func() (*ldapv3.SearchResult, error) {
			return &ldapv3.SearchResult{Entries: []*ldapv3.Entry{
				newComputerEntry("", map[string][]string{"configurationNamingContext": {testConfigNC}}, nil),
			}}, nil
		},
		func() (*ldapv3.SearchResult, error) {
			return &ldapv3.SearchResult{Entries: []*ldapv3.Entry{
				// A child domain's crossRef must not leak onto the parent.
				newComputerEntry("CN=EU,CN=Partitions,"+testConfigNC, map[string][]string{"nCName": {"DC=eu,DC=corp,DC=acme,DC=com"}, "nETBIOSName": {"EU"}}, nil),
				// AD returns nCName with its own casing; matching is case-insensitive.
				newComputerEntry("CN=CORP,CN=Partitions,"+testConfigNC, map[string][]string{"nCName": {"dc=corp,dc=acme,dc=com"}, "nETBIOSName": {"CORP"}}, nil),
			}}, nil
		},
	)

	inventory, err := collectDirectoryInventory(context.Background(), conn, domainOnlyConfig())
	if err != nil {
		t.Fatalf("collectDirectoryInventory: %v", err)
	}
	if len(inventory.Domains) != 1 {
		t.Fatalf("domains = %d, want 1", len(inventory.Domains))
	}
	got := inventory.Domains[0]
	if got.DNSRoot != "corp.acme.com" {
		t.Errorf("DNSRoot = %q, want corp.acme.com", got.DNSRoot)
	}
	if got.NetBIOSName != "CORP" {
		t.Errorf("NetBIOSName = %q, want CORP", got.NetBIOSName)
	}
}

func TestCollectDirectoryInventory_NetBIOSLookupFailureIsNonFatal(t *testing.T) {
	for name, rootDSE := range map[string]func() (*ldapv3.SearchResult, error){
		"search error": func() (*ldapv3.SearchResult, error) { return nil, errors.New("insufficient access") },
		"no config NC": func() (*ldapv3.SearchResult, error) { return &ldapv3.SearchResult{}, nil },
	} {
		t.Run(name, func(t *testing.T) {
			conn := directoryFake(rootDSE, func() (*ldapv3.SearchResult, error) {
				t.Fatal("crossRef search must not run without a configuration naming context")
				return nil, nil
			})

			inventory, err := collectDirectoryInventory(context.Background(), conn, domainOnlyConfig())
			if err != nil {
				t.Fatalf("collectDirectoryInventory: %v", err)
			}
			if len(inventory.Domains) != 1 {
				t.Fatalf("domains = %d, want 1", len(inventory.Domains))
			}
			if got := inventory.Domains[0]; got.DNSRoot != "corp.acme.com" || got.NetBIOSName != "" {
				t.Errorf("domain = %+v, want DNSRoot corp.acme.com and empty NetBIOSName", got)
			}
		})
	}
}
