package ldap

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	ldapv3 "github.com/go-ldap/ldap/v3"
	"github.com/vulnertrack/kite-collector/internal/model"
)

const (
	userSearchFilter   = "(&(objectCategory=person)(objectClass=user))"
	groupSearchFilter  = "(objectClass=group)"
	ouSearchFilter     = "(objectClass=organizationalUnit)"
	gpoSearchFilter    = "(objectClass=groupPolicyContainer)"
	domainSearchFilter = "(objectClass=domainDNS)"
	// crossRefSearchFilter matches domain partitions only; configuration,
	// schema and application partitions carry no NetBIOS name.
	crossRefSearchFilter = "(&(objectClass=crossRef)(nETBIOSName=*))"
)

func collectDirectoryInventory(ctx context.Context, conn directoryConn, conf *ldapConfig) (model.ADInventory, error) {
	inventory := model.ADInventory{DomainDNSName: domainFromBaseDN(conf.baseDN)}
	var err error
	if conf.collectUsers {
		var result *ldapv3.SearchResult
		result, err = searchPaged(ctx, conn, conf, userSearchFilter, []string{"distinguishedName", "sAMAccountName", "userPrincipalName", "displayName", "mail", "objectSid", "userAccountControl", "memberOf", "department", "title", "manager", "telephoneNumber", "lastLogonTimestamp", "whenCreated", "accountExpires"})
		if err != nil {
			return inventory, err
		}
		for _, entry := range result.Entries {
			inventory.Users = append(inventory.Users, adUser(entry))
		}
	}
	if conf.collectGroups {
		var result *ldapv3.SearchResult
		result, err = searchPaged(ctx, conn, conf, groupSearchFilter, []string{"distinguishedName", "sAMAccountName", "objectSid", "member", "description", "groupType"})
		if err != nil {
			return inventory, err
		}
		for _, entry := range result.Entries {
			inventory.Groups = append(inventory.Groups, adGroup(entry))
		}
	}
	if conf.collectOUs {
		var result *ldapv3.SearchResult
		result, err = searchPaged(ctx, conn, conf, ouSearchFilter, []string{"distinguishedName", "ou", "gPLink", "description"})
		if err != nil {
			return inventory, err
		}
		for _, entry := range result.Entries {
			inventory.OUs = append(inventory.OUs, adOU(entry))
		}
	}
	if conf.collectGPOs {
		var result *ldapv3.SearchResult
		result, err = searchPaged(ctx, conn, conf, gpoSearchFilter, []string{"distinguishedName", "displayName", "name", "versionNumber", "flags"})
		if err != nil {
			return inventory, err
		}
		for _, entry := range result.Entries {
			inventory.GPOs = append(inventory.GPOs, adGPO(entry))
		}
	}
	result, err := searchPaged(ctx, conn, conf, computerSearchFilter, computerAttributes)
	if err != nil {
		return inventory, err
	}
	for _, entry := range result.Entries {
		inventory.Computers = append(inventory.Computers, adComputer(entry))
	}
	result, err = searchPaged(ctx, conn, conf, domainSearchFilter, []string{"distinguishedName", "objectSid", "whenCreated"})
	if err != nil {
		return inventory, err
	}
	for _, entry := range result.Entries {
		inventory.Domains = append(inventory.Domains, adDomain(entry))
	}
	if len(inventory.Domains) > 0 {
		// The NetBIOS name is identity metadata, not inventory: a bind account
		// that cannot read the configuration partition still gets a full scan.
		names, lookupErr := netBIOSNamesByNC(conn, conf)
		if lookupErr != nil {
			slog.Warn("ldap: could not resolve domain NetBIOS names", "code", string(LogCodeInventoryNetBIOSLookupFailed), "error", lookupErr)
		}
		for i := range inventory.Domains {
			inventory.Domains[i].NetBIOSName = names[strings.ToLower(inventory.Domains[i].DistinguishedName)]
		}
	}
	return inventory, nil
}

func adUser(entry *ldapv3.Entry) model.ADUser {
	uac := parseUint32(entry.GetAttributeValue("userAccountControl"))
	return model.ADUser{DistinguishedName: entry.DN, SAMAccountName: entry.GetAttributeValue("sAMAccountName"), UserPrincipalName: entry.GetAttributeValue("userPrincipalName"), DisplayName: entry.GetAttributeValue("displayName"), Mail: entry.GetAttributeValue("mail"), ObjectSID: parseObjectSID(entry.GetRawAttributeValue("objectSid")), Enabled: uac&uacAccountDisable == 0, Department: entry.GetAttributeValue("department"), Title: entry.GetAttributeValue("title"), Manager: entry.GetAttributeValue("manager"), Telephone: entry.GetAttributeValue("telephoneNumber"), LastLogon: entry.GetAttributeValue("lastLogonTimestamp"), WhenCreated: entry.GetAttributeValue("whenCreated"), AccountExpires: entry.GetAttributeValue("accountExpires"), PasswordNeverExpires: uac&0x10000 != 0, PasswordNotRequired: uac&0x20 != 0, MemberOf: trimmed(entry.GetAttributeValues("memberOf"))}
}

func adGroup(entry *ldapv3.Entry) model.ADGroup {
	return model.ADGroup{DistinguishedName: entry.DN, SAMAccountName: entry.GetAttributeValue("sAMAccountName"), ObjectSID: parseObjectSID(entry.GetRawAttributeValue("objectSid")), Description: entry.GetAttributeValue("description"), GroupType: entry.GetAttributeValue("groupType"), Members: trimmed(entry.GetAttributeValues("member"))}
}

func adOU(entry *ldapv3.Entry) model.ADOrganizationalUnit {
	return model.ADOrganizationalUnit{DistinguishedName: entry.DN, Name: entry.GetAttributeValue("ou"), GPOLinks: trimmed([]string{entry.GetAttributeValue("gPLink")}), Description: entry.GetAttributeValue("description")}
}

func adGPO(entry *ldapv3.Entry) model.ADGroupPolicyObject {
	return model.ADGroupPolicyObject{DistinguishedName: entry.DN, DisplayName: entry.GetAttributeValue("displayName"), GUID: entry.GetAttributeValue("name"), Version: entry.GetAttributeValue("versionNumber"), Flags: entry.GetAttributeValue("flags")}
}

func adComputer(entry *ldapv3.Entry) model.ADComputer {
	uac := parseUint32(entry.GetAttributeValue("userAccountControl"))
	return model.ADComputer{DistinguishedName: entry.DN, Name: entry.GetAttributeValue("sAMAccountName"), DNSHostName: entry.GetAttributeValue("dnsHostName"), OperatingSystem: entry.GetAttributeValue("operatingSystem"), OperatingSystemVersion: entry.GetAttributeValue("operatingSystemVersion"), ObjectSID: parseObjectSID(entry.GetRawAttributeValue("objectSid")), Enabled: uac&uacAccountDisable == 0, LastLogon: ldapTime(entry.GetAttributeValue("lastLogonTimestamp")), PasswordLastSet: ldapTime(entry.GetAttributeValue("pwdLastSet")), ServicePrincipalNames: trimmed(entry.GetAttributeValues("servicePrincipalName"))}
}

// adDomain maps a domainDNS object. dnsRoot and nETBIOSName are not populated
// on that object in AD (dnsRoot is a crossRef-only attribute), so the DNS root
// comes from the domain naming context's DC= components and the NetBIOS name
// is filled in from the partition's crossRef by resolveNetBIOSNames.
func adDomain(entry *ldapv3.Entry) model.ADDomain {
	return model.ADDomain{DistinguishedName: entry.DN, DNSRoot: domainFromBaseDN(entry.DN), ObjectSID: parseObjectSID(entry.GetRawAttributeValue("objectSid")), WhenCreated: entry.GetAttributeValue("whenCreated")}
}

// netBIOSNamesByNC reads every crossRef under CN=Partitions of the forest
// configuration partition and returns nETBIOSName keyed by the lowercased
// nCName. The configuration partition is a separate naming context, so a
// subtree search from base_dn never reaches it.
func netBIOSNamesByNC(conn directoryConn, conf *ldapConfig) (map[string]string, error) {
	rootDSE, err := conn.Search(ldapv3.NewSearchRequest("", ldapv3.ScopeBaseObject, ldapv3.NeverDerefAliases, 0, conf.timeoutSeconds, false, "(objectClass=*)", []string{"configurationNamingContext"}, nil))
	if err != nil {
		return nil, fmt.Errorf("read rootDSE: %w", err)
	}
	var configNC string
	if len(rootDSE.Entries) > 0 {
		configNC = rootDSE.Entries[0].GetAttributeValue("configurationNamingContext")
	}
	if configNC == "" {
		return nil, fmt.Errorf("rootDSE has no configurationNamingContext")
	}
	result, err := conn.Search(ldapv3.NewSearchRequest("CN=Partitions,"+configNC, ldapv3.ScopeSingleLevel, ldapv3.NeverDerefAliases, 0, conf.timeoutSeconds, false, crossRefSearchFilter, []string{"nCName", "nETBIOSName"}, nil))
	if err != nil {
		return nil, fmt.Errorf("search crossRef partitions: %w", err)
	}
	names := make(map[string]string, len(result.Entries))
	for _, entry := range result.Entries {
		if nc, name := entry.GetAttributeValue("nCName"), entry.GetAttributeValue("nETBIOSName"); nc != "" && name != "" {
			names[strings.ToLower(nc)] = name
		}
	}
	return names, nil
}

func ldapTime(value string) string {
	n := parseInt64(value)
	if n <= 0 || n == 9223372036854775807 {
		return ""
	}
	unix := windowsTimeToUnix(n)
	if unix <= 0 {
		return ""
	}
	return time.Unix(unix, 0).UTC().Format(time.RFC3339)
}

func trimmed(values []string) []string {
	out := make([]string, 0, len(values))
	for _, v := range values {
		if v = strings.TrimSpace(v); v != "" {
			out = append(out, v)
		}
	}
	return out
}
