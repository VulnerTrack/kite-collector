package sqlite

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/vulnertrack/kite-collector/internal/model"
	"github.com/vulnertrack/kite-collector/internal/store"
)

var _ store.ADInventoryStore = (*SQLiteStore)(nil)

// adInventoryPurges are the per-domain deletes run before a replace. Each
// statement is a full literal rather than a concatenated table name so the SQL
// stays constant (gosec G202) — children first, domains last, mirroring the
// insert order below in reverse.
var adInventoryPurges = []struct{ table, stmt string }{
	{"ad_directory_relationships", `DELETE FROM ad_directory_relationships WHERE domain_dns_name = ?`},
	{"ad_directory_users", `DELETE FROM ad_directory_users WHERE domain_dns_name = ?`},
	{"ad_directory_groups", `DELETE FROM ad_directory_groups WHERE domain_dns_name = ?`},
	{"ad_directory_ous", `DELETE FROM ad_directory_ous WHERE domain_dns_name = ?`},
	{"ad_directory_gpos", `DELETE FROM ad_directory_gpos WHERE domain_dns_name = ?`},
	{"ad_directory_computers", `DELETE FROM ad_directory_computers WHERE domain_dns_name = ?`},
	{"ad_directory_domains", `DELETE FROM ad_directory_domains WHERE domain_dns_name = ?`},
}

func (s *SQLiteStore) ReplaceADInventory(ctx context.Context, inventory model.ADInventory) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin AD inventory transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	for _, purge := range adInventoryPurges {
		if _, err := tx.ExecContext(ctx, purge.stmt, inventory.DomainDNSName); err != nil {
			return fmt.Errorf("clear %s: %w", purge.table, err)
		}
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	for _, user := range inventory.Users {
		if _, err := tx.ExecContext(ctx, `INSERT INTO ad_directory_users (distinguished_name, domain_dns_name, sam_account_name, user_principal_name, display_name, mail, object_sid, enabled, last_seen_at, department, title, manager, telephone, last_logon, when_created, account_expires, password_never_expires, password_not_required) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, user.DistinguishedName, inventory.DomainDNSName, user.SAMAccountName, user.UserPrincipalName, user.DisplayName, user.Mail, user.ObjectSID, boolToInt(user.Enabled), now, user.Department, user.Title, user.Manager, user.Telephone, user.LastLogon, user.WhenCreated, user.AccountExpires, boolToInt(user.PasswordNeverExpires), boolToInt(user.PasswordNotRequired)); err != nil {
			return fmt.Errorf("insert AD user %q: %w", user.DistinguishedName, err)
		}
		for _, group := range user.MemberOf {
			if _, err := tx.ExecContext(ctx, `INSERT INTO ad_directory_relationships VALUES (?, ?, 'member_of', ?, ?)`, user.DistinguishedName, group, inventory.DomainDNSName, now); err != nil {
				return fmt.Errorf("insert AD user membership %q -> %q: %w", user.DistinguishedName, group, err)
			}
		}
	}
	for _, group := range inventory.Groups {
		if _, err := tx.ExecContext(ctx, `INSERT INTO ad_directory_groups (distinguished_name, domain_dns_name, sam_account_name, object_sid, last_seen_at, description, group_type) VALUES (?, ?, ?, ?, ?, ?, ?)`, group.DistinguishedName, inventory.DomainDNSName, group.SAMAccountName, group.ObjectSID, now, group.Description, group.GroupType); err != nil {
			return fmt.Errorf("insert AD group %q: %w", group.DistinguishedName, err)
		}
		for _, member := range group.Members {
			if _, err := tx.ExecContext(ctx, `INSERT INTO ad_directory_relationships VALUES (?, ?, 'has_member', ?, ?)`, group.DistinguishedName, member, inventory.DomainDNSName, now); err != nil {
				return fmt.Errorf("insert AD group member %q -> %q: %w", group.DistinguishedName, member, err)
			}
		}
	}
	for _, ou := range inventory.OUs {
		links, _ := json.Marshal(ou.GPOLinks)
		if _, err := tx.ExecContext(ctx, `INSERT INTO ad_directory_ous (distinguished_name, domain_dns_name, name, gpo_links, last_seen_at, description) VALUES (?, ?, ?, ?, ?, ?)`, ou.DistinguishedName, inventory.DomainDNSName, ou.Name, string(links), now, ou.Description); err != nil {
			return fmt.Errorf("insert AD OU %q: %w", ou.DistinguishedName, err)
		}
	}
	for _, gpo := range inventory.GPOs {
		if _, err := tx.ExecContext(ctx, `INSERT INTO ad_directory_gpos VALUES (?, ?, ?, ?, ?, ?, ?)`, gpo.DistinguishedName, inventory.DomainDNSName, gpo.DisplayName, gpo.GUID, gpo.Version, gpo.Flags, now); err != nil {
			return fmt.Errorf("insert AD GPO %q: %w", gpo.DistinguishedName, err)
		}
	}
	for _, computer := range inventory.Computers {
		spns, _ := json.Marshal(computer.ServicePrincipalNames)
		if _, err := tx.ExecContext(ctx, `INSERT INTO ad_directory_computers (distinguished_name, domain_dns_name, name, dns_host_name, operating_system, operating_system_version, object_sid, enabled, last_logon, password_last_set, service_principal_names, last_seen_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, computer.DistinguishedName, inventory.DomainDNSName, computer.Name, computer.DNSHostName, computer.OperatingSystem, computer.OperatingSystemVersion, computer.ObjectSID, boolToInt(computer.Enabled), computer.LastLogon, computer.PasswordLastSet, string(spns), now); err != nil {
			return fmt.Errorf("insert AD computer %q: %w", computer.DistinguishedName, err)
		}
	}
	for _, domain := range inventory.Domains {
		if _, err := tx.ExecContext(ctx, `INSERT INTO ad_directory_domains VALUES (?, ?, ?, ?, ?, ?, ?)`, domain.DistinguishedName, inventory.DomainDNSName, domain.DNSRoot, domain.NetBIOSName, domain.ObjectSID, domain.WhenCreated, now); err != nil {
			return fmt.Errorf("insert AD domain %q: %w", domain.DistinguishedName, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit AD inventory: %w", err)
	}
	return nil
}
