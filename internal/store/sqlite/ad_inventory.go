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

func (s *SQLiteStore) ReplaceADInventory(ctx context.Context, inventory model.ADInventory) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin AD inventory transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	for _, table := range []string{"ad_directory_relationships", "ad_directory_users", "ad_directory_groups", "ad_directory_ous", "ad_directory_gpos", "ad_directory_computers", "ad_directory_domains"} {
		if _, err := tx.ExecContext(ctx, "DELETE FROM "+table+" WHERE domain_dns_name = ?", inventory.DomainDNSName); err != nil {
			return fmt.Errorf("clear %s: %w", table, err)
		}
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	for _, user := range inventory.Users {
		if _, err := tx.ExecContext(ctx, `INSERT INTO ad_directory_users (distinguished_name, domain_dns_name, sam_account_name, user_principal_name, display_name, mail, object_sid, enabled, last_seen_at, department, title, manager, telephone, last_logon, when_created, account_expires, password_never_expires, password_not_required) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, user.DistinguishedName, inventory.DomainDNSName, user.SAMAccountName, user.UserPrincipalName, user.DisplayName, user.Mail, user.ObjectSID, boolToInt(user.Enabled), now, user.Department, user.Title, user.Manager, user.Telephone, user.LastLogon, user.WhenCreated, user.AccountExpires, boolToInt(user.PasswordNeverExpires), boolToInt(user.PasswordNotRequired)); err != nil {
			return err
		}
		for _, group := range user.MemberOf {
			if _, err := tx.ExecContext(ctx, `INSERT INTO ad_directory_relationships VALUES (?, ?, 'member_of', ?, ?)`, user.DistinguishedName, group, inventory.DomainDNSName, now); err != nil {
				return err
			}
		}
	}
	for _, group := range inventory.Groups {
		if _, err := tx.ExecContext(ctx, `INSERT INTO ad_directory_groups (distinguished_name, domain_dns_name, sam_account_name, object_sid, last_seen_at, description, group_type) VALUES (?, ?, ?, ?, ?, ?, ?)`, group.DistinguishedName, inventory.DomainDNSName, group.SAMAccountName, group.ObjectSID, now, group.Description, group.GroupType); err != nil {
			return err
		}
		for _, member := range group.Members {
			if _, err := tx.ExecContext(ctx, `INSERT INTO ad_directory_relationships VALUES (?, ?, 'has_member', ?, ?)`, group.DistinguishedName, member, inventory.DomainDNSName, now); err != nil {
				return err
			}
		}
	}
	for _, ou := range inventory.OUs {
		links, _ := json.Marshal(ou.GPOLinks)
		if _, err := tx.ExecContext(ctx, `INSERT INTO ad_directory_ous (distinguished_name, domain_dns_name, name, gpo_links, last_seen_at, description) VALUES (?, ?, ?, ?, ?, ?)`, ou.DistinguishedName, inventory.DomainDNSName, ou.Name, string(links), now, ou.Description); err != nil {
			return err
		}
	}
	for _, gpo := range inventory.GPOs {
		if _, err := tx.ExecContext(ctx, `INSERT INTO ad_directory_gpos VALUES (?, ?, ?, ?, ?, ?, ?)`, gpo.DistinguishedName, inventory.DomainDNSName, gpo.DisplayName, gpo.GUID, gpo.Version, gpo.Flags, now); err != nil {
			return err
		}
	}
	for _, computer := range inventory.Computers {
		spns, _ := json.Marshal(computer.ServicePrincipalNames)
		if _, err := tx.ExecContext(ctx, `INSERT INTO ad_directory_computers (distinguished_name, domain_dns_name, name, dns_host_name, operating_system, operating_system_version, object_sid, enabled, last_logon, password_last_set, service_principal_names, last_seen_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, computer.DistinguishedName, inventory.DomainDNSName, computer.Name, computer.DNSHostName, computer.OperatingSystem, computer.OperatingSystemVersion, computer.ObjectSID, boolToInt(computer.Enabled), computer.LastLogon, computer.PasswordLastSet, string(spns), now); err != nil {
			return err
		}
	}
	for _, domain := range inventory.Domains {
		if _, err := tx.ExecContext(ctx, `INSERT INTO ad_directory_domains VALUES (?, ?, ?, ?, ?, ?, ?)`, domain.DistinguishedName, inventory.DomainDNSName, domain.DNSRoot, domain.NetBIOSName, domain.ObjectSID, domain.WhenCreated, now); err != nil {
			return err
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit AD inventory: %w", err)
	}
	return nil
}
