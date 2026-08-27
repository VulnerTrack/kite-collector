package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/term"
)

type integrationCLIView struct {
	Key              string `json:"key"`
	Name             string `json:"name"`
	Description      string `json:"description"`
	Account          string `json:"account"`
	DomainController string `json:"domain_controller"`
	BaseDN           string `json:"base_dn"`
	TLSMode          string `json:"tls_mode"`
	Status           string `json:"status"`
}

func newIntegrationsCmd() *cobra.Command {
	var dashboardURL string
	cmd := &cobra.Command{
		Use:   "integrations",
		Short: "List and configure services connected to Kite",
		Long:  "Discover and configure credentialed integrations through the running local Kite dashboard.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runIntegrationsList(cmd, dashboardURL, "table")
		},
	}
	cmd.PersistentFlags().StringVar(&dashboardURL, "dashboard-url", "http://127.0.0.1:9090", "local Kite dashboard URL")
	cmd.AddCommand(newIntegrationsListCmd(&dashboardURL), newIntegrationsConfigureCmd(&dashboardURL))
	return cmd
}

func newIntegrationsListCmd(dashboardURL *string) *cobra.Command {
	var output string
	cmd := &cobra.Command{
		Use:   "list",
		Short: "Show detected configurable integrations",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runIntegrationsList(cmd, *dashboardURL, output)
		},
	}
	cmd.Flags().StringVar(&output, "output", "table", "output format: table or json")
	return cmd
}

func runIntegrationsList(cmd *cobra.Command, dashboardURL, output string) error {
	items, err := fetchIntegrations(dashboardURL)
	if err != nil {
		return err
	}
	if output != "table" && output != "json" {
		return fmt.Errorf("unsupported output format %q; use table or json", output)
	}
	if output == "json" {
		if err := json.NewEncoder(cmd.OutOrStdout()).Encode(items); err != nil {
			return fmt.Errorf("encode integrations: %w", err)
		}
		return nil
	}
	if len(items) == 0 {
		_, _ = fmt.Fprintln(cmd.OutOrStdout(), "No configurable integrations were detected.")
		return nil
	}
	w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 4, 2, ' ', 0)
	_, _ = fmt.Fprintln(w, "INTEGRATION\tKEY\tSTATUS\tENDPOINT")
	for _, item := range items {
		_, _ = fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", item.Name, item.Key, item.Status, item.DomainController)
	}
	if err := w.Flush(); err != nil {
		return fmt.Errorf("flush integrations table: %w", err)
	}
	_, _ = fmt.Fprintln(cmd.OutOrStdout(), "\nConfigure an integration:")
	_, _ = fmt.Fprintln(cmd.OutOrStdout(), "  kite-collector integrations configure active-directory")
	return nil
}

func newIntegrationsConfigureCmd(dashboardURL *string) *cobra.Command {
	var account, dc, baseDN, tlsMode string
	var passwordStdin bool
	cmd := &cobra.Command{
		Use:   "configure <integration>",
		Short: "Configure, validate, and scan an integration",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			key := strings.ToLower(strings.TrimSpace(args[0]))
			if key == "active-directory" || key == "ad" {
				key = "ldap"
			}
			items, err := fetchIntegrations(*dashboardURL)
			if err != nil {
				return err
			}
			var selected *integrationCLIView
			for i := range items {
				if items[i].Key == key {
					selected = &items[i]
					break
				}
			}
			if selected == nil {
				return fmt.Errorf("integration %q was not detected; run: kite-collector integrations list", args[0])
			}
			if key != "ldap" {
				return fmt.Errorf("interactive configuration is not available yet for %s", selected.Name)
			}
			if account == "" {
				account = selected.Account
			}
			if dc == "" {
				dc = selected.DomainController
			}
			if baseDN == "" {
				baseDN = selected.BaseDN
			}
			if tlsMode == "" {
				tlsMode = selected.TLSMode
			}
			password, err := readIntegrationPassword(cmd, passwordStdin)
			if err != nil {
				return err
			}
			form := url.Values{"bind_dn": {account}, "password": {password}, "domain_controller": {dc}, "base_dn": {baseDN}, "tls_mode": {tlsMode}}
			endpoint := strings.TrimRight(*dashboardURL, "/") + "/api/v1/onboarding/active-directory"
			req, err := http.NewRequestWithContext(cmd.Context(), http.MethodPost, endpoint, strings.NewReader(form.Encode()))
			if err != nil {
				return fmt.Errorf("create integration request: %w", err)
			}
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req.Header.Set("Origin", strings.TrimRight(*dashboardURL, "/"))
			client := &http.Client{Timeout: 6 * time.Minute}
			resp, err := client.Do(req)
			if err != nil {
				return fmt.Errorf("configure integration: %w", err)
			}
			defer func() { _ = resp.Body.Close() }()
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
			if resp.StatusCode != http.StatusOK || strings.Contains(string(body), `role="alert"`) {
				return fmt.Errorf("active directory configuration failed: %s", strings.TrimSpace(stripHTML(string(body))))
			}
			_, _ = fmt.Fprintln(cmd.OutOrStdout(), "Active Directory configured and scanned successfully.")
			return nil
		},
	}
	cmd.Flags().StringVar(&account, "account", "", "Active Directory account (default: detected value)")
	cmd.Flags().StringVar(&dc, "domain-controller", "", "Domain Controller override")
	cmd.Flags().StringVar(&baseDN, "base-dn", "", "Base DN override")
	cmd.Flags().StringVar(&tlsMode, "tls-mode", "", "TLS mode: ldaps, starttls, or none")
	cmd.Flags().BoolVar(&passwordStdin, "password-stdin", false, "read password from standard input")
	return cmd
}

func fetchIntegrations(baseURL string) ([]integrationCLIView, error) {
	client := &http.Client{Timeout: 10 * time.Second}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(baseURL, "/")+"/api/v1/integrations", nil)
	if err != nil {
		return nil, fmt.Errorf("create integrations request: %w", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("connect to local Kite dashboard: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("dashboard returned HTTP %d", resp.StatusCode)
	}
	var out []integrationCLIView
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("decode integrations: %w", err)
	}
	return out, nil
}

func readIntegrationPassword(cmd *cobra.Command, fromStdin bool) (string, error) {
	if fromStdin {
		value, err := bufio.NewReader(cmd.InOrStdin()).ReadString('\n')
		if err != nil && err != io.EOF {
			return "", fmt.Errorf("read integration password: %w", err)
		}
		value = strings.TrimSpace(value)
		if value == "" {
			return "", fmt.Errorf("password cannot be empty")
		}
		return value, nil
	}
	fd := int(os.Stdin.Fd())
	if term.IsTerminal(fd) {
		_, _ = fmt.Fprint(cmd.ErrOrStderr(), "Active Directory password: ")
		value, err := term.ReadPassword(fd)
		_, _ = fmt.Fprintln(cmd.ErrOrStderr())
		return strings.TrimSpace(string(value)), err
	}
	if value := os.Getenv("KITE_LDAP_BIND_PASSWORD"); value != "" {
		return value, nil
	}
	return "", fmt.Errorf("no interactive terminal; use --password-stdin or KITE_LDAP_BIND_PASSWORD")
}

func stripHTML(value string) string {
	var out strings.Builder
	inTag := false
	for _, r := range value {
		switch r {
		case '<':
			inTag = true
		case '>':
			inTag = false
		default:
			if !inTag {
				out.WriteRune(r)
			}
		}
	}
	return strings.Join(strings.Fields(out.String()), " ")
}
