//go:build windows
// +build windows

// Kite Collector Legacy is the deliberately small Windows 7/8 32-bit agent.
// Keep this module independent from the main collector: Go 1.20 is the last Go
// release capable of producing Windows 7 binaries.
package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/eventlog"
)

const (
	serviceName       = "kite-collector-legacy"
	modernServiceName = "kite-collector"
	defaultPKI        = "https://pki.vulnertrack.io"
)

type enrollResponse struct {
	Status      string `json:"status"`
	CA          string `json:"ca_certificate"`
	Certificate string `json:"client_certificate"`
}

type proof struct {
	AgentCode   string `json:"agent_code"`
	Certificate string `json:"certificate_pem"`
	Nonce       string `json:"nonce"`
	Signature   string `json:"signature"`
	Timestamp   int64  `json:"timestamp"`
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: kite-collector-legacy <enroll|install|service|heartbeat|scan|query|dashboard|version>")
	}
	switch args[0] {
	case "version", "--version":
		fmt.Println("kite-collector-legacy", version)
		return nil
	case "enroll":
		return enrollCommand(args[1:])
	case "install":
		return installCommand(args[1:])
	case "service":
		if len(args) < 2 || args[1] != "run" {
			return errors.New("usage: service run --certs-dir PATH")
		}
		return serviceCommand(args[2:])
	case "heartbeat":
		return heartbeatCommand(args[1:])
	case "scan":
		return scanCommand(args[1:])
	case "query":
		return queryCommand(args[1:])
	case "dashboard":
		return dashboardCommand(args[1:])
	default:
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func enrollCommand(args []string) error {
	fs := flag.NewFlagSet("enroll", flag.ContinueOnError)
	agent := fs.String("agent-code", "", "agent code")
	token := fs.String("enrollment-token", "", "single-use token")
	dir := fs.String("certs-dir", defaultDataDir(), "certificate directory")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *agent == "" || *token == "" {
		return errors.New("--agent-code and --enrollment-token are required")
	}
	return enroll(*agent, *token, *dir)
}

func enroll(agent, token, dir string) error {
	// A successful PKI response consumes the single-use token. If a previous
	// attempt reached PKI but failed during local certificate validation (most
	// commonly because a Windows 7 clock was wrong), finish from the protected
	// pending material instead of contacting PKI and losing the response.
	if recovered, err := recoverPendingEnrollment(agent, dir); recovered || err != nil {
		return err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: agent}}, key)
	if err != nil {
		return err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr})
	body, _ := json.Marshal(map[string]string{"token": token, "agent_code": agent, "csr_pem": string(csrPEM)})
	base := strings.TrimRight(os.Getenv("KITE_PKI_ENDPOINT"), "/")
	if base == "" {
		base = defaultPKI
	}
	client := &http.Client{Timeout: 45 * time.Second}
	resp, err := client.Post(base+"/pki/enroll/token", "application/json", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("contact PKI: %w", err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("PKI returned %s: %s", resp.Status, data)
	}
	var result enrollResponse
	if err := json.Unmarshal(data, &result); err != nil {
		return err
	}
	// Persist the complete response before validation. The token is already
	// consumed at this point, so these files are the recovery boundary if local
	// validation fails. They remain owner-only until promoted to the live names.
	if err := storePendingEnrollment(dir, agent, []byte(result.Certificate), []byte(result.CA), keyDER); err != nil {
		return fmt.Errorf("preserve PKI enrollment response: %w", err)
	}
	if err := validateCertificate(agent, []byte(result.Certificate), []byte(result.CA), key); err != nil {
		return fmt.Errorf("validate PKI response (response preserved for retry): %w", err)
	}
	if err := promotePendingEnrollment(dir); err != nil {
		return fmt.Errorf("activate PKI enrollment response: %w", err)
	}
	fmt.Println("Windows legacy collector enrolled as", agent)
	return nil
}

const (
	pendingAgent = ".enrollment-pending-agent"
	pendingCA    = ".enrollment-pending-ca.pem"
	pendingCert  = ".enrollment-pending-agent.pem"
	pendingKey   = ".enrollment-pending-agent-key.pem"
)

func storePendingEnrollment(dir, agent string, certPEM, caPEM, keyDER []byte) error {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	files := []struct {
		name string
		data []byte
	}{
		{pendingAgent, []byte(agent)},
		{pendingCA, caPEM},
		{pendingCert, certPEM},
		{pendingKey, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})},
	}
	for _, f := range files {
		if err := writeAtomic(filepath.Join(dir, f.name), f.data, 0600); err != nil {
			return err
		}
	}
	return nil
}

func recoverPendingEnrollment(agent, dir string) (bool, error) {
	pendingAgentCode, err := os.ReadFile(filepath.Join(dir, pendingAgent))
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return true, fmt.Errorf("read pending enrollment identity: %w", err)
	}
	if strings.TrimSpace(string(pendingAgentCode)) != agent {
		return true, errors.New("pending enrollment belongs to a different agent")
	}
	certPEM, err := os.ReadFile(filepath.Join(dir, pendingCert))
	if err != nil {
		return true, fmt.Errorf("read pending certificate: %w", err)
	}
	caPEM, err := os.ReadFile(filepath.Join(dir, pendingCA))
	if err != nil {
		return true, fmt.Errorf("read pending CA: %w", err)
	}
	keyPEM, err := os.ReadFile(filepath.Join(dir, pendingKey))
	if err != nil {
		return true, fmt.Errorf("read pending private key: %w", err)
	}
	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return true, errors.New("pending private key is invalid")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return true, fmt.Errorf("parse pending private key: %w", err)
	}
	key, ok := parsed.(*ecdsa.PrivateKey)
	if !ok {
		return true, errors.New("pending private key is not ECDSA")
	}
	if err := validateCertificate(agent, certPEM, caPEM, key); err != nil {
		return true, fmt.Errorf("validate preserved PKI response: %w", err)
	}
	if err := promotePendingEnrollment(dir); err != nil {
		return true, fmt.Errorf("activate preserved PKI response: %w", err)
	}
	fmt.Println("Windows legacy collector recovered preserved enrollment as", agent)
	return true, nil
}

func promotePendingEnrollment(dir string) error {
	for pending, live := range map[string]string{
		pendingCA:   "ca.pem",
		pendingCert: "agent.pem",
		pendingKey:  "agent-key.pem",
	} {
		data, err := os.ReadFile(filepath.Join(dir, pending))
		if err != nil {
			return err
		}
		mode := os.FileMode(0644)
		if live == "agent-key.pem" {
			mode = 0600
		}
		if err := writeAtomic(filepath.Join(dir, live), data, mode); err != nil {
			return err
		}
	}
	for _, name := range []string{pendingAgent, pendingCA, pendingCert, pendingKey} {
		_ = os.Remove(filepath.Join(dir, name))
	}
	return nil
}

func validateCertificate(agent string, certPEM, caPEM []byte, key *ecdsa.PrivateKey) error {
	b, _ := pem.Decode(certPEM)
	if b == nil {
		return errors.New("PKI returned an invalid agent certificate")
	}
	cert, err := x509.ParseCertificate(b.Bytes)
	if err != nil {
		return err
	}
	if cert.Subject.CommonName != agent {
		return errors.New("agent certificate identity mismatch")
	}
	want, _ := x509.MarshalPKIXPublicKey(key.Public())
	got, _ := x509.MarshalPKIXPublicKey(cert.PublicKey)
	if !bytes.Equal(want, got) {
		return errors.New("agent certificate key mismatch")
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return errors.New("PKI returned an invalid CA")
	}
	_, err = cert.Verify(x509.VerifyOptions{Roots: pool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}})
	return err
}

func writeAtomic(path string, data []byte, mode os.FileMode) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, mode); err != nil {
		return err
	}
	_ = os.Remove(path)
	return os.Rename(tmp, path)
}

func installCommand(args []string) error {
	fs := flag.NewFlagSet("install", flag.ContinueOnError)
	dir := fs.String("certs-dir", defaultDataDir(), "certificate directory")
	noStart := fs.Bool("no-start", false, "do not start service")
	if err := fs.Parse(args); err != nil {
		return err
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	exe, _ = filepath.Abs(exe)
	// A previous full collector cannot run correctly on Windows 7 and its
	// dashboard occupies the same loopback port as this compatibility service.
	// Retire only that service/process registration; preserve ProgramData so an
	// existing enrollment identity and inventory remain available.
	_ = exec.Command("sc.exe", "stop", modernServiceName).Run()
	_ = exec.Command("taskkill.exe", "/F", "/IM", "kite-collector.exe").Run()
	_ = exec.Command("sc.exe", "delete", modernServiceName).Run()
	_ = exec.Command("sc.exe", "stop", serviceName).Run()
	_ = exec.Command("sc.exe", "delete", serviceName).Run()
	binPath := fmt.Sprintf("\"%s\" service run --certs-dir \"%s\"", exe, *dir)
	out, err := exec.Command("sc.exe", "create", serviceName, "binPath=", binPath, "start=", "auto", "DisplayName=", "Kite Collector Legacy (Windows 7)").CombinedOutput()
	if err != nil {
		return fmt.Errorf("register service: %s", strings.TrimSpace(string(out)))
	}
	installDashboardShortcuts()
	if !*noStart {
		out, err = exec.Command("sc.exe", "start", serviceName).CombinedOutput()
		if err != nil {
			return fmt.Errorf("start service: %s", strings.TrimSpace(string(out)))
		}
	}
	return nil
}

func installDashboardShortcuts() {
	content := []byte("[InternetShortcut]\r\nURL=http://127.0.0.1:9090/\r\n")
	programData := os.Getenv("ProgramData")
	if programData == "" {
		programData = `C:\ProgramData`
	}
	paths := []string{
		filepath.Join(programData, `Microsoft\Windows\Start Menu\Programs\Kite Collector Dashboard.url`),
	}
	// Remove the MSI shortcut that starts the unsupported full dashboard. It
	// otherwise remains visible beside the compatibility dashboard URL.
	_ = os.Remove(filepath.Join(programData, `Microsoft\Windows\Start Menu\Programs\Kite Collector Dashboard.lnk`))
	if publicDir := os.Getenv("PUBLIC"); publicDir != "" {
		paths = append(paths, filepath.Join(publicDir, `Desktop\Kite Collector Dashboard.url`))
	}
	for _, path := range paths {
		_ = os.MkdirAll(filepath.Dir(path), 0755)
		_ = os.WriteFile(path, content, 0644)
	}
}

func serviceCommand(args []string) error {
	fs := flag.NewFlagSet("service run", flag.ContinueOnError)
	dir := fs.String("certs-dir", defaultDataDir(), "certificate directory")
	dashboardAddr := fs.String("dashboard-addr", "127.0.0.1:9090", "local inventory dashboard address")
	if err := fs.Parse(args); err != nil {
		return err
	}
	isService, err := svc.IsWindowsService()
	if err != nil {
		return err
	}
	if isService {
		return svc.Run(serviceName, &handler{dir: *dir, dashboardAddr: *dashboardAddr})
	}
	return loop(*dir, *dashboardAddr, make(chan struct{}))
}

type handler struct {
	dir           string
	dashboardAddr string
}

func (h *handler) Execute(_ []string, requests <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	status <- svc.Status{State: svc.StartPending}
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() { _ = loop(h.dir, h.dashboardAddr, stop); close(done) }()
	status <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	for r := range requests {
		if r.Cmd == svc.Stop || r.Cmd == svc.Shutdown {
			status <- svc.Status{State: svc.StopPending}
			close(stop)
			<-done
			return false, 0
		}
	}
	return false, 0
}

func loop(dir, dashboardAddr string, stop <-chan struct{}) error {
	log, _ := eventlog.Open(serviceName)
	if log != nil {
		defer log.Close()
		_ = log.Info(1, "Kite Collector Legacy started")
	}
	dashboard, err := startLegacyDashboard(dir, dashboardAddr)
	if err != nil && log != nil {
		_ = log.Warning(3, "dashboard: "+err.Error())
	}
	if dashboard != nil {
		defer func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = dashboard.shutdown(ctx)
		}()
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 12*time.Minute)
		defer cancel()
		if scanErr := scanAndSaveInventory(ctx, dir); scanErr != nil && log != nil {
			_ = log.Warning(4, "inventory scan: "+scanErr.Error())
		} else if syncErr := syncLatestInventory(ctx, dir); syncErr != nil && log != nil {
			_ = log.Warning(5, "inventory upstream sync: "+syncErr.Error())
		}
	}()
	heartbeatTicker := time.NewTicker(5 * time.Minute)
	scanTicker := time.NewTicker(6 * time.Hour)
	defer heartbeatTicker.Stop()
	defer scanTicker.Stop()
	runHeartbeat := func() {
		ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
		defer cancel()
		if heartbeatErr := heartbeat(ctx, dir); heartbeatErr != nil && log != nil {
			_ = log.Warning(2, heartbeatErr.Error())
		}
		if syncErr := syncLatestInventory(ctx, dir); syncErr != nil && log != nil {
			_ = log.Warning(5, "inventory upstream sync: "+syncErr.Error())
		}
	}
	runHeartbeat()
	for {
		select {
		case <-stop:
			return nil
		case <-heartbeatTicker.C:
			runHeartbeat()
		case <-scanTicker.C:
			go func() {
				ctx, cancel := context.WithTimeout(context.Background(), 12*time.Minute)
				defer cancel()
				if scanErr := scanAndSaveInventory(ctx, dir); scanErr != nil && log != nil {
					_ = log.Warning(4, "inventory scan: "+scanErr.Error())
				} else if syncErr := syncLatestInventory(ctx, dir); syncErr != nil && log != nil {
					_ = log.Warning(5, "inventory upstream sync: "+syncErr.Error())
				}
			}()
		}
	}
}

func scanCommand(args []string) error {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	dir := fs.String("certs-dir", defaultDataDir(), "data directory")
	if err := fs.Parse(args); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Minute)
	defer cancel()
	if err := scanAndSaveInventory(ctx, *dir); err != nil {
		return err
	}
	if err := syncLatestInventory(ctx, *dir); err != nil {
		return fmt.Errorf("inventory saved locally but upstream sync failed: %w", err)
	}
	snapshot, err := loadLatestInventory(*dir)
	if err != nil {
		return err
	}
	fmt.Printf("Inventory saved to %s (%d categories)\n", inventoryDBPath(*dir), len(snapshot.Categories))
	return nil
}

func queryCommand(args []string) error {
	fs := flag.NewFlagSet("query", flag.ContinueOnError)
	dir := fs.String("certs-dir", defaultDataDir(), "data directory")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() == 0 {
		snapshot, err := loadLatestInventory(*dir)
		if err != nil {
			return err
		}
		for _, category := range inventoryCategoryNames(snapshot) {
			fmt.Printf("%-28s %d\n", category, len(snapshot.Categories[category]))
		}
		return nil
	}
	rows, err := loadInventoryCategory(*dir, fs.Arg(0))
	if err != nil {
		return err
	}
	encoded, err := json.MarshalIndent(rows, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(encoded))
	return nil
}

func dashboardCommand(args []string) error {
	fs := flag.NewFlagSet("dashboard", flag.ContinueOnError)
	dir := fs.String("certs-dir", defaultDataDir(), "data directory")
	addr := fs.String("addr", "127.0.0.1:9090", "dashboard address")
	noBrowser := fs.Bool("no-browser", false, "do not open the browser")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if _, err := loadLatestInventory(*dir); err != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 12*time.Minute)
		if scanErr := scanAndSaveInventory(ctx, *dir); scanErr != nil {
			cancel()
			return scanErr
		}
		cancel()
	}
	dashboard, err := startLegacyDashboard(*dir, *addr)
	if err != nil {
		return err
	}
	defer dashboard.shutdown(context.Background())
	if !*noBrowser {
		openLegacyDashboard(*addr)
	}
	fmt.Println("Kite Windows 7 dashboard:", dashboardURL(*addr))
	select {}
}

func heartbeatCommand(args []string) error {
	fs := flag.NewFlagSet("heartbeat", flag.ContinueOnError)
	dir := fs.String("certs-dir", defaultDataDir(), "certificate directory")
	if err := fs.Parse(args); err != nil {
		return err
	}
	return heartbeat(context.Background(), *dir)
}
func heartbeat(ctx context.Context, dir string) error {
	certPEM, err := os.ReadFile(filepath.Join(dir, "agent.pem"))
	if err != nil {
		return err
	}
	keyPEM, err := os.ReadFile(filepath.Join(dir, "agent-key.pem"))
	if err != nil {
		return err
	}
	b, _ := pem.Decode(certPEM)
	if b == nil {
		return errors.New("invalid agent certificate")
	}
	cert, err := x509.ParseCertificate(b.Bytes)
	if err != nil {
		return err
	}
	kb, _ := pem.Decode(keyPEM)
	if kb == nil {
		return errors.New("invalid private key")
	}
	raw, err := x509.ParsePKCS8PrivateKey(kb.Bytes)
	if err != nil {
		return err
	}
	signer, ok := raw.(crypto.Signer)
	if !ok {
		return errors.New("unsupported private key")
	}
	nonceBytes := make([]byte, 24)
	if _, err = rand.Read(nonceBytes); err != nil {
		return err
	}
	nonce := base64.RawURLEncoding.EncodeToString(nonceBytes)
	now := time.Now().Unix()
	msg := []byte(fmt.Sprintf("kite-pki-v1\nheartbeat\n%s\n%d\n%s\n", cert.Subject.CommonName, now, nonce))
	digest := sha256.Sum256(msg)
	sig, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		return err
	}
	p := proof{AgentCode: cert.Subject.CommonName, Certificate: string(certPEM), Nonce: nonce, Signature: base64.StdEncoding.EncodeToString(sig), Timestamp: now}
	body, _ := json.Marshal(p)
	client := &http.Client{Timeout: 45 * time.Second}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, defaultPKI+"/pki/agent/heartbeat", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("heartbeat returned %s: %s", resp.Status, data)
	}
	return nil
}

func defaultDataDir() string {
	if v := os.Getenv("ProgramData"); v != "" {
		return filepath.Join(v, "kite-collector")
	}
	return `C:\ProgramData\kite-collector`
}
