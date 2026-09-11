package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/vulnertrack/kite-collector/internal/config"
	"github.com/vulnertrack/kite-collector/internal/enrollment"
	"github.com/vulnertrack/kite-collector/internal/identity"
	"github.com/vulnertrack/kite-collector/internal/store/sqlite"
)

func runDeviceEnrollment(out io.Writer, agentCode, dbPath, certsDir string, userMode bool) error {
	return runDeviceEnrollmentWithDeps(out, agentCode, dbPath, certsDir, userMode, enrollment.NewClient(slog.Default()).EnrollDevice, transitionEnrolledService)
}

func runDeviceEnrollmentWithDeps(out io.Writer, agentCode, dbPath, certsDir string, userMode bool, enroll func(context.Context, string, func(enrollment.DeviceAuthorization) error) (*enrollment.Result, error), transition func(bool) (string, error)) error {
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	if agentCode == "" {
		fingerprint := strings.TrimPrefix(identity.MachineFingerprint(), "sha256:")
		agentCode = "kite-" + fingerprint[:min(20, len(fingerprint))]
	}
	if certsDir == "" {
		certsDir = filepath.Dir(dbPath)
	}
	// Open/migrate storage before asking the user to approve this machine.
	st, err := openSQLiteStore(dbPath, config.IdentityConfig{})
	if err != nil {
		return fmt.Errorf("open enrollment store: %w", err)
	}
	storeOpen := true
	defer func() {
		if storeOpen {
			_ = st.Close()
		}
	}()
	if migrateErr := st.Migrate(ctx); migrateErr != nil {
		return fmt.Errorf("migrate enrollment store: %w", migrateErr)
	}
	identities, ok := st.Store.(*sqlite.SQLiteStore)
	if !ok {
		return fmt.Errorf("device enrollment requires SQLite")
	}
	result, err := enroll(ctx, agentCode, func(auth enrollment.DeviceAuthorization) error {
		_, displayErr := fmt.Fprintf(out, "\nOn your computer, open: %s\nCollector: %s\nWaiting for approval (expires in %d seconds). Press Ctrl+C to cancel.\n", auth.VerificationURIComplete, agentCode, auth.ExpiresIn)
		if displayErr != nil {
			return fmt.Errorf("display device code: %w", displayErr)
		}
		return nil
	})
	if err != nil {
		return err
	}
	if storeErr := enrollment.StoreCertificates(certsDir, result); storeErr != nil {
		return fmt.Errorf("save enrollment certificates: %w", storeErr)
	}
	// mTLS is the credential. Do not persist the already-consumed device token
	// or pretend it is a reusable platform API key.
	if recordErr := identities.UpsertEnrolledIdentity(ctx, sqlite.EnrolledIdentity{
		ApiKeyFingerprint: "certificate:" + sqlite.APIKeyFingerprint(string(result.ClientCertificate)),
		ApiKeyWrapped:     []byte{},
	}); recordErr != nil {
		return fmt.Errorf("record certificate enrollment: %w", recordErr)
	}
	if closeErr := st.Close(); closeErr != nil {
		return fmt.Errorf("close enrollment store: %w", closeErr)
	}
	storeOpen = false
	action, err := transition(userMode)
	if err != nil {
		return fmt.Errorf("certificate saved; service transition failed: %w", err)
	}
	_, err = fmt.Fprintf(out, "Collector %s enrolled. Certificates: %s. Service: %s\n", agentCode, certsDir, action)
	if err != nil {
		return fmt.Errorf("display enrollment result: %w", err)
	}
	return nil
}
