//go:build kite_preview

package dashboard

import (
	"errors"
	"net"
	"net/http"
	"testing"

	kiteerrors "github.com/vulnertrack/kite-collector/internal/errors"
)

// Run with: go test -tags kite_preview ./internal/dashboard -run TestKiteOAuthPreviewServer -v -timeout=0
// The dashboard uses a temporary database; only the preview callback is simulated.
func TestKiteOAuthPreviewServer(t *testing.T) {
	const address = "127.0.0.1:9090"
	st := testStore(t)
	srv := Serve(address, st, testContext(), nil, Options{
		AppVersion: "preview",
		CertsDir:   t.TempDir(),
	})
	original := srv.Handler
	srv.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		preview := r.URL.Query().Get("preview")
		if r.URL.Path == "/oauth/callback" && (preview == "kite" || preview == "role" || preview == "membership") {
			pkiErr := kiteerrors.FromCatalog(kiteerrors.CodeEnrollmentFailed,
				errors.New("PKI rejected enrollment")).
				With("http_status", http.StatusForbidden).
				With("pki_detail", "Kite enrollment is not enabled for this user").
				With("pki_user_email", "usuario@gmail.com")
			serveKiteOAuthErrorPage(w, http.StatusInternalServerError,
				kiteOAuthEnrollmentError(pkiErr, "preview"))
			return
		}
		original.ServeHTTP(w, r)
	})

	listener, err := net.Listen("tcp", address)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("Kite preview: http://%s/oauth/callback?preview=kite", address)
	if err := srv.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
		t.Fatal(err)
	}
}
