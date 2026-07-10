package errors

import (
	stderrors "errors"
	"fmt"
	"os"
	"strings"
	"testing"
)

func TestWrapFileError_PermissionSurfacesCatalogE008(t *testing.T) {
	err := WrapFileError("write cert", fmt.Errorf("open /etc/kite/agent.pem: %w", os.ErrPermission))

	var ke *Error
	if !stderrors.As(err, &ke) {
		t.Fatalf("expected *Error, got %T: %v", err, err)
	}
	if ke.Code != "KITE-E008" {
		t.Errorf("Code = %q, want KITE-E008", ke.Code)
	}
	if ke.Hint == "" {
		t.Error("expected the E008 remediation hint to be populated")
	}
	if !stderrors.Is(err, os.ErrPermission) {
		t.Error("must remain detectable as a permission error via errors.Is")
	}
	if !strings.Contains(err.Error(), "write cert") {
		t.Errorf("operation context lost: %q", err.Error())
	}
}

func TestWrapFileError_NonPermissionStaysGeneric(t *testing.T) {
	err := WrapFileError("read cert", stderrors.New("unexpected EOF"))

	var ke *Error
	if stderrors.As(err, &ke) {
		t.Error("non-permission errors must not be labelled E008")
	}
	if !strings.Contains(err.Error(), "read cert") {
		t.Errorf("operation context lost: %q", err.Error())
	}
}

func TestWrapFileError_NilStaysNil(t *testing.T) {
	if err := WrapFileError("noop", nil); err != nil {
		t.Errorf("nil input must return nil, got %v", err)
	}
}
