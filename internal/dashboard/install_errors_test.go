package dashboard

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestCategorizeInstallError pins the error-string taxonomy so a future
// change to error wrapping or platform-specific strings doesn't silently
// downgrade a categorized recovery action to the generic CLI hint.
//
// Add a row whenever you discover a new error string in the wild — the
// installErrorCategory consts in install_errors.go are the source of truth.
func TestCategorizeInstallError(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want installErrorCategory
	}{
		{
			name: "nil-error-falls-through",
			err:  nil,
			want: installErrOther,
		},
		{
			name: "permission-denied-unix",
			err:  errors.New("install binary: open /usr/local/bin/kite-collector.tmp: permission denied"),
			want: installErrPermission,
		},
		{
			name: "operation-not-permitted",
			err:  errors.New("install service: operation not permitted"),
			want: installErrPermission,
		},
		{
			name: "access-is-denied-windows",
			err:  errors.New("create service handle: Access is denied."),
			want: installErrPermission,
		},
		{
			name: "must-be-root-explicit",
			err:  errors.New("kite-collector: this operation must be root"),
			want: installErrPermission,
		},
		{
			name: "read-only-filesystem",
			err:  errors.New("create binary dir: read-only file system"),
			want: installErrDiskWrite,
		},
		{
			name: "no-space-left",
			err:  errors.New("copy binary: write /usr/local/bin/kite-collector.tmp: no space left on device"),
			want: installErrDiskWrite,
		},
		{
			name: "no-init-system",
			err:  errors.New("create service: no init system found"),
			want: installErrServiceMgr,
		},
		{
			name: "systemd-unit-missing",
			err:  errors.New("install service: systemd: no such file or directory"),
			want: installErrServiceMgr,
		},
		{
			name: "windows-scm-error",
			err:  errors.New("create service handle: openSCManager: service control manager unavailable"),
			want: installErrServiceMgr,
		},
		{
			name: "novel-error-falls-through-to-other",
			err:  errors.New("something exploded in an unexpected way"),
			want: installErrOther,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, categorizeInstallError(tc.err))
		})
	}
}
