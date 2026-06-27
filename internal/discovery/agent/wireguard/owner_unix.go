//go:build darwin || linux || freebsd || openbsd || netbsd

package wireguard

import (
	"os"
	"syscall"
)

func populateOwner(t *Tunnel, fi os.FileInfo) {
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		t.FileOwnerUID = int(st.Uid)
	}
}
