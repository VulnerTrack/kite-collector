//go:build darwin || linux || freebsd || openbsd || netbsd

package wingit

import (
	"os"
	"syscall"
)

func ownerUID(fi os.FileInfo) int {
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		return int(st.Uid)
	}
	return 0
}
