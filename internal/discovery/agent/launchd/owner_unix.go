//go:build darwin || linux || freebsd || openbsd || netbsd

package launchd

import (
	"os"
	"syscall"
)

func populateOwner(s *Service, fi os.FileInfo) {
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		s.FileOwnerUID = int(st.Uid)
		s.FileOwnerGID = int(st.Gid)
	}
}
