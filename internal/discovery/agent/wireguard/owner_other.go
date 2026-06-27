//go:build !darwin && !linux && !freebsd && !openbsd && !netbsd

package wireguard

import "os"

func populateOwner(_ *Tunnel, _ os.FileInfo) {}
