//go:build !darwin && !linux && !freebsd && !openbsd && !netbsd

package launchd

import "os"

func populateOwner(_ *Service, _ os.FileInfo) {}
