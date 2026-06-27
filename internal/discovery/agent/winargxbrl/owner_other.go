//go:build !darwin && !linux && !freebsd && !openbsd && !netbsd

package winargxbrl

import "os"

func ownerUID(_ os.FileInfo) int { return 0 }
