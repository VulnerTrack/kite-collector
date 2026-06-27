//go:build windows

package winargmatbarofex

import "os"

func ownerUID(_ os.FileInfo) int { return 0 }
