//go:build windows

package winargmercap

import "os"

func ownerUID(_ os.FileInfo) int { return 0 }
