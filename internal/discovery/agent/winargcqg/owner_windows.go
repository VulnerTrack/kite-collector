//go:build windows

package winargcqg

import "os"

func ownerUID(_ os.FileInfo) int { return 0 }
