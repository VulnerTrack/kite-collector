//go:build windows

package winargccxt

import "os"

func ownerUID(_ os.FileInfo) int { return 0 }
