//go:build windows

package winargsgr

import "os"

func ownerUID(_ os.FileInfo) int { return 0 }
