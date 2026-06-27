//go:build windows

package winargcrypto

import "os"

func ownerUID(_ os.FileInfo) int { return 0 }
