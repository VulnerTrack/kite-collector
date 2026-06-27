//go:build windows

package winargcrs

import "os"

func ownerUID(_ os.FileInfo) int { return 0 }
