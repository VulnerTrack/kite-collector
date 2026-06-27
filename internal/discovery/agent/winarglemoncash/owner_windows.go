//go:build windows

package winarglemoncash

import "os"

func ownerUID(_ os.FileInfo) int { return 0 }
