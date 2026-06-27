//go:build windows

package winargccp

import "os"

func ownerUID(_ os.FileInfo) int { return 0 }
