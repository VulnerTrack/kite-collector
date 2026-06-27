//go:build windows

package winargallaria

import "os"

func ownerUID(_ os.FileInfo) int { return 0 }
