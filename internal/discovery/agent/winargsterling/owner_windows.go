//go:build windows

package winargsterling

import "os"

func ownerUID(_ os.FileInfo) int { return 0 }
