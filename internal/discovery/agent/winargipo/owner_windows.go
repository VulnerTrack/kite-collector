//go:build windows

package winargipo

import "os"

func ownerUID(_ os.FileInfo) int { return 0 }
