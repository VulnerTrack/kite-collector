//go:build windows

package winargdas

import "os"

func ownerUID(_ os.FileInfo) int { return 0 }
