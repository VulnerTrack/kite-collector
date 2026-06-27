//go:build windows

package winargfgs

import "os"

func ownerUID(_ os.FileInfo) int { return 0 }
