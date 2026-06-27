//go:build windows

package winargabogado

import "os"

func ownerUID(_ os.FileInfo) int { return 0 }
