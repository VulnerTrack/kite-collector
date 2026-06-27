//go:build windows

package winargquantower

import "os"

func ownerUID(_ os.FileInfo) int { return 0 }
