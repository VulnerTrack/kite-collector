//go:build windows

package winargmodel

import "os"

func ownerUID(_ os.FileInfo) int { return 0 }
