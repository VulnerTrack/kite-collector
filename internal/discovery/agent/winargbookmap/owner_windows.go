//go:build windows

package winargbookmap

import "os"

func ownerUID(_ os.FileInfo) int { return 0 }
