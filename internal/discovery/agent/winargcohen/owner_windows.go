//go:build windows

package winargcohen

import "os"

func ownerUID(_ os.FileInfo) int { return 0 }
