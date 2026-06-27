//go:build windows

package winargbloomberg

import "os"

func ownerUID(_ os.FileInfo) int { return 0 }
