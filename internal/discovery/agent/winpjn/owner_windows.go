//go:build windows

package winpjn

import "os"

func ownerUID(_ os.FileInfo) int { return 0 }
