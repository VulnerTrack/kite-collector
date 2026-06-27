//go:build windows

package winargpymebursatil

import "os"

func ownerUID(_ os.FileInfo) int { return 0 }
