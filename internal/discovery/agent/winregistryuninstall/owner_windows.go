//go:build windows

package winregistryuninstall

import "os"

func ownerUID(_ os.FileInfo) int { return 0 }
