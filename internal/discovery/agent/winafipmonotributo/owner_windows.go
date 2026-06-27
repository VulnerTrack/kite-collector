//go:build windows

package winafipmonotributo

import "os"

func ownerUID(_ os.FileInfo) int { return 0 }
