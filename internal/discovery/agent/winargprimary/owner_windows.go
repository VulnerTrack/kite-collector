//go:build windows

package winargprimary

import "os"

func ownerUID(_ os.FileInfo) int { return 0 }
