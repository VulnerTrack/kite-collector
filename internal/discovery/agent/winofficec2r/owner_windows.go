//go:build windows

package winofficec2r

import "os"

func ownerUID(_ os.FileInfo) int { return 0 }
