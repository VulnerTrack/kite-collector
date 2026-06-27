//go:build windows

package macoshomebrew

import "os"

func ownerUID(_ os.FileInfo) int { return 0 }
