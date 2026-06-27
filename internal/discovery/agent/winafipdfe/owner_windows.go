//go:build windows

package winafipdfe

import "os"

func ownerUID(_ os.FileInfo) int { return 0 }
