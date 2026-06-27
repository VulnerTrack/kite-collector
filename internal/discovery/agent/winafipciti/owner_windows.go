//go:build windows

package winafipciti

import "os"

func ownerUID(_ os.FileInfo) int { return 0 }
