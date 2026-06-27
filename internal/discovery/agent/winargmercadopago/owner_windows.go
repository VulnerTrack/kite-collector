//go:build windows

package winargmercadopago

import "os"

func ownerUID(_ os.FileInfo) int { return 0 }
