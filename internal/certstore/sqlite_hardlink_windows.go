//go:build windows && !js

package certstore

import (
	"errors"

	"golang.org/x/sys/windows"
)

func isPlatformHardLinkUnsupported(err error) bool {
	return errors.Is(err, windows.ERROR_NOT_SUPPORTED) ||
		errors.Is(err, windows.ERROR_INVALID_FUNCTION) ||
		errors.Is(err, windows.ERROR_PRIVILEGE_NOT_HELD) ||
		errors.Is(err, windows.ERROR_ACCESS_DENIED)
}
