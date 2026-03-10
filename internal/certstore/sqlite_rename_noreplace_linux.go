//go:build linux && !js

package certstore

import (
	"fmt"

	"golang.org/x/sys/unix"
)

func renameSQLiteFileNoReplace(oldPath, newPath string) error {
	if err := unix.Renameat2(unix.AT_FDCWD, oldPath, unix.AT_FDCWD, newPath, unix.RENAME_NOREPLACE); err != nil {
		return fmt.Errorf("no-replace rename %s: %w", newPath, err)
	}
	return nil
}
