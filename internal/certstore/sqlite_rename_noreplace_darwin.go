//go:build darwin && !js

package certstore

import (
	"fmt"

	"golang.org/x/sys/unix"
)

func renameSQLiteFileNoReplace(oldPath, newPath string) error {
	if err := unix.RenamexNp(oldPath, newPath, unix.RENAME_EXCL); err != nil {
		return fmt.Errorf("no-replace rename %s: %w", newPath, err)
	}
	return nil
}
