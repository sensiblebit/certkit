//go:build darwin && !js

package certstore

import (
	"errors"
	"fmt"

	"golang.org/x/sys/unix"
)

func renameSQLiteFileNoReplace(oldPath, newPath string) error {
	err := unix.RenamexNp(oldPath, newPath, unix.RENAME_EXCL)
	if err == nil {
		return nil
	}
	if errors.Is(err, unix.ENOSYS) || errors.Is(err, unix.EINVAL) ||
		errors.Is(err, unix.EOPNOTSUPP) || errors.Is(err, unix.ENOTSUP) {
		return errSQLiteNoReplaceRenameUnsupported
	}
	return fmt.Errorf("no-replace rename %s: %w", newPath, err)
}
