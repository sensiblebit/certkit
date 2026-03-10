//go:build !js && !linux && !darwin

package certstore

func renameSQLiteFileNoReplace(oldPath, newPath string) error {
	_ = oldPath
	_ = newPath
	return errSQLiteNoReplaceRenameUnsupported
}
