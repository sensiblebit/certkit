package internal

import (
	"os"
	"testing"
)

func createSymlinkOrSkip(t *testing.T, target, link string) {
	t.Helper()
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("skipping symlink-dependent test: %v", err)
	}
}
