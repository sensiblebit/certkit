package internal

import (
	"strings"
	"testing"
)

func TestLoadContainerFile_NotFound(t *testing.T) {
	// WHY: A nonexistent file must return an error, not panic or return empty contents.
	_, err := LoadContainerFile("/nonexistent/file.pem", nil)
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
	if !strings.Contains(err.Error(), "reading") {
		t.Errorf("unexpected error: %v", err)
	}
}
