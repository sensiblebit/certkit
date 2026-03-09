package internal

import "testing"

func mustReadTestFile(t *testing.T, path string) []byte {
	t.Helper()

	data, err := ReadFileLimited(path, 0)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return data
}
