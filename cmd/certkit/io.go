package main

import (
	"fmt"

	"github.com/sensiblebit/certkit/internal"
)

func readCLIFile(path string) ([]byte, error) {
	data, err := internal.ReadFileLimited(path, 0)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	return data, nil
}
