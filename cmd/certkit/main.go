//go:build !gendocs

package main

import (
	"errors"
	"fmt"
	"os"
	"runtime/debug"
)

var version = "dev"

func init() {
	// Safety net: prevent runaway memory from malformed binary files triggering
	// pathological ASN.1 allocations. 1GB is generous for any cert operation.
	debug.SetMemoryLimit(1 << 30)
}

func main() {
	rootCmd.Version = version
	if err := rootCmd.Execute(); err != nil {
		if ve, ok := errors.AsType[*ValidationError](err); ok {
			if !ve.Quiet {
				fmt.Fprintf(os.Stderr, "Error: %s\n", err)
			}
			os.Exit(2)
		}
		fmt.Fprintf(os.Stderr, "Error: %s\n", err)
		os.Exit(1)
	}
}
