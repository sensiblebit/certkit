//go:build js

package certkit

import (
	"context"
	"net"
)

func defaultLookupIPAddresses(_ context.Context, _ string) ([]net.IP, error) {
	return nil, nil
}

func aiaDNSResolutionAvailable() bool {
	return false
}
