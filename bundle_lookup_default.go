//go:build !js

package certkit

import (
	"context"
	"net"
)

func defaultLookupIPAddresses(ctx context.Context, host string) ([]net.IP, error) {
	return net.DefaultResolver.LookupIP(ctx, "ip", host)
}

func aiaDNSResolutionAvailable() bool {
	return true
}
