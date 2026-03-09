//go:build !js

package certkit

import (
	"context"
	"fmt"
	"net"
)

func defaultLookupIPAddresses(ctx context.Context, host string) ([]net.IP, error) {
	ips, err := net.DefaultResolver.LookupIP(ctx, "ip", host)
	if err != nil {
		return nil, fmt.Errorf("lookup IP addresses for %s: %w", host, err)
	}
	return ips, nil
}

func aiaDNSResolutionAvailable() bool {
	return true
}
