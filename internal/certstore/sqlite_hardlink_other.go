//go:build !windows && !js

package certstore

func isPlatformHardLinkUnsupported(err error) bool {
	_ = err
	return false
}
