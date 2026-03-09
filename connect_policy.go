package certkit

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"slices"
)

func diagnoseNegotiatedCipherPolicy(protocol, cipherSuite string, policy SecurityPolicy) []ChainDiagnostic {
	if !policy.Enabled() {
		return nil
	}
	if cipherSuiteAllowedByPolicy(protocol, cipherSuite, policy) {
		return nil
	}
	return []ChainDiagnostic{{
		Check:  "policy-cipher",
		Status: "warn",
		Detail: fmt.Sprintf("negotiated cipher suite %s under %s is likely not authorized by %s", cipherSuite, protocol, policy.DisplayName()),
	}}
}

func diagnosePeerChainPolicy(peerChain []*x509.Certificate, policy SecurityPolicy) []ChainDiagnostic {
	if !policy.Enabled() || len(peerChain) == 0 {
		return nil
	}

	leaf := peerChain[0]
	var diags []ChainDiagnostic
	if !certificatePublicKeyAllowedByPolicy(leaf, policy) {
		diags = append(diags, ChainDiagnostic{
			Check:  "policy-cert-key",
			Status: "warn",
			Detail: fmt.Sprintf("leaf certificate public key algorithm %s is likely not authorized by %s", publicKeyAlgorithmName(leaf), policy.DisplayName()),
		})
	}
	if !certificateSignatureAllowedByPolicy(leaf, policy) {
		diags = append(diags, ChainDiagnostic{
			Check:  "policy-cert-signature",
			Status: "warn",
			Detail: fmt.Sprintf("leaf certificate signature algorithm %s is likely not authorized by %s", leaf.SignatureAlgorithm, policy.DisplayName()),
		})
	}
	return diags
}

// DiagnoseCipherScanPolicy reports policy-specific findings for an advertised
// TLS cipher scan. These checks are heuristic policy gates, not proof of
// formal module validation.
func DiagnoseCipherScanPolicy(r *CipherScanResult) []ChainDiagnostic {
	if r == nil || !r.Policy.Enabled() {
		return nil
	}

	allCiphers := slices.Concat(r.Ciphers, r.QUICCiphers)
	if len(allCiphers) == 0 {
		return nil
	}

	var diags []ChainDiagnostic
	if disallowed := disallowedCipherScanEntries(r); len(disallowed) > 0 {
		diags = append(diags, ChainDiagnostic{
			Check:  "policy-cipher",
			Status: "warn",
			Detail: formatLikelyNotAuthorizedDetail(r.Policy, "advertised cipher suite", "advertised cipher suites", disallowed),
		})
	}
	if disallowed := disallowedProtocolVersions(r); len(disallowed) > 0 {
		diags = append(diags, ChainDiagnostic{
			Check:  "policy-protocol",
			Status: "warn",
			Detail: formatLikelyNotAuthorizedDetail(r.Policy, "protocol version", "protocol versions", disallowed),
		})
	}
	return diags
}

func scanCipherPolicyViolationCount(r *CipherScanResult) int {
	if r == nil || !r.Policy.Enabled() {
		return 0
	}
	return len(disallowedCipherScanEntries(r)) + len(disallowedProtocolVersions(r))
}

func disallowedCipherScanEntries(r *CipherScanResult) []string {
	allCiphers := slices.Concat(r.Ciphers, r.QUICCiphers)
	disallowed := make([]string, 0, len(allCiphers))
	seen := make(map[string]bool, len(allCiphers))
	for _, c := range allCiphers {
		key := c.Version + ":" + c.Name
		if seen[key] {
			continue
		}
		seen[key] = true
		if !cipherSuiteAllowedByPolicy(c.Version, c.Name, r.Policy) {
			disallowed = append(disallowed, c.Version+" "+c.Name)
		}
	}
	return disallowed
}

func disallowedProtocolVersions(r *CipherScanResult) []string {
	disallowed := make([]string, 0, len(r.SupportedVersions))
	for _, version := range r.SupportedVersions {
		if tlsVersionAllowedByPolicy(version, r.Policy) {
			continue
		}
		disallowed = append(disallowed, version)
	}
	return disallowed
}

func tlsVersionAllowedByPolicy(version string, policy SecurityPolicy) bool {
	if !policy.Enabled() {
		return true
	}
	return version == "TLS 1.2" || version == "TLS 1.3"
}

func cipherSuiteAllowedByPolicy(protocol, cipherSuite string, policy SecurityPolicy) bool {
	if !policy.Enabled() {
		return true
	}
	if !tlsVersionAllowedByPolicy(protocol, policy) {
		return false
	}

	switch protocol {
	case "TLS 1.3":
		switch cipherSuite {
		case "TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384", "TLS_AES_128_CCM_SHA256":
			return true
		default:
			return false
		}
	case "TLS 1.2":
		switch cipherSuite {
		case "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
			"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384":
			return true
		default:
			return false
		}
	default:
		return false
	}
}

func certificatePublicKeyAllowedByPolicy(cert *x509.Certificate, policy SecurityPolicy) bool {
	if !policy.Enabled() || cert == nil {
		return true
	}
	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		return pub.N.BitLen() >= 2048
	case *ecdsa.PublicKey:
		switch pub.Curve.Params().Name {
		case "P-256", "P-384", "P-521":
			return true
		default:
			return false
		}
	case ed25519.PublicKey:
		return false
	default:
		return false
	}
}

func certificateSignatureAllowedByPolicy(cert *x509.Certificate, policy SecurityPolicy) bool {
	if !policy.Enabled() || cert == nil {
		return true
	}
	switch cert.SignatureAlgorithm {
	case x509.SHA256WithRSA, x509.SHA384WithRSA, x509.SHA512WithRSA,
		x509.ECDSAWithSHA256, x509.ECDSAWithSHA384, x509.ECDSAWithSHA512,
		x509.SHA256WithRSAPSS, x509.SHA384WithRSAPSS, x509.SHA512WithRSAPSS:
		return true
	case x509.UnknownSignatureAlgorithm, x509.MD2WithRSA, x509.MD5WithRSA,
		x509.SHA1WithRSA, x509.DSAWithSHA1, x509.DSAWithSHA256, x509.ECDSAWithSHA1, x509.PureEd25519:
		return false
	default:
		return false
	}
}

func publicKeyAlgorithmName(cert *x509.Certificate) string {
	if cert == nil {
		return "unknown"
	}
	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		return fmt.Sprintf("RSA-%d", pub.N.BitLen())
	case *ecdsa.PublicKey:
		return "ECDSA-" + pub.Curve.Params().Name
	case ed25519.PublicKey:
		return "Ed25519"
	default:
		return cert.PublicKeyAlgorithm.String()
	}
}
