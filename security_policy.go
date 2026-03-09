package certkit

import (
	"fmt"
	"strings"
)

// SecurityPolicy selects an optional strictness profile for transport and
// certificate diagnostics. These are heuristic policy checks, not proof that a
// remote service is operating with a validated cryptographic module.
type SecurityPolicy string

const (
	// SecurityPolicyNone disables policy-specific diagnostics.
	SecurityPolicyNone SecurityPolicy = ""
	// SecurityPolicyFIPS1402 enables a conservative FIPS 140-2 heuristic profile.
	SecurityPolicyFIPS1402 SecurityPolicy = "fips-140-2"
	// SecurityPolicyFIPS1403 enables a conservative FIPS 140-3 heuristic profile.
	SecurityPolicyFIPS1403 SecurityPolicy = "fips-140-3"
)

// Enabled reports whether a policy profile is active.
func (p SecurityPolicy) Enabled() bool {
	return p != SecurityPolicyNone
}

// DisplayName returns a human-readable label for the selected policy.
func (p SecurityPolicy) DisplayName() string {
	switch p {
	case SecurityPolicyNone:
		return ""
	case SecurityPolicyFIPS1402:
		return "FIPS 140-2"
	case SecurityPolicyFIPS1403:
		return "FIPS 140-3"
	default:
		return ""
	}
}

type likelyNotAuthorizedDetailInput struct {
	policy   SecurityPolicy
	singular string
	plural   string
	items    []string
}

func formatLikelyNotAuthorizedDetail(input likelyNotAuthorizedDetailInput) string {
	noun := input.plural
	if len(input.items) == 1 {
		noun = input.singular
	}
	return fmt.Sprintf("%d %s likely not authorized by %s: %s", len(input.items), noun, input.policy.DisplayName(), strings.Join(input.items, ", "))
}
