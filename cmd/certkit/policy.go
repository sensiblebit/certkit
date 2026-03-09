package main

import (
	"errors"

	"github.com/sensiblebit/certkit"
)

var errConflictingFIPSPolicies = errors.New("choose only one of --fips-140-2 or --fips-140-3")

func selectedPolicy(fips1402, fips1403 bool) (certkit.SecurityPolicy, error) {
	switch {
	case fips1402 && fips1403:
		return certkit.SecurityPolicyNone, errConflictingFIPSPolicies
	case fips1402:
		return certkit.SecurityPolicyFIPS1402, nil
	case fips1403:
		return certkit.SecurityPolicyFIPS1403, nil
	default:
		return certkit.SecurityPolicyNone, nil
	}
}
