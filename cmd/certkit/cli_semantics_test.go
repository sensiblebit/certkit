package main

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/sensiblebit/certkit"
)

func TestJSONSchemaConsistency(t *testing.T) {
	// WHY: JSON field names are a CLI contract; regressions in key names would
	// break downstream integrations expecting stable schema keys.
	t.Parallel()

	t.Run("ocsp verbose uses subject and issuer keys", func(t *testing.T) {
		t.Parallel()
		data, err := json.Marshal(ocspVerboseJSON{
			OCSPResult: &certkit.OCSPResult{
				Status:       "good",
				SerialNumber: "0x2a",
				ThisUpdate:   "2026-03-09T12:00:00Z",
				NextUpdate:   "2026-03-10T12:00:00Z",
			},
			Subject: "CN=leaf",
			Issuer:  "CN=issuer",
		})
		if err != nil {
			t.Fatalf("marshal ocsp verbose: %v", err)
		}
		jsonText := string(data)
		for _, key := range []string{`"subject"`, `"issuer"`, `"serial"`, `"this_update"`, `"next_update"`} {
			if !strings.Contains(jsonText, key) {
				t.Fatalf("ocsp verbose json missing %s: %s", key, jsonText)
			}
		}
		for _, key := range []string{`"cert_subject"`, `"cert_issuer"`, `"serial_number"`, `"not_before"`, `"not_after"`} {
			if strings.Contains(jsonText, key) {
				t.Fatalf("ocsp verbose json contains legacy key %s: %s", key, jsonText)
			}
		}
	})

	t.Run("crl info uses protocol update keys", func(t *testing.T) {
		t.Parallel()
		data, err := json.Marshal(crlOutputJSON{
			CRLInfo: &certkit.CRLInfo{
				Issuer:             "CN=issuer",
				ThisUpdate:         "2026-03-09T12:00:00Z",
				NextUpdate:         "2026-03-10T12:00:00Z",
				NumEntries:         1,
				SignatureAlgorithm: "SHA256-RSA",
				CRLNumber:          "7",
			},
			CheckResult: &crlCheckResult{
				Serial:  "0x2a",
				Revoked: true,
			},
		})
		if err != nil {
			t.Fatalf("marshal crl json: %v", err)
		}
		jsonText := string(data)
		for _, key := range []string{`"issuer"`, `"this_update"`, `"next_update"`, `"num_entries"`, `"signature_algorithm"`, `"check_result"`, `"serial"`} {
			if !strings.Contains(jsonText, key) {
				t.Fatalf("crl json missing %s: %s", key, jsonText)
			}
		}
		for _, key := range []string{`"not_before"`, `"not_after"`, `"serial_number"`} {
			if strings.Contains(jsonText, key) {
				t.Fatalf("crl json contains inconsistent key %s: %s", key, jsonText)
			}
		}
	})

	t.Run("payload uses data with explicit encoding", func(t *testing.T) {
		t.Parallel()
		data, err := json.Marshal(payloadJSON{Data: "Zm9v", Encoding: "base64", Format: "p12"})
		if err != nil {
			t.Fatalf("marshal payload json: %v", err)
		}
		jsonText := string(data)
		for _, key := range []string{`"data"`, `"encoding"`, `"format"`} {
			if !strings.Contains(jsonText, key) {
				t.Fatalf("payload json missing %s: %s", key, jsonText)
			}
		}
		if strings.Contains(jsonText, `"chain_pem"`) {
			t.Fatalf("payload json contains legacy chain_pem key: %s", jsonText)
		}
	})
}

func TestTreeCommand(t *testing.T) {
	state := snapshotReadonlyGlobals()
	defer restoreReadonlyGlobals(state)

	// This test mutates the shared Cobra command graph to force default
	// help/version/completion registration, so it must stay serialized.
	prevVersion := rootCmd.Version
	t.Cleanup(func() {
		rootCmd.Version = prevVersion
	})
	rootCmd.Version = "test"
	initTreeSurface(rootCmd)

	// Build tree output once to avoid concurrent Cobra Commands() sorting.
	var rootTree strings.Builder
	printCommandTree(&rootTree, printCommandTreeInput{cmd: rootCmd})
	rootOutput := rootTree.String()

	// Snapshot every non-hidden command before subtests run.
	var expectedCommands []string
	for _, child := range rootCmd.Commands() {
		if child.Hidden {
			continue
		}
		expectedCommands = append(expectedCommands, child.Name()+" — "+child.Short)
	}

	t.Run("includes all non-hidden commands", func(t *testing.T) {
		for _, entry := range expectedCommands {
			if !strings.Contains(rootOutput, entry) {
				t.Errorf("tree output missing command %q", entry)
			}
		}
	})

	t.Run("includes help and completion", func(t *testing.T) {
		for _, name := range []string{"help", "completion"} {
			if !strings.Contains(rootOutput, name+" — ") {
				t.Errorf("tree output missing built-in command %q", name)
			}
		}
	})

	t.Run("includes nested subcommands", func(t *testing.T) {
		if !strings.Contains(rootOutput, "self-signed — Create a self-signed certificate") {
			t.Errorf("tree output missing nested command %q", "self-signed")
		}
		if !strings.Contains(rootOutput, "csr — Sign a CSR with a CA certificate and key") {
			t.Errorf("tree output missing nested command %q", "csr")
		}
	})

	t.Run("includes help and version flags", func(t *testing.T) {
		for _, flag := range []string{"--help", "--version"} {
			if !strings.Contains(rootOutput, flag) {
				t.Errorf("tree output missing flag %q", flag)
			}
		}
	})

	t.Run("includes subcommand help and inherited global flags", func(t *testing.T) {
		var bundleTree strings.Builder
		fmt.Fprintf(&bundleTree, "%s — %s\n", bundleCmd.Name(), bundleCmd.Short)
		printCommandTree(&bundleTree, printCommandTreeInput{cmd: bundleCmd})
		bundleSection := bundleTree.String()
		if !strings.Contains(bundleSection, "inherits: ") {
			t.Fatal("bundle subtree missing inherited flag summary")
		}
		for _, flag := range []string{"--help", "--password-file", "--passwords", "--verbose", "--json", "--allow-expired"} {
			if !strings.Contains(bundleSection, flag) {
				t.Errorf("bundle subtree missing inherited flag %q", flag)
			}
		}
		for _, localFlag := range []string{"--format", "--out-file", "--trust-store"} {
			if !strings.Contains(bundleSection, localFlag) {
				t.Errorf("bundle subtree missing local flag %q", localFlag)
			}
		}
	})

	t.Run("prefers long flag names over shorthand pairs", func(t *testing.T) {
		for _, flag := range []string{"-h, --help", "-l, --log-level", "-p, --passwords", "-v, --verbose"} {
			if strings.Contains(rootOutput, flag) {
				t.Errorf("tree output should omit shorthand pair %q", flag)
			}
		}
	})

	t.Run("collapses inherited flags to one summary line", func(t *testing.T) {
		if strings.Count(rootOutput, "inherits: ") == 0 {
			t.Fatal("tree output missing inherited flag summaries")
		}
		if strings.Count(rootOutput, "\n│   ├── --json\n")+strings.Count(rootOutput, "\n│   └── --json\n") != 0 {
			t.Fatal("tree output should not repeat inherited flags as standalone subcommand entries")
		}
	})

	t.Run("rejects arguments", func(t *testing.T) {
		if treeCmd.Args == nil {
			t.Fatal("treeCmd.Args is nil; expected cobra.NoArgs")
		}
		if err := treeCmd.Args(treeCmd, []string{"unexpected"}); err == nil {
			t.Fatal("expected error for unexpected argument")
		}
	})

	t.Run("uses box-drawing connectors", func(t *testing.T) {
		for _, connector := range []string{"├── ", "└── ", "│   "} {
			if !strings.Contains(rootOutput, connector) {
				t.Errorf("tree output missing connector %q", connector)
			}
		}
	})
}
