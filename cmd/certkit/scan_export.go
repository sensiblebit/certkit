package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/sensiblebit/certkit"
	"github.com/sensiblebit/certkit/internal"
	"github.com/sensiblebit/certkit/internal/certstore"
)

type scanRefreshFlags struct {
	Names              []string
	Only               []string
	Required           []string
	Formats            []string
	InputPasswordFile  string
	OutputPasswordFile string
	Write              bool
	DryRun             bool
	FailOnSkip         bool
}

var errScanRefreshOptions = errors.New("invalid managed bundle options")

var scanRefresh scanRefreshFlags
var scanPlanBundles = internal.PlanBundleExports

func init() {
	flags := scanCmd.Flags()
	flags.StringSliceVar(&scanRefresh.Names, "bundle-name", nil, "Export only these configured bundle names (repeatable)")
	flags.StringSliceVar(&scanRefresh.Only, "only", nil, "Alias for --bundle-name (repeatable)")
	flags.StringSliceVar(&scanRefresh.Required, "require-bundle", nil, "Fail unless each named bundle can be produced (repeatable)")
	flags.StringSliceVar(&scanRefresh.Formats, "formats", nil, "Bundle artifacts: pem,key,chain,fullchain,intermediates,root,json,yaml,p12,k8s,csr,csr-json (default pem,key,chain,fullchain,intermediates,root,json,p12)")
	flags.StringVar(&scanRefresh.InputPasswordFile, "input-password-file", "", "Input decryption passwords, one per line; never used for output encryption")
	flags.StringVar(&scanRefresh.OutputPasswordFile, "output-password-file", "", "Output password for encrypted key/YAML and P12 artifacts (P12 defaults to changeit; key/YAML remain unencrypted)")
	flags.BoolVar(&scanRefresh.Write, "write", false, "Apply the bundle export plan (default is a read-only preview)")
	flags.BoolVar(&scanRefresh.DryRun, "dry-run", false, "Show the export plan without writing any files")
	flags.BoolVar(&scanRefresh.FailOnSkip, "fail-on-skip", false, "Fail the entire export if any requested bundle is skipped")
	// These command-local flags deliberately shadow the legacy shared semantics.
	flags.StringSliceVarP(&passwordList, "passwords", "p", nil, "Comma-separated input decryption passwords; never used for scan output encryption")
	flags.StringVar(&passwordFile, "password-file", "", "Input decryption passwords, one per line (alias for --input-password-file)")
}

func validateScanRefreshFlags() error {
	for _, selection := range []struct {
		flag   string
		values []string
	}{{"--bundle-name", scanRefresh.Names}, {"--only", scanRefresh.Only}, {"--require-bundle", scanRefresh.Required}, {"--formats", scanRefresh.Formats}} {
		if selection.values != nil && len(selection.values) == 0 {
			return fmt.Errorf("%w: %s must not be empty", errScanRefreshOptions, selection.flag)
		}
	}
	if scanRefresh.Write && scanRefresh.DryRun {
		return fmt.Errorf("%w: --write and --dry-run cannot be combined", errScanRefreshOptions)
	}
	if scanBundlePath == "" {
		if scanRefresh.Write || scanRefresh.DryRun || scanRefresh.FailOnSkip || len(scanRefresh.Names)+len(scanRefresh.Only)+len(scanRefresh.Required)+len(scanRefresh.Formats) > 0 || scanRefresh.OutputPasswordFile != "" {
			return fmt.Errorf("%w: bundle export options require --bundle-path", errScanRefreshOptions)
		}
		return nil
	}
	if scanDumpKeys != "" || scanDumpCerts != "" {
		return fmt.Errorf("%w: --bundle-path cannot be combined with --dump-keys or --dump-certs; select bundle artifacts with --formats", errScanRefreshOptions)
	}
	if !scanRefresh.Write && scanSaveDB != "" {
		return fmt.Errorf("%w: a bundle preview cannot write --save-db; use --write or scan separately", errScanRefreshOptions)
	}
	return nil
}

func scanPasswords() ([]string, string, error) {
	passwords := certkit.DeduplicatePasswords(passwordList)
	for _, path := range []string{passwordFile, scanRefresh.InputPasswordFile} {
		if path == "" {
			continue
		}
		data, err := internal.ReadFileLimited(path, 64*1024)
		if err != nil {
			return nil, "", fmt.Errorf("reading input password file: %w", err)
		}
		for line := range strings.SplitSeq(string(data), "\n") {
			password := strings.TrimSuffix(line, "\r")
			if password != "" {
				passwords = append(passwords, password)
			}
		}
	}
	passwords = certkit.DeduplicatePasswords(passwords)
	outputPassword := ""
	if scanRefresh.OutputPasswordFile != "" {
		data, err := internal.ReadFileLimited(scanRefresh.OutputPasswordFile, 64*1024)
		if err != nil {
			return nil, "", fmt.Errorf("reading output password file: %w", err)
		}
		outputPassword = strings.TrimSuffix(strings.TrimSuffix(string(data), "\n"), "\r")
		if strings.TrimSpace(outputPassword) == "" || strings.ContainsAny(outputPassword, "\r\n") {
			return nil, "", fmt.Errorf("%w: output password file must contain exactly one nonempty password", errScanRefreshOptions)
		}
	}
	return passwords, outputPassword, nil
}

type runScanBundleExportInput struct {
	Store          *certstore.MemStore
	Configs        []internal.BundleConfig
	OutputPassword string
	Format         string
}

func runScanBundleExport(ctx context.Context, input runScanBundleExportInput) error {
	plan, err := scanPlanBundles(ctx, internal.BundlePlanInput{
		Configs: input.Configs, OutDir: scanBundlePath,
		Store: input.Store, TrustStore: scanTrustStore, ForceBundle: scanForceExport,
		Duplicates: scanDuplicates, P12Password: input.OutputPassword,
		AllowSystemFallback: true, EncryptKey: input.OutputPassword != "",
		ConfigPath: scanConfigPath, BundleNames: slices.Concat(scanRefresh.Names, scanRefresh.Only),
		RequireBundles: scanRefresh.Required, FailOnSkip: scanRefresh.FailOnSkip,
		Formats: scanRefresh.Formats, AllowPrivateNetworks: scanAllowPrivateNetwork, AIATimeout: scanAIATimeout,
		AllowExpired: allowExpired,
	})
	if err != nil {
		return fmt.Errorf("planning bundle exports: %w", err)
	}
	trustPools, err := scanSummaryTrustPoolLoader(scanTrustStore)
	if err != nil {
		return err
	}
	planErr := plan.Validate()
	if scanRefresh.Write && planErr == nil {
		planErr = plan.Write(ctx)
	}
	summary := input.Store.ScanSummary(certstore.ScanSummaryInput{MozillaPool: trustPools.Mozilla, SystemPool: trustPools.System})
	if input.Format == "json" {
		output := scanExportJSON{ScanSummary: summary, BundlePath: scanBundlePath,
			DryRun: !scanRefresh.Write, Exports: plan.Entries}
		data, err := json.MarshalIndent(output, "", "  ")
		if err != nil {
			return fmt.Errorf("encoding bundle export plan: %w", err)
		}
		if _, err := fmt.Fprintln(os.Stdout, string(data)); err != nil {
			return fmt.Errorf("writing bundle export plan: %w", err)
		}
	} else {
		if err := printBundleExportPlan(plan); err != nil {
			return err
		}
	}
	if planErr != nil {
		if errors.Is(planErr, internal.ErrBundlePlanBlocked) {
			return &ValidationError{Message: planErr.Error()}
		}
		return fmt.Errorf("applying bundle export plan: %w", planErr)
	}
	return nil
}

func printBundleExportPlan(plan *internal.BundleExportPlan) error {
	var out strings.Builder
	if scanRefresh.Write {
		out.WriteString("Bundle export results\n")
	} else {
		out.WriteString("Bundle export plan (no files written; use --write to apply)\n")
	}
	for _, entry := range plan.Entries {
		fmt.Fprintf(&out, "\n%s: %s (%s)\n  Directory: %s\n  Reason: %s\n", entry.BundleName, entry.Status, entry.Action, entry.OutputDirectory, entry.Reason)
		if entry.Rule != nil {
			fmt.Fprintf(&out, "  Rule: %s #%d (%s)\n", entry.Rule.ConfigPath, entry.Rule.Index, strings.Join(entry.Rule.CommonNames, ", "))
		}
		for _, skipped := range entry.SkippedCandidates {
			fmt.Fprintf(&out, "  Unselected candidate: serial=%s SHA-256=%s\n    Validity: %s to %s\n    Source: %s\n    Key source: %s\n    Reason: %s\n",
				skipped.Leaf.Serial, skipped.Leaf.Fingerprint, skipped.Leaf.NotBefore.Format(time.RFC3339),
				skipped.Leaf.NotAfter.Format(time.RFC3339), skipped.Leaf.Source, skipped.KeySource, skipped.Reason)
		}
		for _, value := range []struct {
			label string
			leaf  *internal.BundleLeaf
		}{{"Candidate", entry.Leaf}, {"Existing", entry.ExistingLeaf}} {
			if value.leaf != nil {
				leaf := value.leaf
				fmt.Fprintf(&out, "  %s: CN=%s serial=%s\n    SHA-256: %s\n    Validity: %s to %s\n    Source: %s\n", value.label, leaf.CommonName, leaf.Serial, leaf.Fingerprint, leaf.NotBefore.Format(time.RFC3339), leaf.NotAfter.Format(time.RFC3339), leaf.Source)
			}
		}
		if entry.Leaf != nil {
			fmt.Fprintf(&out, "  Selection: %s (%d candidates)\n  Key source: %s\n  Chain: %s (%s)\n", entry.SelectionReason, entry.CandidateCount, entry.KeySource, entry.Chain.Status, entry.Chain.TrustStore)
		}
		for _, warning := range entry.Chain.Warnings {
			fmt.Fprintf(&out, "  Chain warning: %s\n", warning)
		}
		fmt.Fprintf(&out, "  Files: %s\n", strings.Join(entry.Files, ", "))
		if len(entry.RemovedFiles) > 0 {
			fmt.Fprintf(&out, "  Removed on replacement: %s\n", strings.Join(entry.RemovedFiles, ", "))
		}
	}
	if _, err := fmt.Fprint(os.Stdout, out.String()); err != nil {
		return fmt.Errorf("writing bundle export plan: %w", err)
	}
	return nil
}
