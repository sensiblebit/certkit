package internal

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/sensiblebit/certkit"
	"github.com/sensiblebit/certkit/internal/certstore"
)

// ErrBundlePlanBlocked indicates that a requested export failed its safety checks.
var ErrBundlePlanBlocked = errors.New("bundle export plan is blocked")

var errBundlePlanInput = errors.New("invalid bundle export request")

const (
	bundleManifestName    = "manifest.json"
	bundleRefreshLockName = ".certkit-refresh.lock"
)

// BundleLeaf describes a selected or existing certificate without private material.
type BundleLeaf struct {
	CommonName     string    `json:"common_name"`
	DNSNames       []string  `json:"dns_names"`
	IPAddresses    []string  `json:"ip_addresses"`
	EmailAddresses []string  `json:"email_addresses"`
	URIs           []string  `json:"uris"`
	Serial         string    `json:"serial_number"`
	Fingerprint    string    `json:"sha256_fingerprint"`
	NotBefore      time.Time `json:"not_before"`
	NotAfter       time.Time `json:"not_after"`
	Source         string    `json:"source"`
	PEM            string    `json:"pem"`
}

// BundleRule identifies the configuration entry that matched a certificate.
type BundleRule struct {
	ConfigPath  string   `json:"config_path"`
	Index       int      `json:"index"`
	BundleName  string   `json:"bundle_name"`
	CommonNames []string `json:"common_names"`
}

// BundleChain describes the chain and whether trust verification was performed.
type BundleChain struct {
	Status        string   `json:"status"`
	TrustStore    string   `json:"trust_store"`
	Intermediates []string `json:"intermediate_fingerprints"`
	Roots         []string `json:"root_fingerprints"`
	Warnings      []string `json:"warnings,omitempty"`
}

// BundleCandidateDecision records why an alternative certificate was not selected.
type BundleCandidateDecision struct {
	Leaf      *BundleLeaf `json:"leaf"`
	KeySource string      `json:"key_source,omitempty"`
	Reason    string      `json:"reason"`
}

// BundleExportEntry records the decision for one requested bundle directory.
type BundleExportEntry struct {
	BundleName        string                    `json:"bundle_name"`
	OutputDirectory   string                    `json:"output_directory"`
	Rule              *BundleRule               `json:"rule,omitempty"`
	Leaf              *BundleLeaf               `json:"leaf,omitempty"`
	ExistingLeaf      *BundleLeaf               `json:"existing_leaf,omitempty"`
	KeySource         string                    `json:"key_source,omitempty"`
	SelectionReason   string                    `json:"selection_reason,omitempty"`
	CandidateCount    int                       `json:"candidate_count"`
	SkippedCandidates []BundleCandidateDecision `json:"skipped_candidates,omitempty"`
	Chain             BundleChain               `json:"chain"`
	Formats           []string                  `json:"formats"`
	Files             []string                  `json:"files"`
	RemovedFiles      []string                  `json:"removed_files,omitempty"`
	Action            string                    `json:"action"`
	Status            string                    `json:"status"`
	Reason            string                    `json:"reason"`
	Forced            bool                      `json:"forced,omitempty"`
}

// BundlePlanInput configures a managed bundle refresh. It never writes files.
type BundlePlanInput struct {
	ExportBundlesInput
	ConfigPath           string
	BundleNames          []string
	RequireBundles       []string
	FailOnSkip           bool
	Formats              []string
	AllowPrivateNetworks bool
	AIATimeout           time.Duration
	AllowExpired         bool
	// CustomRoots supplies trust anchors when TrustStore is "custom".
	CustomRoots []*x509.Certificate
}

// BundleExportPlan contains a reviewable manifest and private, in-memory output.
// Use Write to apply the plan after inspecting its entries.
type BundleExportPlan struct {
	Entries           []BundleExportEntry `json:"exports"`
	outDir            string
	writes            []plannedBundleWrite
	blocked           []string
	unselectedFolders map[string]string
}

type plannedBundleWrite struct {
	entry    int
	folder   string
	files    []certstore.BundleFile
	existing bundleDirectoryState
}

// Validate reports all decisions that prevent this plan from being applied.
func (p *BundleExportPlan) Validate() error {
	if len(p.blocked) != 0 {
		return fmt.Errorf("%w: %s", ErrBundlePlanBlocked, strings.Join(p.blocked, "; "))
	}
	return nil
}

// PlanBundleExports selects, validates, and renders all requested bundles before
// any output directory is created. Conflicts are returned in the manifest.
func PlanBundleExports(ctx context.Context, input BundlePlanInput) (*BundleExportPlan, error) {
	if input.Store == nil || input.OutDir == "" {
		return nil, fmt.Errorf("%w: bundle store and output directory are required", errBundlePlanInput)
	}
	if len(input.Configs) == 0 {
		return nil, fmt.Errorf("%w: bundle export requires a nonempty configuration", errBundlePlanInput)
	}
	if input.BundleNames != nil && len(input.BundleNames) == 0 {
		return nil, fmt.Errorf("%w: selected bundle names must not be empty", errBundlePlanInput)
	}
	formats := input.Formats
	if formats == nil {
		formats = certstore.DefaultBundleFormats()
	}
	formats, err := certstore.NormalizeBundleFormats(formats)
	if err != nil {
		return nil, fmt.Errorf("selecting bundle artifacts: %w", err)
	}
	if slices.Contains(formats, "p12") && input.P12Password == "" {
		input.P12Password = DefaultExportPassword
	}
	input.Formats = formats
	rules, err := bundlePlanRules(input)
	if err != nil {
		return nil, err
	}
	names := slices.Clone(input.BundleNames)
	if len(names) == 0 {
		for name := range rules {
			names = append(names, name)
		}
	}
	slices.Sort(names)
	names = slices.Compact(names)
	for _, name := range append(slices.Clone(names), input.RequireBundles...) {
		if _, ok := rules[name]; !ok {
			return nil, fmt.Errorf("%w: bundle %q has no configuration rule", errBundlePlanInput, name)
		}
	}
	for _, name := range input.RequireBundles {
		if !slices.Contains(names, name) {
			return nil, fmt.Errorf("%w: required bundle %q is outside the selected scope", errBundlePlanInput, name)
		}
	}
	plan := &BundleExportPlan{outDir: input.OutDir, Entries: []BundleExportEntry{}, unselectedFolders: map[string]string{}}
	for name := range rules {
		if !slices.Contains(names, name) {
			folder, err := certstore.SanitizeBundleFolder(name)
			if err != nil {
				return nil, fmt.Errorf("sanitizing unselected bundle %q: %w", name, err)
			}
			plan.unselectedFolders[name] = folder
		}
	}
	folders := map[string]string{}
	for _, name := range names {
		if err := ctx.Err(); err != nil {
			return nil, fmt.Errorf("planning bundle export: %w", err)
		}
		if slices.Contains(formats, "k8s") {
			if err := certstore.ValidateK8sSecretName(name); err != nil {
				return nil, fmt.Errorf("validating kubernetes secret name for bundle %q: %w", name, err)
			}
		}
		certs := input.Store.CertsByBundleName(name)
		if len(certs) == 0 {
			entry := BundleExportEntry{BundleName: name, OutputDirectory: filepath.Join(input.OutDir, name),
				Rule: rules[name], Formats: formats, Files: []string{}, Action: "skip", Status: "skipped",
				Reason: "no matching certificate was found", Chain: BundleChain{Status: "not_checked"}}
			plan.Entries = append(plan.Entries, entry)
			if input.FailOnSkip || slices.Contains(input.RequireBundles, name) || slices.Contains(input.BundleNames, name) {
				plan.blocked = append(plan.blocked, name+": "+entry.Reason)
			}
			continue
		}
		primaryEntryIndex := len(plan.Entries)
		for i, rec := range certs {
			if i > 0 && !input.Duplicates {
				break
			}
			folderName := name
			if i > 0 {
				folderName = fmt.Sprintf("%s_%s_%s_%s", name, rec.NotAfter.UTC().Format("20060102T150405Z"), rec.Cert.SerialNumber, certkit.CertFingerprint(rec.Cert)[:12])
			}
			folder, err := certstore.SanitizeBundleFolder(folderName)
			if err != nil {
				return nil, fmt.Errorf("sanitizing bundle %q: %w", name, err)
			}
			if strings.EqualFold(folder, bundleRefreshLockName) {
				return nil, fmt.Errorf("%w: bundle directory %q is reserved for the refresh lock; configure a different bundle name", errBundlePlanInput, folder)
			}
			for previousFolder, previousName := range folders {
				if strings.EqualFold(previousFolder, folder) {
					return nil, fmt.Errorf("%w: %q and %q map to the same directory on a case-insensitive filesystem", errExportBundleFolderCollision, previousName, name)
				}
			}
			folders[folder] = name
			entry, write, err := planBundleCandidate(ctx, planBundleCandidateInput{
				Input: input, Record: rec, Folder: folder, Rule: rules[name], CandidateCount: len(certs),
			})
			if err != nil {
				return nil, fmt.Errorf("planning bundle %q: %w", name, err)
			}
			if i == 0 && !input.Duplicates {
				for _, skipped := range certs[1:] {
					decision := BundleCandidateDecision{Leaf: describeBundleLeaf(skipped.Cert, skipped.Source),
						Reason: "higher SHA-256 fingerprint than the selected candidate"}
					if skipped.NotAfter.Before(rec.NotAfter) {
						decision.Reason = "earlier expiration than the selected candidate"
					} else if skipped.Cert.NotBefore.Before(rec.Cert.NotBefore) {
						decision.Reason = "earlier issuance time than the selected candidate"
					}
					if key := input.Store.GetKey(skipped.SKI); key != nil {
						decision.KeySource = key.Source
					}
					entry.SkippedCandidates = append(entry.SkippedCandidates, decision)
				}
			}
			write.entry = len(plan.Entries)
			plan.Entries = append(plan.Entries, entry)
			if entry.Status == "blocked" || (entry.Status == "skipped" && input.FailOnSkip) {
				plan.blocked = append(plan.blocked, name+": "+entry.Reason)
			}
			if entry.Status == "planned" {
				plan.writes = append(plan.writes, write)
			}
		}
		// Required names refer to the primary managed directory. Historical
		// duplicates may be skipped unless the caller explicitly fails on skips.
		primary := plan.Entries[primaryEntryIndex]
		if !input.FailOnSkip && primary.Status == "skipped" && (slices.Contains(input.RequireBundles, name) || slices.Contains(input.BundleNames, name)) {
			plan.blocked = append(plan.blocked, name+": "+primary.Reason)
		}
	}
	if err := plan.checkDirectoryScope(); err != nil {
		return nil, err
	}
	return plan, nil
}

// checkDirectoryScope uses directory entry names rather than path lookup, which
// can silently resolve an unselected case variant on case-insensitive systems.
func (p *BundleExportPlan) checkDirectoryScope() error {
	if len(p.writes) == 0 {
		return nil
	}
	for _, write := range p.writes {
		for _, folder := range p.unselectedFolders {
			if strings.EqualFold(folder, write.folder) {
				return fmt.Errorf("%w: selected directory %q also belongs to an unselected configuration rule; configure distinct bundle names", errExportBundleFolderCollision, write.folder)
			}
		}
	}
	children, err := os.ReadDir(p.outDir)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("checking bundle output directory names: %w", err)
	}
	for _, write := range p.writes {
		for _, child := range children {
			if strings.EqualFold(child.Name(), write.folder) {
				if child.Name() != write.folder {
					return fmt.Errorf("%w: selected directory %q aliases existing directory %q; use the exact existing name or configure a distinct bundle name", errExportBundleFolderCollision, write.folder, child.Name())
				}
			}
		}
	}
	return nil
}

func bundlePlanRules(input BundlePlanInput) (map[string]*BundleRule, error) {
	rules := map[string]*BundleRule{}
	commonNames := map[string]bool{}
	for i, cfg := range input.Configs {
		if len(cfg.CommonNames) == 0 {
			return nil, fmt.Errorf("%w: bundle rule %d has no commonNames", errBundlePlanInput, i+1)
		}
		for _, cn := range cfg.CommonNames {
			if strings.TrimSpace(cn) == "" || commonNames[cn] {
				return nil, fmt.Errorf("%w: empty or duplicate common name in bundle rule %d", errBundlePlanInput, i+1)
			}
			commonNames[cn] = true
			name := cfg.BundleName
			if name == "" {
				name = strings.ReplaceAll(cn, "*", "_")
			}
			if previous, ok := rules[name]; ok && previous.Index != i+1 {
				return nil, fmt.Errorf("%w: duplicate bundle name %q in configuration", errBundlePlanInput, name)
			}
			rules[name] = &BundleRule{ConfigPath: input.ConfigPath, Index: i + 1, BundleName: name, CommonNames: slices.Clone(cfg.CommonNames)}
		}
	}
	return rules, nil
}

type planBundleCandidateInput struct {
	Input          BundlePlanInput
	Record         *certstore.CertRecord
	Folder         string
	Rule           *BundleRule
	CandidateCount int
}

func planBundleCandidate(ctx context.Context, input planBundleCandidateInput) (BundleExportEntry, plannedBundleWrite, error) {
	opts := input.Input
	rec := input.Record
	entry := BundleExportEntry{BundleName: rec.BundleName, OutputDirectory: filepath.Join(opts.OutDir, input.Folder),
		Rule: input.Rule, Leaf: describeBundleLeaf(rec.Cert, rec.Source), CandidateCount: input.CandidateCount,
		SelectionReason: "latest not_after, then latest not_before, then lowest SHA-256 fingerprint",
		Formats:         opts.Formats, Files: []string{}, Status: "planned", Action: "create", Reason: "new bundle",
		Chain: BundleChain{Status: "not_checked"}}
	key := opts.Store.GetKey(rec.SKI)
	if key != nil {
		entry.KeySource = key.Source
	}
	write := plannedBundleWrite{folder: input.Folder}
	if key == nil && certstore.BundleFormatsNeedKey(opts.Formats) {
		entry.Status, entry.Action, entry.Reason = "skipped", "skip", "no matching private key was found"
		return entry, write, nil
	}
	if time.Now().After(rec.Cert.NotAfter) && !opts.AllowExpired {
		entry.Status, entry.Action = "skipped", "skip"
		entry.Reason = "certificate has expired; use --allow-expired to permit expired leaves"
		return entry, write, nil
	}
	bundleOpts := certkit.DefaultOptions()
	bundleOpts.AllowExpired = opts.AllowExpired
	bundleOpts.CustomRoots = opts.CustomRoots
	bundleOpts.ExtraIntermediates = opts.Store.Intermediates()
	bundleOpts.AllowPrivateNetworks = opts.AllowPrivateNetworks
	if opts.AIATimeout > 0 {
		bundleOpts.AIATimeout = opts.AIATimeout
	}
	if opts.TrustStore != "" {
		bundleOpts.TrustStore = opts.TrustStore
	}
	bundleOpts.Verify = !opts.ForceBundle
	bundle, err := certkit.Bundle(ctx, certkit.BundleInput{Leaf: rec.Cert, Options: bundleOpts})
	if err != nil && opts.AllowSystemFallback && bundleOpts.Verify && bundleOpts.TrustStore != "system" && shouldRetrySystemFallback(err) {
		bundleOpts.TrustStore = "system"
		bundle, err = certkit.Bundle(ctx, certkit.BundleInput{Leaf: rec.Cert, Options: bundleOpts})
	}
	entry.Chain.TrustStore = bundleOpts.TrustStore
	if err != nil {
		if !isBundleVerificationError(err) {
			return entry, write, fmt.Errorf("building candidate chain: %w", err)
		}
		entry.Status, entry.Action = "skipped", "skip"
		entry.Reason = "certificate verification failed: " + err.Error()
		entry.Chain.Status = "untrusted"
		return entry, write, nil
	}
	entry.Chain.Status = "verified"
	if !bundleOpts.Verify {
		entry.Chain.Status = "verification_disabled"
		entry.Forced = true
	}
	entry.Chain.Warnings = bundle.Warnings
	for _, cert := range bundle.Intermediates {
		entry.Chain.Intermediates = append(entry.Chain.Intermediates, certkit.CertFingerprint(cert))
	}
	for _, cert := range bundle.Roots {
		entry.Chain.Roots = append(entry.Chain.Roots, certkit.CertFingerprint(cert))
	}
	existing, err := inspectBundleDirectory(entry.OutputDirectory)
	if err != nil {
		return entry, write, err
	}
	if existing.bundleName != "" && existing.bundleName != rec.BundleName {
		return entry, write, fmt.Errorf("%w: existing directory %q belongs to bundle %q instead of %q; configure a distinct bundle name", errExportBundleFolderCollision, input.Folder, existing.bundleName, rec.BundleName)
	}
	write.existing = existing
	entry.ExistingLeaf = existing.leaf
	if existing.exists {
		entry.Action = "replace"
		entry.Reason = "candidate expires later than the existing leaf"
		conflict := existing.ambiguity
		if existing.leaf != nil {
			switch {
			case entry.Leaf.Fingerprint == existing.leaf.Fingerprint:
				entry.Reason = "same leaf certificate; refresh selected artifacts"
			case entry.Leaf.NotAfter.Before(existing.leaf.NotAfter):
				conflict = "candidate would downgrade the existing expiration"
			case entry.Leaf.NotAfter.Equal(existing.leaf.NotAfter):
				conflict = "same expiration with a different certificate fingerprint"
			}
		}
		if conflict != "" {
			entry.Reason = conflict
			if !opts.ForceBundle {
				entry.Status = "blocked"
				entry.Reason += "; use --force to explicitly allow replacement"
				return entry, write, nil
			}
			entry.Forced = true
		}
	}
	fileInput := certstore.BundleExportInput{Bundle: bundle,
		Prefix: certstore.SanitizeFileName(certstore.FormatCN(rec.Cert)), SecretName: rec.BundleName,
		P12Password: opts.P12Password, EncryptKey: opts.EncryptKey, Formats: opts.Formats}
	if key != nil {
		fileInput.KeyPEM, fileInput.KeyType, fileInput.BitLength = key.PEM, key.KeyType, key.BitLength
	}
	if subject := opts.Configs[input.Rule.Index-1].Subject; subject != nil {
		fileInput.CSRSubject = &certstore.CSRSubjectOverride{Country: subject.Country, Province: subject.Province,
			Locality: subject.Locality, Organization: subject.Organization, OrganizationalUnit: subject.OrganizationalUnit}
	}
	files, err := certstore.GenerateBundleFiles(fileInput)
	if err != nil {
		return entry, write, fmt.Errorf("generating selected artifacts: %w", err)
	}
	for _, file := range files {
		if strings.EqualFold(file.Name, bundleManifestName) {
			return entry, write, fmt.Errorf("%w: generated artifact %q conflicts with the reserved export manifest; omit the json format", errBundlePlanInput, file.Name)
		}
		entry.Files = append(entry.Files, file.Name)
	}
	entry.Files = append(entry.Files, bundleManifestName)
	for _, name := range existing.files {
		if !slices.Contains(entry.Files, name) {
			entry.RemovedFiles = append(entry.RemovedFiles, name)
		}
	}
	write.files = files
	return entry, write, nil
}

func describeBundleLeaf(cert *x509.Certificate, source string) *BundleLeaf {
	fingerprint := sha256.Sum256(cert.Raw)
	leaf := &BundleLeaf{CommonName: cert.Subject.CommonName, DNSNames: slices.Clone(cert.DNSNames),
		IPAddresses: certstore.FormatIPAddresses(cert.IPAddresses), EmailAddresses: slices.Clone(cert.EmailAddresses),
		Serial: cert.SerialNumber.String(), Fingerprint: hex.EncodeToString(fingerprint[:]),
		NotBefore: cert.NotBefore.UTC(), NotAfter: cert.NotAfter.UTC(), Source: source, PEM: certkit.CertToPEM(cert)}
	for _, uri := range cert.URIs {
		leaf.URIs = append(leaf.URIs, uri.String())
	}
	return leaf
}

// Write applies a validated plan, rechecking every existing directory before
// modifying any bundle. Each directory is replaced using staging and rollback.
func (p *BundleExportPlan) Write(ctx context.Context) error {
	if err := p.Validate(); err != nil {
		return err
	}
	if len(p.writes) == 0 {
		return nil
	}
	// The lock serializes cooperating certkit processes. Recheck after acquiring
	// it so a preview made before another refresh cannot overwrite that refresh.
	//nolint:gosec // The output directory contains public certificates; private artifacts use 0600.
	if err := os.MkdirAll(p.outDir, 0o755); err != nil {
		return fmt.Errorf("creating bundle output directory: %w", err)
	}
	lockPath := filepath.Join(p.outDir, bundleRefreshLockName)
	if err := os.Mkdir(lockPath, 0o700); err != nil {
		return fmt.Errorf("acquiring bundle refresh lock (another refresh may be running): %w", err)
	}
	defer func() {
		if err := os.Remove(lockPath); err != nil {
			slog.Warn("removing bundle refresh lock", "path", lockPath, "error", err)
		}
	}()
	if err := p.checkDirectoryScope(); err != nil {
		return err
	}
	for _, write := range p.writes {
		current, err := inspectBundleDirectory(p.Entries[write.entry].OutputDirectory)
		if err != nil {
			return fmt.Errorf("rechecking bundle before write: %w", err)
		}
		if current.exists != write.existing.exists || current.digest != write.existing.digest {
			return fmt.Errorf("%w: bundle %q changed after planning; rerun the command", ErrBundlePlanBlocked, p.Entries[write.entry].BundleName)
		}
	}
	writer := &filesystemWriter{outDir: p.outDir}
	for _, write := range p.writes {
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("writing bundle plan: %w", err)
		}
		entry := p.Entries[write.entry]
		entry.Status = "created"
		if entry.Action == "replace" {
			entry.Status = "replaced"
		}
		data, err := json.MarshalIndent(entry, "", "  ")
		if err != nil {
			return fmt.Errorf("encoding export manifest: %w", err)
		}
		files := append(slices.Clone(write.files), certstore.BundleFile{Name: bundleManifestName, Data: append(data, '\n')})
		if err := writer.WriteBundleFiles(write.folder, files); err != nil {
			return fmt.Errorf("writing bundle %q: %w", entry.BundleName, err)
		}
		p.Entries[write.entry] = entry
	}
	return nil
}
