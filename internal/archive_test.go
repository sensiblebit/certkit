package internal

import (
	"archive/tar"
	"bytes"
	"strings"
	"testing"
)

func TestArchiveFormat(t *testing.T) {
	// WHY: Verifies that all supported archive extensions are detected,
	// case-insensitively, and that IsArchive agrees with ArchiveFormat.
	t.Parallel()

	tests := []struct {
		name      string
		path      string
		want      string
		isArchive bool
	}{
		{"zip", "certs.zip", "zip", true},
		{"tar", "certs.tar", "tar", true},
		{"tgz", "certs.tgz", "tar.gz", true},
		{"tar.gz", "certs.tar.gz", "tar.gz", true},
		{"uppercase ZIP", "certs.ZIP", "zip", true},
		{"uppercase TAR.GZ", "certs.TAR.GZ", "tar.gz", true},
		{"mixed case TaR.Gz", "certs.TaR.Gz", "tar.gz", true},
		{"pem file", "cert.pem", "", false},
		{"p12 file", "cert.p12", "", false},
		{"no extension", "certs", "", false},
		{"nested path zip", "/some/path/certs.zip", "zip", true},
		{"nested path tar.gz", "/some/path/certs.tar.gz", "tar.gz", true},
		{"tar.gz.bak", "certs.tar.gz.bak", "", false},
		{"trailing dot", "certs.tar.", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := ArchiveFormat(tt.path)
			if got != tt.want {
				t.Errorf("ArchiveFormat(%q) = %q, want %q", tt.path, got, tt.want)
			}
			if gotBool := IsArchive(tt.path); gotBool != tt.isArchive {
				t.Errorf("IsArchive(%q) = %v, want %v", tt.path, gotBool, tt.isArchive)
			}
		})
	}
}

func TestProcessArchive_PEMCertAllFormats(t *testing.T) {
	// WHY: Verifies that PEM certificates are ingested from all three archive
	// formats. Table-driven to avoid copy-paste between ZIP/TAR/TAR.GZ tests.
	// Checks cert identity (CommonName), not just count.
	t.Parallel()
	ca := newRSACA(t)

	tests := []struct {
		name    string
		format  string
		builder func(t *testing.T, files map[string][]byte) []byte
	}{
		{"zip", "zip", createTestZip},
		{"tar", "tar", createTestTar},
		{"tar.gz", "tar.gz", createTestTarGz},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			cn := tt.name + "-test.example.com"
			leaf := newRSALeaf(t, ca, cn, []string{cn}, nil)

			archiveData := tt.builder(t, map[string][]byte{
				"certs/server.pem": leaf.certPEM,
			})

			cfg := newTestConfig(t)
			n, err := ProcessArchive(ProcessArchiveInput{
				ArchivePath: "test." + tt.name,
				Data:        archiveData,
				Format:      tt.format,
				Limits:      DefaultArchiveLimits(),
				Store:       cfg.Store, Passwords: cfg.Passwords,
			})
			if err != nil {
				t.Fatalf("ProcessArchive: %v", err)
			}
			if n != 1 {
				t.Errorf("processed %d entries, want 1", n)
			}

			certs := cfg.Store.AllCertsFlat()
			if len(certs) != 1 {
				t.Fatalf("got %d certs in store, want 1", len(certs))
			}
			if certs[0].Cert.Subject.CommonName != cn {
				t.Errorf("cert CN = %q, want %q", certs[0].Cert.Subject.CommonName, cn)
			}
		})
	}
}

func TestProcessArchive_ZipWithDERCert(t *testing.T) {
	// WHY: Verifies that DER certificates with binary extensions inside ZIP
	// archives pass through hasBinaryExtension and processDER correctly.
	// Uses an entry name with a directory prefix to exercise the normal path.
	t.Parallel()
	ca := newRSACA(t)
	leaf := newRSALeaf(t, ca, "der-zip.example.com", []string{"der-zip.example.com"}, nil)

	zipData := createTestZip(t, map[string][]byte{
		"certs/server.der": leaf.certDER,
	})

	cfg := newTestConfig(t)
	n, err := ProcessArchive(ProcessArchiveInput{
		ArchivePath: "test.zip",
		Data:        zipData,
		Format:      "zip",
		Limits:      DefaultArchiveLimits(),
		Store:       cfg.Store, Passwords: cfg.Passwords,
	})
	if err != nil {
		t.Fatalf("ProcessArchive: %v", err)
	}
	if n != 1 {
		t.Errorf("processed %d entries, want 1", n)
	}

	certs := cfg.Store.AllCertsFlat()
	if len(certs) != 1 {
		t.Fatalf("got %d certs in store, want 1", len(certs))
	}
	if certs[0].Cert.Subject.CommonName != "der-zip.example.com" {
		t.Errorf("cert CN = %q, want %q", certs[0].Cert.Subject.CommonName, "der-zip.example.com")
	}
}

func TestProcessArchive_DERCertNoDirectoryPrefix(t *testing.T) {
	// WHY: Regression test for the filepath.Ext virtual path bug. When an
	// archive entry name has no "/" separator (e.g., "server.der"), the virtual
	// path "archive.zip:server.der" must still yield ".der" from hasBinaryExtension.
	// Without the colon-aware fix, filepath.Ext would return ".zip:server" (garbage).
	t.Parallel()
	ca := newRSACA(t)
	leaf := newRSALeaf(t, ca, "flat-der.example.com", []string{"flat-der.example.com"}, nil)

	zipData := createTestZip(t, map[string][]byte{
		"server.der": leaf.certDER,
	})

	cfg := newTestConfig(t)
	n, err := ProcessArchive(ProcessArchiveInput{
		ArchivePath: "archive.zip",
		Data:        zipData,
		Format:      "zip",
		Limits:      DefaultArchiveLimits(),
		Store:       cfg.Store, Passwords: cfg.Passwords,
	})
	if err != nil {
		t.Fatalf("ProcessArchive: %v", err)
	}
	if n != 1 {
		t.Errorf("processed %d entries, want 1", n)
	}

	certs := cfg.Store.AllCertsFlat()
	if len(certs) != 1 {
		t.Fatalf("got %d certs in store, want 1 (DER cert with flat entry name)", len(certs))
	}
	if certs[0].Cert.Subject.CommonName != "flat-der.example.com" {
		t.Errorf("cert CN = %q, want %q", certs[0].Cert.Subject.CommonName, "flat-der.example.com")
	}
}

func TestProcessArchive_PEMCertNoExtension(t *testing.T) {
	// WHY: Verifies that PEM certificates are detected by content even when
	// the entry name has no file extension. PEM detection is content-based
	// (looks for "-----BEGIN"), so the extension should not matter.
	t.Parallel()
	ca := newRSACA(t)
	leaf := newRSALeaf(t, ca, "noext.example.com", []string{"noext.example.com"}, nil)

	zipData := createTestZip(t, map[string][]byte{
		"certificate": leaf.certPEM,
	})

	cfg := newTestConfig(t)
	n, err := ProcessArchive(ProcessArchiveInput{
		ArchivePath: "test.zip",
		Data:        zipData,
		Format:      "zip",
		Limits:      DefaultArchiveLimits(),
		Store:       cfg.Store, Passwords: cfg.Passwords,
	})
	if err != nil {
		t.Fatalf("ProcessArchive: %v", err)
	}
	if n != 1 {
		t.Errorf("processed %d entries, want 1", n)
	}

	certs := cfg.Store.AllCertsFlat()
	if len(certs) != 1 {
		t.Fatalf("got %d certs in store, want 1", len(certs))
	}
	if certs[0].Cert.Subject.CommonName != "noext.example.com" {
		t.Errorf("cert CN = %q, want %q", certs[0].Cert.Subject.CommonName, "noext.example.com")
	}
}

func TestProcessArchive_ZipWithPrivateKey(t *testing.T) {
	// WHY: Verifies that PEM private keys inside archives are ingested
	// and the key type is correctly identified.
	t.Parallel()
	keyPEM := rsaKeyPEM(t)

	zipData := createTestZip(t, map[string][]byte{
		"keys/server.key": keyPEM,
	})

	cfg := newTestConfig(t)
	n, err := ProcessArchive(ProcessArchiveInput{
		ArchivePath: "test.zip",
		Data:        zipData,
		Format:      "zip",
		Limits:      DefaultArchiveLimits(),
		Store:       cfg.Store, Passwords: cfg.Passwords,
	})
	if err != nil {
		t.Fatalf("ProcessArchive: %v", err)
	}
	if n != 1 {
		t.Errorf("processed %d entries, want 1", n)
	}

	keys := cfg.Store.AllKeysFlat()
	if len(keys) != 1 {
		t.Fatalf("got %d keys in store, want 1", len(keys))
	}
	if keys[0].KeyType != "RSA" {
		t.Errorf("key type = %q, want %q", keys[0].KeyType, "RSA")
	}
}

func TestProcessArchive_MultipleCertsInArchive(t *testing.T) {
	// WHY: Verifies that multiple certificates across multiple archive entries
	// are all ingested with distinct identities.
	t.Parallel()
	ca := newRSACA(t)
	leaf1 := newRSALeaf(t, ca, "multi1.example.com", []string{"multi1.example.com"}, nil)
	leaf2 := newECDSALeaf(t, ca, "multi2.example.com", []string{"multi2.example.com"})

	zipData := createTestZip(t, map[string][]byte{
		"certs/leaf1.pem": leaf1.certPEM,
		"certs/leaf2.pem": leaf2.certPEM,
	})

	cfg := newTestConfig(t)
	n, err := ProcessArchive(ProcessArchiveInput{
		ArchivePath: "test.zip",
		Data:        zipData,
		Format:      "zip",
		Limits:      DefaultArchiveLimits(),
		Store:       cfg.Store, Passwords: cfg.Passwords,
	})
	if err != nil {
		t.Fatalf("ProcessArchive: %v", err)
	}
	if n != 2 {
		t.Errorf("processed %d entries, want 2", n)
	}

	certs := cfg.Store.AllCertsFlat()
	if len(certs) != 2 {
		t.Fatalf("got %d certs in store, want 2", len(certs))
	}

	// Verify both CNs are present (order may vary)
	cns := map[string]bool{}
	for _, c := range certs {
		if c.Cert.Subject.CommonName != "" {
			cns[c.Cert.Subject.CommonName] = true
		}
	}
	if !cns["multi1.example.com"] || !cns["multi2.example.com"] {
		t.Errorf("expected both multi1 and multi2 CNs, got %v", cns)
	}
}

func TestProcessArchive_ChainFileInSingleEntry(t *testing.T) {
	// WHY: Verifies that a single archive entry containing multiple
	// concatenated PEM certificates (a chain file) ingests all certs.
	t.Parallel()
	ca := newRSACA(t)
	leaf := newRSALeaf(t, ca, "chain.example.com", []string{"chain.example.com"}, nil)

	// Concatenate leaf + CA PEM into one file
	chainPEM := append([]byte{}, leaf.certPEM...)
	chainPEM = append(chainPEM, ca.certPEM...)

	zipData := createTestZip(t, map[string][]byte{
		"chain.pem": chainPEM,
	})

	cfg := newTestConfig(t)
	n, err := ProcessArchive(ProcessArchiveInput{
		ArchivePath: "test.zip",
		Data:        zipData,
		Format:      "zip",
		Limits:      DefaultArchiveLimits(),
		Store:       cfg.Store, Passwords: cfg.Passwords,
	})
	if err != nil {
		t.Fatalf("ProcessArchive: %v", err)
	}
	if n != 1 {
		t.Errorf("processed %d entries, want 1", n)
	}

	certs := cfg.Store.AllCertsFlat()
	if len(certs) != 2 {
		t.Errorf("got %d certs in store, want 2 (leaf + CA from chain file)", len(certs))
	}
}

func TestProcessArchive_MixedContentIgnoresNonCrypto(t *testing.T) {
	// WHY: Verifies that non-crypto files (README, Makefile, etc.) in an
	// archive are silently ignored while crypto files are still ingested.
	t.Parallel()
	ca := newRSACA(t)
	leaf := newRSALeaf(t, ca, "mixed.example.com", []string{"mixed.example.com"}, nil)

	zipData := createTestZip(t, map[string][]byte{
		"README.md":        []byte("# Certificate Bundle\n"),
		"Makefile":         []byte("all: build\n"),
		"data.json":        []byte(`{"key": "value"}`),
		"certs/server.pem": leaf.certPEM,
	})

	cfg := newTestConfig(t)
	n, err := ProcessArchive(ProcessArchiveInput{
		ArchivePath: "test.zip",
		Data:        zipData,
		Format:      "zip",
		Limits:      DefaultArchiveLimits(),
		Store:       cfg.Store, Passwords: cfg.Passwords,
	})
	if err != nil {
		t.Fatalf("ProcessArchive: %v", err)
	}
	// All 4 entries are "processed" (passed to ProcessData), but only the PEM one produces a cert
	if n != 4 {
		t.Errorf("processed %d entries, want 4", n)
	}

	certs := cfg.Store.AllCertsFlat()
	if len(certs) != 1 {
		t.Errorf("got %d certs in store, want 1", len(certs))
	}
}

func TestProcessArchive_ZeroByteEntry(t *testing.T) {
	// WHY: Verifies that zero-byte entries in archives don't cause panics
	// or phantom records.
	t.Parallel()

	zipData := createTestZip(t, map[string][]byte{
		"empty.pem": {},
		"empty.der": {},
	})

	cfg := newTestConfig(t)
	n, err := ProcessArchive(ProcessArchiveInput{
		ArchivePath: "test.zip",
		Data:        zipData,
		Format:      "zip",
		Limits:      DefaultArchiveLimits(),
		Store:       cfg.Store, Passwords: cfg.Passwords,
	})
	if err != nil {
		t.Fatalf("ProcessArchive: %v", err)
	}
	if n != 2 {
		t.Errorf("processed %d entries, want 2", n)
	}

	certs := cfg.Store.AllCertsFlat()
	if len(certs) != 0 {
		t.Errorf("got %d certs in store, want 0 (empty entries)", len(certs))
	}
}

func TestProcessArchive_EntryExceedsMaxSize_ZIP(t *testing.T) {
	// WHY: Verifies that individual ZIP entries exceeding MaxEntrySize are
	// skipped based on the UncompressedSize64 header check.
	t.Parallel()
	ca := newRSACA(t)
	leaf := newRSALeaf(t, ca, "big-entry.example.com", []string{"big-entry.example.com"}, nil)

	zipData := createTestZip(t, map[string][]byte{
		"certs/server.pem": leaf.certPEM,
	})

	limits := DefaultArchiveLimits()
	limits.MaxEntrySize = 10 // absurdly small — cert PEM will exceed this

	cfg := newTestConfig(t)
	n, err := ProcessArchive(ProcessArchiveInput{
		ArchivePath: "test.zip",
		Data:        zipData,
		Format:      "zip",
		Limits:      limits,
		Store:       cfg.Store, Passwords: cfg.Passwords,
	})
	if err != nil {
		t.Fatalf("ProcessArchive: %v", err)
	}
	if n != 0 {
		t.Errorf("processed %d entries, want 0 (entry should be skipped)", n)
	}

	certs := cfg.Store.AllCertsFlat()
	if len(certs) != 0 {
		t.Errorf("got %d certs in store, want 0", len(certs))
	}
}

func TestProcessArchive_TarEntryExceedsMaxSize(t *testing.T) {
	// WHY: Verifies that oversized TAR entries are skipped and the reader
	// advances past them so subsequent entries are still processed.
	// Uses deterministic entry ordering (writes TAR directly, not via map).
	t.Parallel()
	ca := newRSACA(t)
	leaf := newRSALeaf(t, ca, "after-big.example.com", []string{"after-big.example.com"}, nil)
	bigData := make([]byte, 100_000)

	// Build TAR with deterministic order: big entry FIRST, then cert
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	writeEntry := func(name string, data []byte) {
		if err := tw.WriteHeader(&tar.Header{Name: name, Size: int64(len(data)), Mode: 0644}); err != nil {
			t.Fatalf("write TAR header %s: %v", name, err)
		}
		if _, err := tw.Write(data); err != nil {
			t.Fatalf("write TAR entry %s: %v", name, err)
		}
	}
	writeEntry("big.bin", bigData)
	writeEntry("certs/server.pem", leaf.certPEM)
	if err := tw.Close(); err != nil {
		t.Fatalf("close TAR: %v", err)
	}
	tarData := buf.Bytes()

	limits := DefaultArchiveLimits()
	limits.MaxEntrySize = 10_000 // big.bin (100KB) exceeds, cert PEM (~1.3KB) fits

	cfg := newTestConfig(t)
	n, err := ProcessArchive(ProcessArchiveInput{
		ArchivePath: "test.tar",
		Data:        tarData,
		Format:      "tar",
		Limits:      limits,
		Store:       cfg.Store, Passwords: cfg.Passwords,
	})
	if err != nil {
		t.Fatalf("ProcessArchive: %v", err)
	}
	if n != 1 {
		t.Errorf("processed %d entries, want 1 (big.bin skipped, cert processed)", n)
	}

	certs := cfg.Store.AllCertsFlat()
	if len(certs) != 1 {
		t.Fatalf("got %d certs in store, want 1", len(certs))
	}
	if certs[0].Cert.Subject.CommonName != "after-big.example.com" {
		t.Errorf("cert CN = %q, want %q", certs[0].Cert.Subject.CommonName, "after-big.example.com")
	}
}

func TestProcessArchive_EntryCountLimit(t *testing.T) {
	// WHY: Verifies that MaxEntryCount stops processing at the specified limit,
	// protecting against archive bombs. Covers both boundary (0) and mid-stream (1).
	t.Parallel()
	ca := newRSACA(t)
	leaf := newRSALeaf(t, ca, "count.example.com", []string{"count.example.com"}, nil)

	files := map[string][]byte{
		"a.pem": leaf.certPEM,
		"b.pem": leaf.certPEM,
		"c.pem": leaf.certPEM,
	}

	tests := []struct {
		name      string
		format    string
		builder   func(t *testing.T, files map[string][]byte) []byte
		maxCount  int
		wantCount int
	}{
		{"zip/limit=1", "zip", createTestZip, 1, 1},
		{"tar/limit=1", "tar", createTestTar, 1, 1},
		{"zip/limit=0", "zip", createTestZip, 0, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			archiveData := tt.builder(t, files)

			limits := DefaultArchiveLimits()
			limits.MaxEntryCount = tt.maxCount

			cfg := newTestConfig(t)
			n, err := ProcessArchive(ProcessArchiveInput{
				ArchivePath: "test." + tt.format,
				Data:        archiveData,
				Format:      tt.format,
				Limits:      limits,
				Store:       cfg.Store, Passwords: cfg.Passwords,
			})
			if err != nil {
				t.Fatalf("ProcessArchive: %v", err)
			}
			if n != tt.wantCount {
				t.Errorf("processed %d entries, want %d (MaxEntryCount=%d)", n, tt.wantCount, tt.maxCount)
			}
		})
	}
}

func TestProcessArchive_TotalSizeLimit(t *testing.T) {
	// WHY: Verifies that the total extracted size limit stops processing,
	// preventing an archive from consuming unbounded memory.
	t.Parallel()
	ca := newRSACA(t)
	leaf := newRSALeaf(t, ca, "totalsize.example.com", []string{"totalsize.example.com"}, nil)

	files := map[string][]byte{
		"a.pem": leaf.certPEM,
		"b.pem": leaf.certPEM,
	}

	tests := []struct {
		name    string
		format  string
		builder func(t *testing.T, files map[string][]byte) []byte
	}{
		{"zip", "zip", createTestZip},
		{"tar", "tar", createTestTar},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			archiveData := tt.builder(t, files)

			limits := DefaultArchiveLimits()
			// Set total size just big enough for one cert but not two
			limits.MaxTotalSize = int64(len(leaf.certPEM)) + 10

			cfg := newTestConfig(t)
			n, err := ProcessArchive(ProcessArchiveInput{
				ArchivePath: "test." + tt.format,
				Data:        archiveData,
				Format:      tt.format,
				Limits:      limits,
				Store:       cfg.Store, Passwords: cfg.Passwords,
			})
			if err != nil {
				t.Fatalf("ProcessArchive: %v", err)
			}
			if n != 1 {
				t.Errorf("processed %d entries, want exactly 1 (total size limit should stop after first)", n)
			}
		})
	}
}

func TestProcessArchive_EmptyArchive(t *testing.T) {
	// WHY: Verifies that empty archives of all formats are handled gracefully
	// with 0 entries and no error.
	t.Parallel()

	tests := []struct {
		name    string
		format  string
		builder func(t *testing.T, files map[string][]byte) []byte
	}{
		{"zip", "zip", createTestZip},
		{"tar", "tar", createTestTar},
		{"tar.gz", "tar.gz", createTestTarGz},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			archiveData := tt.builder(t, map[string][]byte{})

			cfg := newTestConfig(t)
			n, err := ProcessArchive(ProcessArchiveInput{
				ArchivePath: "empty." + tt.name,
				Data:        archiveData,
				Format:      tt.format,
				Limits:      DefaultArchiveLimits(),
				Store:       cfg.Store, Passwords: cfg.Passwords,
			})
			if err != nil {
				t.Fatalf("ProcessArchive: %v", err)
			}
			if n != 0 {
				t.Errorf("processed %d entries, want 0", n)
			}
		})
	}
}

func TestProcessArchive_CorruptedArchive(t *testing.T) {
	// WHY: Verifies that corrupted archive data returns an error rather than
	// panicking or producing garbage output. Tests all three formats.
	t.Parallel()

	tests := []struct {
		name   string
		format string
	}{
		{"corrupted zip", "zip"},
		{"corrupted tar", "tar"},
		{"corrupted tar.gz", "tar.gz"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			cfg := newTestConfig(t)
			_, err := ProcessArchive(ProcessArchiveInput{
				ArchivePath: "bad." + tt.format,
				Data:        []byte("this is not a valid archive"),
				Format:      tt.format,
				Limits:      DefaultArchiveLimits(),
				Store:       cfg.Store, Passwords: cfg.Passwords,
			})
			if err == nil {
				t.Errorf("expected error for corrupted %s, got nil", tt.format)
			}
			if err.Error() == "" {
				t.Error("error message should not be empty")
			}
		})
	}
}

func TestProcessArchive_NestedArchiveNotRecursed(t *testing.T) {
	// WHY: Verifies that archive files nested inside an archive are skipped
	// (no recursive extraction), preventing nested archive bombs.
	t.Parallel()
	ca := newRSACA(t)
	leaf := newRSALeaf(t, ca, "nested.example.com", []string{"nested.example.com"}, nil)

	innerZip := createTestZip(t, map[string][]byte{
		"inner.pem": leaf.certPEM,
	})

	outerZip := createTestZip(t, map[string][]byte{
		"outer.pem":     leaf.certPEM,
		"inner.zip":     innerZip,
		"archive.tar":   []byte("fake tar"),
		"bundle.tar.gz": []byte("fake tar.gz"),
		"archive.tgz":   []byte("fake tgz"),
	})

	cfg := newTestConfig(t)
	n, err := ProcessArchive(ProcessArchiveInput{
		ArchivePath: "outer.zip",
		Data:        outerZip,
		Format:      "zip",
		Limits:      DefaultArchiveLimits(),
		Store:       cfg.Store, Passwords: cfg.Passwords,
	})
	if err != nil {
		t.Fatalf("ProcessArchive: %v", err)
	}
	if n != 1 {
		t.Errorf("processed %d entries, want 1 (nested archives should be skipped)", n)
	}

	certs := cfg.Store.AllCertsFlat()
	if len(certs) != 1 {
		t.Errorf("got %d certs in store, want 1", len(certs))
	}
}

func TestProcessArchive_ExpiredCertStored(t *testing.T) {
	// WHY: Expired certificates inside archives must be ingested into the store;
	// filtering is an output-only concern. This ensures chain building works even
	// when intermediates are expired.
	t.Parallel()
	ca := newRSACA(t)
	expired := newExpiredLeaf(t, ca)

	zipData := createTestZip(t, map[string][]byte{
		"expired.pem": expired.certPEM,
	})

	cfg := newTestConfig(t)

	n, err := ProcessArchive(ProcessArchiveInput{
		ArchivePath: "test.zip",
		Data:        zipData,
		Format:      "zip",
		Limits:      DefaultArchiveLimits(),
		Store:       cfg.Store,
		Passwords:   cfg.Passwords,
	})
	if err != nil {
		t.Fatalf("ProcessArchive: %v", err)
	}
	if n != 1 {
		t.Errorf("processed %d entries, want 1", n)
	}

	certs := cfg.Store.AllCertsFlat()
	if len(certs) != 1 {
		t.Errorf("got %d certs in store, want 1 (expired certs should be stored)", len(certs))
	}
}

func TestProcessArchive_UnsupportedFormat(t *testing.T) {
	// WHY: Verifies that an unknown format string produces a clear error
	// with a descriptive message.
	t.Parallel()

	cfg := newTestConfig(t)
	_, err := ProcessArchive(ProcessArchiveInput{
		ArchivePath: "test.rar",
		Data:        []byte("data"),
		Format:      "rar",
		Limits:      DefaultArchiveLimits(),
		Store:       cfg.Store, Passwords: cfg.Passwords,
	})
	if err == nil {
		t.Fatal("expected error for unsupported format, got nil")
	}
	if !strings.Contains(err.Error(), "unsupported archive format") {
		t.Errorf("error %q should mention unsupported archive format", err.Error())
	}
}

func TestProcessArchive_DecompressionRatioLimit(t *testing.T) {
	// WHY: Verifies that the ZIP decompression ratio check rejects entries
	// with suspiciously high compression ratios — the primary zip bomb defense.
	// A 10KB zero-filled entry compresses to ~50 bytes (ratio ~200:1).
	t.Parallel()

	// Create a ZIP with a highly compressible entry (10KB of zeros)
	compressibleData := make([]byte, 10*1024)
	zipData := createTestZip(t, map[string][]byte{
		"zeros.pem": compressibleData,
	})

	limits := DefaultArchiveLimits()
	limits.MaxDecompressionRatio = 2 // very strict — will reject the zeros entry

	cfg := newTestConfig(t)
	n, err := ProcessArchive(ProcessArchiveInput{
		ArchivePath: "test.zip",
		Data:        zipData,
		Format:      "zip",
		Limits:      limits,
		Store:       cfg.Store, Passwords: cfg.Passwords,
	})
	if err != nil {
		t.Fatalf("ProcessArchive: %v", err)
	}
	if n != 0 {
		t.Errorf("processed %d entries, want 0 (high ratio should be rejected)", n)
	}
}

func TestProcessArchive_TarPartialCorruption(t *testing.T) {
	// WHY: Verifies graceful degradation when a TAR archive has valid entries
	// followed by corruption. The code should return the successfully processed
	// entries without an error, rather than discarding all progress.
	t.Parallel()
	ca := newRSACA(t)
	leaf := newRSALeaf(t, ca, "partial.example.com", []string{"partial.example.com"}, nil)

	// Build a valid TAR with one entry, then append garbage
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	if err := tw.WriteHeader(&tar.Header{Name: "valid.pem", Size: int64(len(leaf.certPEM)), Mode: 0644}); err != nil {
		t.Fatalf("write TAR header: %v", err)
	}
	if _, err := tw.Write(leaf.certPEM); err != nil {
		t.Fatalf("write TAR entry: %v", err)
	}
	// Don't close the writer cleanly — append garbage instead
	validTar := buf.Bytes()
	corruptedTar := append(validTar, []byte("CORRUPT_GARBAGE_DATA_THAT_BREAKS_TAR_PARSING")...)

	cfg := newTestConfig(t)
	n, err := ProcessArchive(ProcessArchiveInput{
		ArchivePath: "partial.tar",
		Data:        corruptedTar,
		Format:      "tar",
		Limits:      DefaultArchiveLimits(),
		Store:       cfg.Store, Passwords: cfg.Passwords,
	})
	// Should not return an error (graceful degradation)
	if err != nil {
		t.Fatalf("ProcessArchive should degrade gracefully, got error: %v", err)
	}
	if n != 1 {
		t.Errorf("processed %d entries, want 1 (valid entry before corruption)", n)
	}

	certs := cfg.Store.AllCertsFlat()
	if len(certs) != 1 {
		t.Errorf("got %d certs in store, want 1", len(certs))
	}
}
