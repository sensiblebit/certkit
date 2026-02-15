package internal

import (
	"archive/tar"
	"bytes"
	"math"
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
				Config:      cfg,
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
		Config:      cfg,
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
		Config:      cfg,
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
		Config:      cfg,
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
		Config:      cfg,
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
		Config:      cfg,
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
		Config:      cfg,
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
		Config:      cfg,
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
		Config:      cfg,
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
		Config:      cfg,
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
		Config:      cfg,
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
	// WHY: Verifies that the entry count limit stops processing before
	// exhausting all entries, protecting against archive bombs with many files.
	t.Parallel()
	ca := newRSACA(t)
	leaf := newRSALeaf(t, ca, "count.example.com", []string{"count.example.com"}, nil)

	zipData := createTestZip(t, map[string][]byte{
		"a.pem": leaf.certPEM,
		"b.pem": leaf.certPEM,
		"c.pem": leaf.certPEM,
	})

	limits := DefaultArchiveLimits()
	limits.MaxEntryCount = 1

	cfg := newTestConfig(t)
	n, err := ProcessArchive(ProcessArchiveInput{
		ArchivePath: "test.zip",
		Data:        zipData,
		Format:      "zip",
		Limits:      limits,
		Config:      cfg,
	})
	if err != nil {
		t.Fatalf("ProcessArchive: %v", err)
	}
	if n != 1 {
		t.Errorf("processed %d entries, want exactly 1 (limit should stop after first)", n)
	}
}

func TestProcessArchive_TotalSizeLimit(t *testing.T) {
	// WHY: Verifies that the total extracted size limit stops processing,
	// preventing an archive from consuming unbounded memory.
	t.Parallel()
	ca := newRSACA(t)
	leaf := newRSALeaf(t, ca, "totalsize.example.com", []string{"totalsize.example.com"}, nil)

	zipData := createTestZip(t, map[string][]byte{
		"a.pem": leaf.certPEM,
		"b.pem": leaf.certPEM,
	})

	limits := DefaultArchiveLimits()
	// Set total size just big enough for one cert but not two
	limits.MaxTotalSize = int64(len(leaf.certPEM)) + 10

	cfg := newTestConfig(t)
	n, err := ProcessArchive(ProcessArchiveInput{
		ArchivePath: "test.zip",
		Data:        zipData,
		Format:      "zip",
		Limits:      limits,
		Config:      cfg,
	})
	if err != nil {
		t.Fatalf("ProcessArchive: %v", err)
	}
	if n > 1 {
		t.Errorf("processed %d entries, want at most 1 (total size limit should stop)", n)
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
				Config:      cfg,
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
				Config:      cfg,
			})
			if err == nil {
				t.Errorf("expected error for corrupted %s, got nil", tt.format)
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
		Config:      cfg,
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

func TestProcessArchive_ExpiredCertRejectedByDefault(t *testing.T) {
	// WHY: Verifies that expired certificates inside archives are filtered
	// when IncludeExpired is false, matching non-archive scan behavior.
	t.Parallel()
	ca := newRSACA(t)
	expired := newExpiredLeaf(t, ca)

	zipData := createTestZip(t, map[string][]byte{
		"expired.pem": expired.certPEM,
	})

	cfg := newTestConfig(t)
	cfg.IncludeExpired = false

	n, err := ProcessArchive(ProcessArchiveInput{
		ArchivePath: "test.zip",
		Data:        zipData,
		Format:      "zip",
		Limits:      DefaultArchiveLimits(),
		Config:      cfg,
	})
	if err != nil {
		t.Fatalf("ProcessArchive: %v", err)
	}
	if n != 1 {
		t.Errorf("processed %d entries, want 1 (entry processed, cert filtered)", n)
	}

	certs := cfg.Store.AllCertsFlat()
	if len(certs) != 0 {
		t.Errorf("got %d certs in store, want 0 (expired should be filtered)", len(certs))
	}
}

func TestProcessArchive_ExpiredCertIncludedWhenAllowed(t *testing.T) {
	// WHY: Verifies that expired certificates inside archives are included
	// when IncludeExpired is true.
	t.Parallel()
	ca := newRSACA(t)
	expired := newExpiredLeaf(t, ca)

	zipData := createTestZip(t, map[string][]byte{
		"expired.pem": expired.certPEM,
	})

	cfg := newTestConfig(t)
	cfg.IncludeExpired = true

	n, err := ProcessArchive(ProcessArchiveInput{
		ArchivePath: "test.zip",
		Data:        zipData,
		Format:      "zip",
		Limits:      DefaultArchiveLimits(),
		Config:      cfg,
	})
	if err != nil {
		t.Fatalf("ProcessArchive: %v", err)
	}
	if n != 1 {
		t.Errorf("processed %d entries, want 1", n)
	}

	certs := cfg.Store.AllCertsFlat()
	if len(certs) != 1 {
		t.Errorf("got %d certs in store, want 1 (expired should be included)", len(certs))
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
		Config:      cfg,
	})
	if err == nil {
		t.Fatal("expected error for unsupported format, got nil")
	}
	if !strings.Contains(err.Error(), "unsupported archive format") {
		t.Errorf("error %q should mention unsupported archive format", err.Error())
	}
}

func TestProcessArchive_EntryCountLimitZero(t *testing.T) {
	// WHY: Verifies that MaxEntryCount=0 immediately stops processing,
	// producing 0 entries and no error (boundary value test).
	t.Parallel()
	ca := newRSACA(t)
	leaf := newRSALeaf(t, ca, "zero-limit.example.com", []string{"zero-limit.example.com"}, nil)

	zipData := createTestZip(t, map[string][]byte{
		"cert.pem": leaf.certPEM,
	})

	limits := DefaultArchiveLimits()
	limits.MaxEntryCount = 0

	cfg := newTestConfig(t)
	n, err := ProcessArchive(ProcessArchiveInput{
		ArchivePath: "test.zip",
		Data:        zipData,
		Format:      "zip",
		Limits:      limits,
		Config:      cfg,
	})
	if err != nil {
		t.Fatalf("ProcessArchive: %v", err)
	}
	if n != 0 {
		t.Errorf("processed %d entries, want 0 (MaxEntryCount=0)", n)
	}
}

func TestProcessArchive_DefaultArchiveLimits(t *testing.T) {
	// WHY: Verifies that DefaultArchiveLimits returns the documented defaults,
	// catching accidental changes to safety thresholds.
	t.Parallel()

	limits := DefaultArchiveLimits()
	if limits.MaxDecompressionRatio != 100 {
		t.Errorf("MaxDecompressionRatio = %d, want 100", limits.MaxDecompressionRatio)
	}
	if limits.MaxTotalSize != 256*1024*1024 {
		t.Errorf("MaxTotalSize = %d, want %d", limits.MaxTotalSize, 256*1024*1024)
	}
	if limits.MaxEntryCount != 10_000 {
		t.Errorf("MaxEntryCount = %d, want 10000", limits.MaxEntryCount)
	}
	if limits.MaxEntrySize != 10*1024*1024 {
		t.Errorf("MaxEntrySize = %d, want %d", limits.MaxEntrySize, 10*1024*1024)
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
		Config:      cfg,
	})
	if err != nil {
		t.Fatalf("ProcessArchive: %v", err)
	}
	if n != 0 {
		t.Errorf("processed %d entries, want 0 (high ratio should be rejected)", n)
	}
}

func TestProcessArchive_TarEntryCountLimit(t *testing.T) {
	// WHY: Verifies that the entry count limit works for TAR archives,
	// not just ZIP. The TAR entry count check happens after reading the
	// header, so the ordering is slightly different from ZIP.
	t.Parallel()
	ca := newRSACA(t)
	leaf := newRSALeaf(t, ca, "tar-count.example.com", []string{"tar-count.example.com"}, nil)

	// Build TAR with deterministic order: 3 entries
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, name := range []string{"a.pem", "b.pem", "c.pem"} {
		if err := tw.WriteHeader(&tar.Header{Name: name, Size: int64(len(leaf.certPEM)), Mode: 0644}); err != nil {
			t.Fatalf("write TAR header: %v", err)
		}
		if _, err := tw.Write(leaf.certPEM); err != nil {
			t.Fatalf("write TAR entry: %v", err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("close TAR: %v", err)
	}

	limits := DefaultArchiveLimits()
	limits.MaxEntryCount = 1

	cfg := newTestConfig(t)
	n, err := ProcessArchive(ProcessArchiveInput{
		ArchivePath: "test.tar",
		Data:        buf.Bytes(),
		Format:      "tar",
		Limits:      limits,
		Config:      cfg,
	})
	if err != nil {
		t.Fatalf("ProcessArchive: %v", err)
	}
	if n != 1 {
		t.Errorf("processed %d entries, want 1 (TAR entry count limit)", n)
	}
}

func TestProcessArchive_TarTotalSizeLimit(t *testing.T) {
	// WHY: Verifies that the total size limit works for TAR archives,
	// not just ZIP. The TAR path uses header.Size for the budget check.
	t.Parallel()
	ca := newRSACA(t)
	leaf := newRSALeaf(t, ca, "tar-total.example.com", []string{"tar-total.example.com"}, nil)

	// Build TAR with deterministic order: 2 entries
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, name := range []string{"a.pem", "b.pem"} {
		if err := tw.WriteHeader(&tar.Header{Name: name, Size: int64(len(leaf.certPEM)), Mode: 0644}); err != nil {
			t.Fatalf("write TAR header: %v", err)
		}
		if _, err := tw.Write(leaf.certPEM); err != nil {
			t.Fatalf("write TAR entry: %v", err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("close TAR: %v", err)
	}

	limits := DefaultArchiveLimits()
	limits.MaxTotalSize = int64(len(leaf.certPEM)) + 10 // room for one but not two

	cfg := newTestConfig(t)
	n, err := ProcessArchive(ProcessArchiveInput{
		ArchivePath: "test.tar",
		Data:        buf.Bytes(),
		Format:      "tar",
		Limits:      limits,
		Config:      cfg,
	})
	if err != nil {
		t.Fatalf("ProcessArchive: %v", err)
	}
	if n > 1 {
		t.Errorf("processed %d entries, want at most 1 (TAR total size limit)", n)
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
		Config:      cfg,
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

func TestSafeLimitSize(t *testing.T) {
	// WHY: Verifies that safeLimitSize prevents int64 overflow when maxSize
	// is near math.MaxInt64. Without this, io.LimitReader gets a negative
	// limit and silently returns empty data — a zip bomb protection bypass.
	t.Parallel()

	tests := []struct {
		name  string
		input int64
		want  int64
	}{
		{"zero", 0, 1},
		{"normal", 100, 101},
		{"large", 10 * 1024 * 1024, 10*1024*1024 + 1},
		{"near max", math.MaxInt64 - 1, math.MaxInt64},
		{"at max", math.MaxInt64, math.MaxInt64},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := safeLimitSize(tt.input)
			if got != tt.want {
				t.Errorf("safeLimitSize(%d) = %d, want %d", tt.input, got, tt.want)
			}
		})
	}
}

func TestHasBinaryExtension_VirtualPaths(t *testing.T) {
	// WHY: Verifies that hasBinaryExtension correctly extracts the extension
	// from virtual paths with ":" separators. Without this fix, filepath.Ext
	// on "archive.zip:cert" returns ".zip:cert" instead of "".
	t.Parallel()

	tests := []struct {
		name string
		path string
		want bool
	}{
		{"normal .der", "certs/server.der", true},
		{"normal .pem", "certs/server.pem", true},
		{"normal .p12", "certs/bundle.p12", true},
		{"normal .jks", "certs/store.jks", true},
		{"normal .txt", "README.txt", false},
		{"no extension", "Makefile", false},
		{"virtual path with dir", "archive.zip:certs/server.der", true},
		{"virtual path flat .der", "archive.zip:server.der", true},
		{"virtual path no ext", "archive.zip:cert", false},
		{"virtual path no ext no dir", "archive.zip:Makefile", false},
		{"case insensitive", "archive.zip:SERVER.DER", true},
		{"virtual tar.gz path", "archive.tar.gz:certs/ca.pem", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := hasBinaryExtension(tt.path); got != tt.want {
				t.Errorf("hasBinaryExtension(%q) = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}
