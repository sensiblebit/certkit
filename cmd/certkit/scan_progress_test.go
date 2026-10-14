package main

import (
	"bytes"
	"errors"
	"io"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"
)

type scanProgressRecorder struct {
	mu     sync.Mutex
	buf    bytes.Buffer
	writes chan string
}

func (w *scanProgressRecorder) Write(data []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.buf.Write(data)
	select {
	case w.writes <- string(data):
	default:
	}
	return len(data), nil
}

func (w *scanProgressRecorder) String() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.buf.String()
}

func TestScanProgress_ReportsActiveWorkAndSeparatesWarnings(t *testing.T) {
	t.Parallel()
	out := &scanProgressRecorder{writes: make(chan string, 16)}
	progress := newScanProgress(out)
	progress.Start(t.Context())
	t.Cleanup(func() {
		if err := progress.Stop(); err != nil {
			t.Error(err)
		}
	})
	if err := progress.SetCounts("52 certs, 20 keys, 341 files"); err != nil {
		t.Fatal(err)
	}
	if err := progress.SetActivity(`Scanning "slow.p12"`); err != nil {
		t.Fatal(err)
	}
	// A second update must arrive while the same file is still processing.
	for range 2 {
		select {
		case line := <-out.writes:
			if !strings.Contains(line, `Scanning "slow.p12"`) || !strings.Contains(line, "341 files") {
				t.Fatalf("missing active file or counts: %q", line)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("progress did not update while processing a file")
		}
	}
	logger := slog.New(scanProgressLogHandler{
		Handler: slog.NewTextHandler(out, nil), progress: progress,
	}).WithGroup("archive").With("path", "input.zip")
	logger.WarnContext(t.Context(), "entry skipped")
	if !strings.Contains(out.String(), "\r\033[Ktime=") || !strings.Contains(out.String(), "archive.path=input.zip") {
		t.Fatalf("warning did not clear progress or retain attributes: %q", out.String())
	}
	if err := progress.SetActivity("Resolving certificate chains (AIA)"); err != nil {
		t.Fatal(err)
	}
	deadline := time.After(3 * time.Second)
	for {
		select {
		case line := <-out.writes:
			if strings.Contains(line, "Resolving certificate chains (AIA)") {
				return
			}
		case <-deadline:
			t.Fatal("progress did not change to the AIA phase")
		}
	}
}

func TestScanProgress_LongPathFitsOnOneLine(t *testing.T) {
	t.Parallel()
	var out bytes.Buffer
	progress := newScanProgress(&out)
	if err := progress.SetCounts("52 certs, 20 keys, 341 files"); err != nil {
		t.Fatal(err)
	}
	if err := progress.SetActivity("Scanning " + strings.Repeat("directory/", 30) + "problem.json"); err != nil {
		t.Fatal(err)
	}
	line := strings.TrimPrefix(out.String(), "\r\033[K")
	if len(line) > 79 || !strings.HasSuffix(line, "problem.json") || !strings.Contains(line, "0s") {
		t.Fatalf("long path hid the filename or exceeded one line: %q", line)
	}
}

type scanProgressFailedWriter struct{}

func (scanProgressFailedWriter) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }

func TestScanProgress_PreservesWriteError(t *testing.T) {
	t.Parallel()
	progress := newScanProgress(scanProgressFailedWriter{})
	progress.Start(t.Context())
	if err := progress.SetActivity("Scanning input"); !errors.Is(err, io.ErrClosedPipe) {
		t.Errorf("progress lost the write error: %v", err)
	}
	if err := progress.Stop(); !errors.Is(err, io.ErrClosedPipe) {
		t.Errorf("cleanup lost the write error: %v", err)
	}
}
