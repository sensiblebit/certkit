package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"sync"
	"time"
)

const scanProgressInterval = 250 * time.Millisecond

// scanProgress keeps the current activity visible while a file or phase runs.
type scanProgress struct {
	mu       sync.Mutex
	out      io.Writer
	activity string
	counts   string
	started  time.Time
	updated  time.Time
	visible  bool
	err      error
	stop     chan struct{}
	done     chan struct{}
	stopOnce sync.Once
}

func newScanProgress(out io.Writer) *scanProgress {
	return &scanProgress{out: out, stop: make(chan struct{}), done: make(chan struct{})}
}

func (p *scanProgress) Start(ctx context.Context) {
	if p.out == nil {
		close(p.done)
		return
	}
	go func() {
		defer close(p.done)
		ticker := time.NewTicker(scanProgressInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-p.stop:
				return
			case <-ticker.C:
				p.mu.Lock()
				p.render(time.Now())
				p.mu.Unlock()
			}
		}
	}()
}

func (p *scanProgress) SetActivity(activity string) error {
	slog.Debug("scan activity", "activity", activity)
	p.mu.Lock()
	defer p.mu.Unlock()
	p.activity = activity
	p.started = time.Now()
	if time.Since(p.updated) >= scanProgressInterval {
		p.render(p.started)
	}
	return p.err
}

func (p *scanProgress) SetCounts(counts string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.counts = counts
	return p.err
}

func (p *scanProgress) Stop() error {
	p.stopOnce.Do(func() { close(p.stop) })
	<-p.done
	p.mu.Lock()
	defer p.mu.Unlock()
	p.clear()
	return p.err
}

// The caller must hold mu while rendering or clearing the progress line.
func (p *scanProgress) render(now time.Time) {
	if p.out == nil || p.err != nil || p.activity == "" {
		return
	}
	elapsed := now.Sub(p.started).Truncate(time.Second)
	prefix := fmt.Sprintf("%s | %s | ", p.counts, elapsed)
	activity := p.activity
	// Keep progress within 80 columns. Preserve the filename when a path is long.
	if available := max(0, 79-len(prefix)); len(activity) > available {
		tail := max(0, available-3)
		activity = "..." + activity[len(activity)-tail:]
	}
	if _, err := fmt.Fprintf(p.out, "\r\033[K%s%s", prefix, activity); err != nil {
		p.err = fmt.Errorf("writing scan progress: %w", err)
		return
	}
	p.visible = true
	p.updated = now
}

func (p *scanProgress) clear() {
	if !p.visible {
		return
	}
	if _, err := fmt.Fprint(p.out, "\r\033[K"); err != nil && p.err == nil {
		p.err = fmt.Errorf("clearing scan progress: %w", err)
	}
	p.visible = false
}

// Clear progress before logs so warnings start on their own line.
type scanProgressLogHandler struct {
	slog.Handler
	progress *scanProgress
}

func (h scanProgressLogHandler) Handle(ctx context.Context, record slog.Record) error {
	h.progress.mu.Lock()
	defer h.progress.mu.Unlock()
	h.progress.clear()
	if err := h.Handler.Handle(ctx, record); err != nil {
		return fmt.Errorf("writing scan log: %w", err)
	}
	return nil
}

func (h scanProgressLogHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return scanProgressLogHandler{Handler: h.Handler.WithAttrs(attrs), progress: h.progress}
}

func (h scanProgressLogHandler) WithGroup(name string) slog.Handler {
	return scanProgressLogHandler{Handler: h.Handler.WithGroup(name), progress: h.progress}
}
