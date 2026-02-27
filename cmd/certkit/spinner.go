package main

import (
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/mattn/go-isatty"
)

// spinner displays an animated progress indicator on stderr when the output
// is a terminal. It silently does nothing when piped or redirected.
type spinner struct {
	mu      sync.Mutex
	msg     string
	stop    chan struct{}
	done    chan struct{}
	started bool
}

// newSpinner creates a spinner with the given message. Call Start() to begin
// animating and Stop() when finished. The spinner only renders when stderr
// is a terminal — safe to use unconditionally.
func newSpinner(msg string) *spinner {
	return &spinner{
		msg:  msg,
		stop: make(chan struct{}),
		done: make(chan struct{}),
	}
}

// Start begins the spinner animation in a background goroutine.
func (s *spinner) Start() {
	if !isatty.IsTerminal(os.Stderr.Fd()) && !isatty.IsCygwinTerminal(os.Stderr.Fd()) {
		close(s.done)
		return
	}

	s.started = true
	go s.run()
}

// SetMessage updates the spinner text while it's running.
func (s *spinner) SetMessage(msg string) {
	s.mu.Lock()
	s.msg = msg
	s.mu.Unlock()
}

// Stop halts the spinner and clears the line.
func (s *spinner) Stop() {
	if !s.started {
		<-s.done
		return
	}
	close(s.stop)
	<-s.done
}

var spinnerFrames = [...]string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}

func (s *spinner) run() {
	defer close(s.done)

	ticker := time.NewTicker(80 * time.Millisecond)
	defer ticker.Stop()

	frame := 0
	for {
		s.mu.Lock()
		msg := s.msg
		s.mu.Unlock()

		fmt.Fprintf(os.Stderr, "\r%s %s", spinnerFrames[frame%len(spinnerFrames)], msg)
		frame++

		select {
		case <-s.stop:
			// Clear the spinner line.
			fmt.Fprintf(os.Stderr, "\r\033[K")
			return
		case <-ticker.C:
		}
	}
}
