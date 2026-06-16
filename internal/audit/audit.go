// Package audit writes structured decision logs for every inspected request
// and response, so guardrail decisions are reviewable after the fact.
package audit

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sync"
	"time"

	"github.com/arthurpanhku/gorial/internal/config"
)

// Entry is a single audit record.
type Entry struct {
	Time      time.Time `json:"time"`
	Direction string    `json:"direction"`
	Method    string    `json:"method,omitempty"`
	Path      string    `json:"path"`
	Status    int       `json:"status,omitempty"`
	Blocked   bool      `json:"blocked"`
	Findings  []string  `json:"findings,omitempty"`
	LatencyMS float64   `json:"latency_ms,omitempty"`
}

// Logger serializes audit entries to an output sink. It is safe for
// concurrent use.
type Logger struct {
	mu     sync.Mutex
	w      io.Writer
	format string
}

// New builds a Logger from the log config. When File is empty it writes to
// stdout.
func New(cfg config.LogConfig) (*Logger, error) {
	var w io.Writer = os.Stdout
	if cfg.File != "" {
		f, err := os.OpenFile(cfg.File, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
		if err != nil {
			return nil, fmt.Errorf("open audit log %q: %w", cfg.File, err)
		}
		w = f
	}
	return &Logger{w: w, format: cfg.Format}, nil
}

// Log writes one entry.
func (l *Logger) Log(e Entry) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.format == "text" {
		fmt.Fprintf(l.w, "%s %-8s %s blocked=%v findings=%v\n",
			e.Time.Format(time.RFC3339), e.Direction, e.Path, e.Blocked, e.Findings)
		return
	}
	_ = json.NewEncoder(l.w).Encode(e)
}
