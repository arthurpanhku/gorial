package audit

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/arthurpanhku/gorial/internal/config"
)

func TestLoggerJSONFormat(t *testing.T) {
	var buf bytes.Buffer
	l := &Logger{w: &buf, format: "json"}

	e := Entry{
		Time:      time.Date(2026, 1, 15, 12, 0, 0, 0, time.UTC),
		EventID:   "evt-1",
		RequestID: "req-1",
		Direction: "inbound",
		Method:    "POST",
		Path:      "/v1/chat/completions",
		Decision:  "block",
		Blocked:   true,
		Findings:  []string{"prompt-injection(block):(?i)ignore"},
		LatencyMS: 3.2,
	}
	l.Log(e)

	var decoded Entry
	if err := json.NewDecoder(&buf).Decode(&decoded); err != nil {
		t.Fatalf("invalid JSON: %v (raw: %s)", err, buf.String())
	}
	if decoded.Decision != "block" {
		t.Fatalf("expected block, got %s", decoded.Decision)
	}
	if !decoded.Blocked {
		t.Fatal("expected blocked")
	}
	if decoded.RequestID != "req-1" {
		t.Fatalf("expected req-1, got %s", decoded.RequestID)
	}
	if len(decoded.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(decoded.Findings))
	}
}

func TestLoggerTextFormat(t *testing.T) {
	var buf bytes.Buffer
	l := &Logger{w: &buf, format: "text"}

	e := Entry{
		Time:      time.Date(2026, 1, 15, 12, 0, 0, 0, time.UTC),
		RequestID: "req-2",
		Direction: "outbound",
		Path:      "/v1/chat/completions",
		Decision:  "redact",
		Blocked:   false,
		Bypassed:  false,
		Findings:  []string{"pii(redact):PII:EMAIL"},
	}
	l.Log(e)

	out := buf.String()
	if !strings.Contains(out, "request_id=req-2") {
		t.Fatalf("expected request_id in text output: %s", out)
	}
	if !strings.Contains(out, "decision=redact") {
		t.Fatalf("expected decision=redact in text output: %s", out)
	}
	if !strings.Contains(out, "blocked=false") {
		t.Fatalf("expected blocked=false in text output: %s", out)
	}
}

func TestLoggerBypassEntry(t *testing.T) {
	var buf bytes.Buffer
	l := &Logger{w: &buf, format: "json"}

	e := Entry{
		Time:         time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC),
		EventID:      "evt-bypass",
		RequestID:    "req-3",
		Direction:    "outbound",
		Path:         "/v1/chat/completions",
		Decision:     "bypass",
		Bypassed:     true,
		BypassReason: "streaming_pass_through",
	}
	l.Log(e)

	var decoded Entry
	if err := json.NewDecoder(&buf).Decode(&decoded); err != nil {
		t.Fatal(err)
	}
	if !decoded.Bypassed {
		t.Fatal("expected bypassed=true")
	}
	if decoded.BypassReason != "streaming_pass_through" {
		t.Fatalf("expected bypass reason, got %q", decoded.BypassReason)
	}
	if decoded.Decision != "bypass" {
		t.Fatalf("expected bypass, got %s", decoded.Decision)
	}
}

func TestLoggerAllowEntry(t *testing.T) {
	var buf bytes.Buffer
	l := &Logger{w: &buf, format: "json"}

	e := Entry{
		Time:      time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC),
		EventID:   "evt-allow",
		RequestID: "req-4",
		Direction: "inbound",
		Method:    "POST",
		Path:      "/v1/chat/completions",
		Decision:  "allow",
		Blocked:   false,
		LatencyMS: 1.5,
	}
	l.Log(e)

	var decoded Entry
	if err := json.NewDecoder(&buf).Decode(&decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Decision != "allow" {
		t.Fatalf("expected allow, got %s", decoded.Decision)
	}
	if decoded.Blocked {
		t.Fatal("expected not blocked")
	}
}

func TestLoggerConcurrency(t *testing.T) {
	var buf bytes.Buffer
	l := &Logger{w: &buf, format: "json"}

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			l.Log(Entry{
				Time:      time.Now(),
				EventID:   "evt",
				RequestID: "req",
				Direction: "inbound",
				Path:      "/",
				Decision:  "allow",
			})
		}(i)
	}
	wg.Wait()

	lines := 0
	for _, b := range bytes.Split(buf.Bytes(), []byte{'\n'}) {
		if len(b) > 0 {
			lines++
		}
	}
	if lines != 50 {
		t.Fatalf("expected 50 lines, got %d", lines)
	}
}

func TestLoggerToFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")

	l, err := New(config.LogConfig{Format: "json", File: path})
	if err != nil {
		t.Fatal(err)
	}

	l.Log(Entry{
		Time:      time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC),
		EventID:   "evt-file",
		RequestID: "req-file",
		Direction: "inbound",
		Path:      "/v1/chat/completions",
		Decision:  "allow",
	})

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	var decoded Entry
	if err := json.NewDecoder(bytes.NewReader(data)).Decode(&decoded); err != nil {
		t.Fatalf("invalid JSON from file: %v", err)
	}
	if decoded.EventID != "evt-file" {
		t.Fatalf("expected evt-file, got %s", decoded.EventID)
	}
}

func TestNewDefaultLoggerStdout(t *testing.T) {
	l, err := New(config.LogConfig{Format: "json", File: ""})
	if err != nil {
		t.Fatal(err)
	}
	if l == nil {
		t.Fatal("expected non-nil logger")
	}
	if l.format != "json" {
		t.Fatalf("expected json format, got %q", l.format)
	}
}

func TestNewLoggerInvalidFilePath(t *testing.T) {
	_, err := New(config.LogConfig{Format: "json", File: "/nonexistent/dir/shouldfail/audit.log"})
	if err == nil {
		t.Fatal("expected error for invalid file path")
	}
}

func TestLoggerZeroFieldsOmitted(t *testing.T) {
	var buf bytes.Buffer
	l := &Logger{w: &buf, format: "json"}

	// Minimal entry — omitempty should suppress zero values.
	l.Log(Entry{
		Time:      time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC),
		Direction: "inbound",
		Path:      "/",
	})

	out := buf.String()
	var decoded map[string]any
	if err := json.NewDecoder(strings.NewReader(out)).Decode(&decoded); err != nil {
		t.Fatal(err)
	}
	// Omitted fields should not appear.
	if _, ok := decoded["event_id"]; ok {
		t.Fatal("event_id should be omitted when empty")
	}
	if _, ok := decoded["findings"]; ok {
		t.Fatal("findings should be omitted when nil")
	}
	if _, ok := decoded["latency_ms"]; ok {
		t.Fatal("latency_ms should be omitted when zero")
	}
}

func TestLoggerRedactedFlag(t *testing.T) {
	var buf bytes.Buffer
	l := &Logger{w: &buf, format: "json"}

	l.Log(Entry{
		Time:      time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC),
		RequestID: "req-redact",
		Direction: "inbound",
		Path:      "/v1/chat/completions",
		Decision:  "redact",
		Redacted:  true,
		Findings:  []string{"secret-leak(redact):sk-[A-Za-z0-9]{20,}"},
	})

	var decoded Entry
	if err := json.NewDecoder(&buf).Decode(&decoded); err != nil {
		t.Fatal(err)
	}
	if !decoded.Redacted {
		t.Fatal("expected redacted=true")
	}
	if decoded.Blocked {
		t.Fatal("expected blocked=false for redacted")
	}
	if len(decoded.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(decoded.Findings))
	}
}

func TestLoggerStructuredFindingDetails(t *testing.T) {
	var buf bytes.Buffer
	l := &Logger{w: &buf, format: "json"}

	l.Log(Entry{
		Time:      time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC),
		RequestID: "req-details",
		Direction: "outbound",
		Path:      "/v1/chat/completions",
		Decision:  "redact",
		Redacted:  true,
		Findings:  []string{"pii(redact):SECRET:OPENAI_KEY"},
		Details: []FindingDetail{
			{
				PolicyID:       "pii",
				Guard:          "pii",
				Detector:       "pii",
				DataClass:      "SECRET",
				Label:          "OPENAI_KEY",
				Action:         "redact",
				Direction:      "outbound",
				Reason:         "SECRET:OPENAI_KEY",
				Severity:       "critical",
				MatchCount:     1,
				RedactionCount: 1,
			},
		},
	})

	var decoded Entry
	if err := json.NewDecoder(&buf).Decode(&decoded); err != nil {
		t.Fatal(err)
	}
	if len(decoded.Findings) != 1 {
		t.Fatalf("expected compatibility finding, got %d", len(decoded.Findings))
	}
	if len(decoded.Details) != 1 {
		t.Fatalf("expected 1 structured detail, got %d", len(decoded.Details))
	}
	detail := decoded.Details[0]
	if detail.DataClass != "SECRET" || detail.Label != "OPENAI_KEY" {
		t.Fatalf("unexpected detail: %+v", detail)
	}
	if detail.MatchCount != 1 || detail.RedactionCount != 1 {
		t.Fatalf("expected counts, got %+v", detail)
	}
}
