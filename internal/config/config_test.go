package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadAppliesV1Defaults(t *testing.T) {
	path := writeConfig(t, `version: "v1"
target: "https://api.openai.com"
guards:
  - name: "inj"
    type: "regex"
    patterns:
      - "(?i)jailbreak"
`)

	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Version != "v1" {
		t.Fatalf("expected v1 config, got %q", cfg.Version)
	}
	if cfg.Listen != ":8080" {
		t.Fatalf("unexpected listen default: %q", cfg.Listen)
	}
	if cfg.Limits.MaxRequestBytes != 1<<20 {
		t.Fatalf("unexpected request limit: %d", cfg.Limits.MaxRequestBytes)
	}
	if cfg.Limits.MaxResponseBytes != 2<<20 {
		t.Fatalf("unexpected response limit: %d", cfg.Limits.MaxResponseBytes)
	}
	if cfg.Limits.GuardTimeoutMS != 100 {
		t.Fatalf("unexpected guard timeout: %d", cfg.Limits.GuardTimeoutMS)
	}
	if cfg.Streaming.Mode != "pass_through" {
		t.Fatalf("unexpected streaming mode: %q", cfg.Streaming.Mode)
	}
	if cfg.Guards[0].Action != "block" {
		t.Fatalf("unexpected guard action default: %q", cfg.Guards[0].Action)
	}
}

func TestLoadRejectsUnimplementedStreamingMode(t *testing.T) {
	path := writeConfig(t, `version: "v1"
target: "https://api.openai.com"
streaming:
  mode: "buffer"
guards:
  - name: "inj"
    type: "regex"
    patterns:
      - "(?i)jailbreak"
`)

	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "not implemented") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestSampleConfigLoads(t *testing.T) {
	path := writeConfig(t, Sample())
	if _, err := Load(path); err != nil {
		t.Fatal(err)
	}
}

func writeConfig(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}
