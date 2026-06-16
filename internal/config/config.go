// Package config loads and validates the YAML policy file that drives gorial.
package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Config is the top-level policy document.
type Config struct {
	Version   string          `yaml:"version"`
	Listen    string          `yaml:"listen"`
	Target    string          `yaml:"target"`
	Limits    LimitsConfig    `yaml:"limits"`
	Streaming StreamingConfig `yaml:"streaming"`
	Log       LogConfig       `yaml:"log"`
	Guards    []GuardConfig   `yaml:"guards"`
}

// LimitsConfig bounds memory use and defines explicit bypass/block behavior.
type LimitsConfig struct {
	MaxRequestBytes    int64  `yaml:"max_request_bytes"`
	MaxResponseBytes   int64  `yaml:"max_response_bytes"`
	GuardTimeoutMS     int    `yaml:"guard_timeout_ms"`
	OnRequestTooLarge  string `yaml:"on_request_too_large"`  // block | pass | bypass
	OnResponseTooLarge string `yaml:"on_response_too_large"` // block | pass | bypass
}

// StreamingConfig controls how outbound Server-Sent Events are handled.
type StreamingConfig struct {
	Mode string `yaml:"mode"` // pass_through; other modes are future work
}

// LogConfig controls the structured audit log.
type LogConfig struct {
	Format         string `yaml:"format"`          // "json" (default) or "text"
	File           string `yaml:"file"`            // empty = stdout
	IncludePayload bool   `yaml:"include_payload"` // reserved; default false
}

// GuardConfig is a single guardrail declaration.
type GuardConfig struct {
	Name     string   `yaml:"name"`
	Type     string   `yaml:"type"`     // "regex" (default) or "pii"
	Action   string   `yaml:"action"`   // "block" (default) or "redact"
	Patterns []string `yaml:"patterns"` // regex sources, for type "regex"
	Apply    []string `yaml:"apply"`    // "inbound" and/or "outbound"; empty = both
}

// Load reads, parses, defaults and validates the policy file at path.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse yaml: %w", err)
	}
	cfg.applyDefaults()
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func (c *Config) applyDefaults() {
	if c.Version == "" {
		c.Version = "legacy"
	}
	if c.Listen == "" {
		c.Listen = ":8080"
	}
	if c.Limits.MaxRequestBytes == 0 {
		c.Limits.MaxRequestBytes = 1 << 20
	}
	if c.Limits.MaxResponseBytes == 0 {
		c.Limits.MaxResponseBytes = 2 << 20
	}
	if c.Limits.GuardTimeoutMS == 0 {
		c.Limits.GuardTimeoutMS = 100
	}
	if c.Limits.OnRequestTooLarge == "" {
		c.Limits.OnRequestTooLarge = "block"
	}
	if c.Limits.OnResponseTooLarge == "" {
		c.Limits.OnResponseTooLarge = "bypass"
	}
	if c.Streaming.Mode == "" {
		c.Streaming.Mode = "pass_through"
	}
	if c.Log.Format == "" {
		c.Log.Format = "json"
	}
	for i := range c.Guards {
		if c.Guards[i].Type == "" {
			c.Guards[i].Type = "regex"
		}
		if c.Guards[i].Action == "" {
			c.Guards[i].Action = "block"
		}
	}
}

func (c *Config) validate() error {
	switch c.Version {
	case "legacy", "v1":
	default:
		return fmt.Errorf("version %q is not supported", c.Version)
	}
	if c.Target == "" {
		return fmt.Errorf("target is required")
	}
	if c.Limits.MaxRequestBytes < 0 {
		return fmt.Errorf("limits.max_request_bytes must be >= 0")
	}
	if c.Limits.MaxResponseBytes < 0 {
		return fmt.Errorf("limits.max_response_bytes must be >= 0")
	}
	if c.Limits.GuardTimeoutMS < 0 {
		return fmt.Errorf("limits.guard_timeout_ms must be >= 0")
	}
	if err := validateSizeAction("limits.on_request_too_large", c.Limits.OnRequestTooLarge); err != nil {
		return err
	}
	if err := validateSizeAction("limits.on_response_too_large", c.Limits.OnResponseTooLarge); err != nil {
		return err
	}
	if c.Streaming.Mode != "pass_through" {
		return fmt.Errorf("streaming.mode %q is not implemented; use pass_through", c.Streaming.Mode)
	}
	switch c.Log.Format {
	case "json", "text":
	default:
		return fmt.Errorf("log.format %q must be json or text", c.Log.Format)
	}
	for i, g := range c.Guards {
		if g.Name == "" {
			return fmt.Errorf("guard #%d: name is required", i)
		}
		switch g.Action {
		case "block", "redact":
		default:
			return fmt.Errorf("guard %q: invalid action %q", g.Name, g.Action)
		}
		switch g.Type {
		case "regex":
			if len(g.Patterns) == 0 {
				return fmt.Errorf("guard %q: regex guard needs at least one pattern", g.Name)
			}
		case "pii":
		default:
			return fmt.Errorf("guard %q: unknown type %q", g.Name, g.Type)
		}
		for _, d := range g.Apply {
			if d != "inbound" && d != "outbound" {
				return fmt.Errorf("guard %q: invalid apply direction %q", g.Name, d)
			}
		}
	}
	return nil
}

func validateSizeAction(field, action string) error {
	switch action {
	case "block", "pass", "bypass":
		return nil
	default:
		return fmt.Errorf("%s %q must be block, pass, or bypass", field, action)
	}
}

// Sample returns a complete v1 policy file suitable for `gorial sample-config`.
func Sample() string {
	return `version: "v1"
listen: ":8080"
target: "https://api.openai.com"

limits:
  max_request_bytes: 1048576
  max_response_bytes: 2097152
  guard_timeout_ms: 100
  on_request_too_large: "block"
  on_response_too_large: "bypass"

streaming:
  mode: "pass_through"

log:
  format: "json"
  include_payload: false

guards:
  - name: "prompt-injection"
    type: "regex"
    action: "block"
    apply: ["inbound"]
    patterns:
      - "(?i)ignore (all|previous|above) instructions"
      - "(?i)reveal (your|the) (system )?prompt"

  - name: "secret-leak"
    type: "regex"
    action: "redact"
    patterns:
      - "sk-[A-Za-z0-9]{20,}"
      - "ghp_[A-Za-z0-9]{36}"
      - "AKIA[0-9A-Z]{16}"

  - name: "pii-scrub"
    type: "pii"
    action: "redact"
    apply: ["outbound"]
`
}
