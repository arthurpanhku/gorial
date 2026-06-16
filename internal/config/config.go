// Package config loads and validates the YAML policy file that drives gorial.
package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Config is the top-level policy document.
type Config struct {
	Listen string        `yaml:"listen"`
	Target string        `yaml:"target"`
	Log    LogConfig     `yaml:"log"`
	Guards []GuardConfig `yaml:"guards"`
}

// LogConfig controls the structured audit log.
type LogConfig struct {
	Format string `yaml:"format"` // "json" (default) or "text"
	File   string `yaml:"file"`   // empty = stdout
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
	if c.Listen == "" {
		c.Listen = ":8080"
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
	if c.Target == "" {
		return fmt.Errorf("target is required")
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
