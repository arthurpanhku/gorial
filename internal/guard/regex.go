package guard

import (
	"context"
	"regexp"
	"strings"
)

// RegexGuard matches content against a set of regular expressions. On a match
// it either blocks the request or rewrites the matched spans with a redaction
// marker, depending on its configured Action.
type RegexGuard struct {
	name     string
	action   Action
	dirs     map[Direction]bool
	patterns []*regexp.Regexp
}

// NewRegexGuard compiles patterns into a RegexGuard.
func NewRegexGuard(name string, action Action, dirs []Direction, patterns []string) (*RegexGuard, error) {
	compiled := make([]*regexp.Regexp, 0, len(patterns))
	for _, p := range patterns {
		re, err := regexp.Compile(p)
		if err != nil {
			return nil, err
		}
		compiled = append(compiled, re)
	}
	return &RegexGuard{
		name:     name,
		action:   action,
		dirs:     directionSet(dirs),
		patterns: compiled,
	}, nil
}

func (g *RegexGuard) Name() string { return g.name }

func (g *RegexGuard) Applies(d Direction) bool { return g.dirs[d] }

func (g *RegexGuard) Inspect(_ context.Context, c *Content) Finding {
	body := c.Body
	matched := false
	var reason string
	details := make([]FindingDetail, 0, len(g.patterns))
	for _, re := range g.patterns {
		matches := re.FindAllIndex(body, -1)
		if len(matches) == 0 {
			continue
		}
		matched = true
		reason = re.String()
		class := inferRegexDataClass(reason)
		detail := FindingDetail{
			PolicyID:   g.name,
			Guard:      g.name,
			Detector:   "regex",
			DataClass:  class,
			Label:      classLabel(class),
			Action:     g.action,
			Direction:  c.Direction,
			Reason:     reason,
			Severity:   severityFor(g.action, class),
			MatchCount: len(matches),
		}
		if g.action == ActionBlock {
			detail.RedactionCount = 0
			return Finding{Guard: g.name, Matched: true, Action: ActionBlock, Reason: reason, Details: []FindingDetail{detail}, Body: c.Body}
		}
		// Redact: rewrite this pattern, then keep scanning the rest.
		body = re.ReplaceAll(body, []byte("[REDACTED]"))
		detail.RedactionCount = len(matches)
		details = append(details, detail)
	}
	if !matched {
		return Finding{Guard: g.name, Matched: false, Body: c.Body}
	}
	return Finding{Guard: g.name, Matched: true, Action: g.action, Reason: reason, Details: details, Body: body}
}

func inferRegexDataClass(pattern string) DataClass {
	p := strings.ToLower(pattern)
	switch {
	case strings.Contains(p, "sk-") ||
		strings.Contains(p, "akia") ||
		strings.Contains(p, "ghp_") ||
		strings.Contains(p, "token") ||
		strings.Contains(p, "api") && strings.Contains(p, "key") ||
		strings.Contains(p, "secret"):
		return DataClassSecret
	case strings.Contains(p, "system") && strings.Contains(p, "prompt"):
		return DataClassSystemSecret
	case strings.Contains(p, "email") ||
		strings.Contains(p, "@") ||
		strings.Contains(p, "ssn") ||
		strings.Contains(p, "phone") ||
		strings.Contains(p, "credit"):
		return DataClassPII
	default:
		return DataClassUnknown
	}
}

func classLabel(class DataClass) string {
	if class == "" || class == DataClassUnknown {
		return ""
	}
	return string(class)
}
