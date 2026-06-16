package guard

import (
	"context"
	"regexp"
)

type piiPattern struct {
	label string
	re    *regexp.Regexp
}

// defaultPIIPatterns covers common PII and credential formats. They favour low
// false-negative rates over precision; tune for your own traffic in practice.
var defaultPIIPatterns = []piiPattern{
	{"EMAIL", regexp.MustCompile(`[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`)},
	{"CREDIT_CARD", regexp.MustCompile(`\b(?:\d[ -]?){13,16}\b`)},
	{"SSN", regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`)},
	{"AWS_ACCESS_KEY", regexp.MustCompile(`AKIA[0-9A-Z]{16}`)},
	{"OPENAI_KEY", regexp.MustCompile(`sk-[A-Za-z0-9]{20,}`)},
}

// PIIGuard detects and redacts common personally-identifiable information and
// credential formats. Each match is replaced with a labelled marker, e.g.
// "[REDACTED:EMAIL]".
type PIIGuard struct {
	name     string
	action   Action
	dirs     map[Direction]bool
	patterns []piiPattern
}

// NewPIIGuard returns a PIIGuard using the built-in pattern set.
func NewPIIGuard(name string, action Action, dirs []Direction) *PIIGuard {
	return &PIIGuard{
		name:     name,
		action:   action,
		dirs:     directionSet(dirs),
		patterns: defaultPIIPatterns,
	}
}

func (g *PIIGuard) Name() string { return g.name }

func (g *PIIGuard) Applies(d Direction) bool { return g.dirs[d] }

func (g *PIIGuard) Inspect(_ context.Context, c *Content) Finding {
	body := c.Body
	matched := false
	var reason string
	for _, p := range g.patterns {
		if !p.re.Match(body) {
			continue
		}
		matched = true
		reason = "PII:" + p.label
		if g.action == ActionBlock {
			return Finding{Guard: g.name, Matched: true, Action: ActionBlock, Reason: reason, Body: c.Body}
		}
		body = p.re.ReplaceAll(body, []byte("[REDACTED:"+p.label+"]"))
	}
	if !matched {
		return Finding{Guard: g.name, Matched: false, Body: c.Body}
	}
	return Finding{Guard: g.name, Matched: true, Action: g.action, Reason: reason, Body: body}
}
