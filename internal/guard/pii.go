package guard

import (
	"context"
	"regexp"
)

type piiPattern struct {
	label    string
	class    DataClass
	severity Severity
	re       *regexp.Regexp
	redactor string
}

// defaultPIIPatterns covers common PII and credential formats. They favour low
// false-negative rates over precision; tune for your own traffic in practice.
var defaultPIIPatterns = []piiPattern{
	{"EMAIL", DataClassPII, SeverityMedium, regexp.MustCompile(`[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`), "[REDACTED:EMAIL]"},
	{"CREDIT_CARD", DataClassPII, SeverityHigh, regexp.MustCompile(`\b(?:\d[ -]?){13,16}\b`), "[REDACTED:CREDIT_CARD]"},
	{"SSN", DataClassPII, SeverityHigh, regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`), "[REDACTED:SSN]"},
	{"AWS_ACCESS_KEY", DataClassSecret, SeverityCritical, regexp.MustCompile(`AKIA[0-9A-Z]{16}`), "[REDACTED:AWS_ACCESS_KEY]"},
	{"OPENAI_KEY", DataClassSecret, SeverityCritical, regexp.MustCompile(`sk-[A-Za-z0-9]{20,}`), "[REDACTED:OPENAI_KEY]"},
	{"GITHUB_TOKEN", DataClassSecret, SeverityCritical, regexp.MustCompile(`ghp_[A-Za-z0-9]{36}`), "[REDACTED:GITHUB_TOKEN]"},
	{"JWT", DataClassSecret, SeverityHigh, regexp.MustCompile(`eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+`), "[REDACTED:JWT]"},
	{"PHONE", DataClassPII, SeverityMedium, regexp.MustCompile(`\b(?:\+?1[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?)\d{3}[-.\s]?\d{4}\b`), "[REDACTED:PHONE]"},
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
	details := make([]FindingDetail, 0, len(g.patterns))
	for _, p := range g.patterns {
		matches := p.re.FindAllIndex(body, -1)
		if len(matches) == 0 {
			continue
		}
		matched = true
		reason = "PII:" + p.label
		if p.class == DataClassSecret {
			reason = "SECRET:" + p.label
		}
		detail := FindingDetail{
			PolicyID:   g.name,
			Guard:      g.name,
			Detector:   "pii",
			DataClass:  p.class,
			Label:      p.label,
			Action:     g.action,
			Direction:  c.Direction,
			Reason:     reason,
			Severity:   p.severity,
			MatchCount: len(matches),
		}
		if g.action == ActionBlock {
			detail.Severity = severityFor(g.action, p.class)
			return Finding{Guard: g.name, Matched: true, Action: ActionBlock, Reason: reason, Details: []FindingDetail{detail}, Body: c.Body}
		}
		body = p.re.ReplaceAll(body, []byte(p.redactor))
		detail.RedactionCount = len(matches)
		details = append(details, detail)
	}
	if !matched {
		return Finding{Guard: g.name, Matched: false, Body: c.Body}
	}
	return Finding{Guard: g.name, Matched: true, Action: g.action, Reason: reason, Details: details, Body: body}
}
