package guard

import (
	"context"
	"regexp"
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
	for _, re := range g.patterns {
		if !re.Match(body) {
			continue
		}
		matched = true
		reason = re.String()
		if g.action == ActionBlock {
			return Finding{Guard: g.name, Matched: true, Action: ActionBlock, Reason: reason, Body: c.Body}
		}
		// Redact: rewrite this pattern, then keep scanning the rest.
		body = re.ReplaceAll(body, []byte("[REDACTED]"))
	}
	if !matched {
		return Finding{Guard: g.name, Matched: false, Body: c.Body}
	}
	return Finding{Guard: g.name, Matched: true, Action: g.action, Reason: reason, Body: body}
}
