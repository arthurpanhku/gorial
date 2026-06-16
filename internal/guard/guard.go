// Package guard defines the guardrail abstraction and the concurrent engine
// that evaluates content against a set of guards.
package guard

import "context"

// Direction indicates whether content is moving toward the LLM (Inbound)
// or back toward the client (Outbound).
type Direction string

const (
	Inbound  Direction = "inbound"
	Outbound Direction = "outbound"
)

// Action is the policy decision attached to a guard.
type Action string

const (
	ActionBlock  Action = "block"
	ActionRedact Action = "redact"
)

// Content is the payload under inspection.
type Content struct {
	Direction Direction
	Body      []byte
}

// Finding is the result of a single guard inspecting content.
type Finding struct {
	Guard   string
	Matched bool
	Action  Action
	Reason  string
	// Body is the (possibly redacted) body produced by this guard alone.
	// The engine re-runs redacting guards sequentially to merge them, so
	// callers should consult Decision.Body for the final result.
	Body []byte
}

// Guard inspects content and reports a Finding. Implementations must be safe
// for concurrent use: the engine runs guards in parallel goroutines.
type Guard interface {
	Name() string
	Applies(Direction) bool
	Inspect(ctx context.Context, c *Content) Finding
}

// directionSet turns a direction list into a lookup. An empty list means the
// guard applies in both directions.
func directionSet(dirs []Direction) map[Direction]bool {
	m := make(map[Direction]bool, 2)
	if len(dirs) == 0 {
		m[Inbound] = true
		m[Outbound] = true
		return m
	}
	for _, d := range dirs {
		m[d] = true
	}
	return m
}
