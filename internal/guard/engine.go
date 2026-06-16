package guard

import (
	"context"
	"sync"
)

// Decision is the aggregate outcome after running every applicable guard.
type Decision struct {
	Blocked  bool
	Body     []byte
	Findings []Finding
}

// Engine runs a set of guards over content and aggregates their findings.
type Engine struct {
	guards []Guard
}

// NewEngine returns an Engine over the given guards. Guard order is preserved
// and used to make redaction deterministic.
func NewEngine(guards []Guard) *Engine {
	return &Engine{guards: guards}
}

// Evaluate runs every guard applicable to c.Direction. Detection happens
// concurrently — one goroutine per guard — because guards are independent and
// inspection (regex matching) dominates the cost. If no guard blocks, the
// redacting guards are then re-applied sequentially in declaration order so
// the merged result is reproducible regardless of goroutine scheduling.
func (e *Engine) Evaluate(ctx context.Context, c *Content) Decision {
	applicable := make([]Guard, 0, len(e.guards))
	for _, g := range e.guards {
		if g.Applies(c.Direction) {
			applicable = append(applicable, g)
		}
	}

	findings := make([]Finding, len(applicable))
	var wg sync.WaitGroup
	for i := range applicable {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			findings[i] = applicable[i].Inspect(ctx, &Content{Direction: c.Direction, Body: c.Body})
		}(i)
	}
	wg.Wait()

	dec := Decision{Body: c.Body}
	body := c.Body
	for i, f := range findings {
		if !f.Matched {
			continue
		}
		dec.Findings = append(dec.Findings, f)
		if f.Action == ActionBlock {
			dec.Blocked = true
			continue
		}
		// Re-run the redacting guard against the evolving body so multiple
		// redactions compose correctly.
		rf := applicable[i].Inspect(ctx, &Content{Direction: c.Direction, Body: body})
		body = rf.Body
	}
	if !dec.Blocked {
		dec.Body = body
	}
	return dec
}
