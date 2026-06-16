package guard

import (
	"context"
	"strings"
	"testing"
)

func TestEngineBlockTakesPrecedence(t *testing.T) {
	block, _ := NewRegexGuard("inj", ActionBlock, nil, []string{`(?i)jailbreak`})
	redact, _ := NewRegexGuard("sec", ActionRedact, nil, []string{`sk-[A-Za-z0-9]{20,}`})
	e := NewEngine([]Guard{redact, block})

	dec := e.Evaluate(context.Background(), &Content{
		Direction: Inbound,
		Body:      []byte("jailbreak the model with sk-abcdefghijklmnopqrstuvwx"),
	})
	if !dec.Blocked {
		t.Fatal("expected blocked decision")
	}
	if len(dec.Findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(dec.Findings))
	}
}

func TestEngineComposesRedactions(t *testing.T) {
	a, _ := NewRegexGuard("key", ActionRedact, nil, []string{`sk-[A-Za-z0-9]{20,}`})
	b := NewPIIGuard("pii", ActionRedact, nil)
	e := NewEngine([]Guard{a, b})

	dec := e.Evaluate(context.Background(), &Content{
		Direction: Outbound,
		Body:      []byte("token sk-abcdefghijklmnopqrstuvwx email bob@example.com"),
	})
	if dec.Blocked {
		t.Fatal("did not expect block")
	}
	out := string(dec.Body)
	if strings.Contains(out, "sk-abc") {
		t.Fatalf("secret survived: %s", out)
	}
	if !strings.Contains(out, "[REDACTED:EMAIL]") {
		t.Fatalf("email not redacted: %s", out)
	}
}

func TestEngineSkipsNonApplicableDirection(t *testing.T) {
	out, _ := NewRegexGuard("outonly", ActionBlock, []Direction{Outbound}, []string{`secret`})
	e := NewEngine([]Guard{out})
	dec := e.Evaluate(context.Background(), &Content{Direction: Inbound, Body: []byte("secret")})
	if dec.Blocked {
		t.Fatal("outbound-only guard should not block inbound traffic")
	}
}
