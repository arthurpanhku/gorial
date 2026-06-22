# gorial Development Plan

Last updated: 2026-06-22

## 1. Product Focus

`gorial` should focus on one sharp use case:

> A local-first LLM policy firewall that prevents high-risk data and user PII from leaking through agentic workflows.

The primary threat model is:

1. Untrusted content enters through a web frontend.
2. The application sends that content to an LLM or agent runtime.
3. The agent may call tools, fetch URLs, send messages, write data, or expose internal context.
4. `gorial` must inspect, block, redact, require approval, or audit these flows before sensitive data leaks or unsafe actions execute.

This plan optimizes for data protection, agent execution boundaries, and benchmark-backed evidence.

## 2. First Principles

- The LLM is not the security boundary.
- Untrusted text must never be allowed to silently become privileged instruction.
- Tool calls are the highest-risk boundary because they can create side effects.
- Data protection requires field-level context, not only raw body scanning.
- Guardrail quality must be measured with repeatable fixtures and benchmarks.
- Local controls should remain local by default; external classifiers must be explicit opt-in.
- Every block, redaction, bypass, or approval decision must be explainable and replayable.

## 3. Risk Model

### 3.1 Protected Data Classes

P0 data classes:

- `PII`: email, phone number, address, government id, payment card, user identifier.
- `SECRET`: API key, OAuth token, cookie, JWT, cloud credential, webhook secret.
- `SYSTEM_SECRET`: system prompt, developer prompt, internal policy, tool credential, hidden routing metadata.
- `BUSINESS_SENSITIVE`: customer records, contracts, financial data, support tickets, internal documents.

### 3.2 Trust Labels

P0 trust labels:

- `trusted_instruction`: system and developer-controlled instructions.
- `user_untrusted`: direct user input from the web frontend.
- `external_untrusted`: web pages, uploaded files, OCR, retrieved documents, email, tool results.
- `model_generated`: assistant content and tool call proposals.
- `tool_output`: returned tool results.

Policies should be able to match on both data class and trust label.

### 3.3 Control Actions

Supported action roadmap:

- `allow`: no enforcement, useful for explicit future overrides.
- `audit_only`: log findings without changing traffic.
- `redact`: rewrite matched values.
- `block`: stop the request or response.
- `require_approval`: pause high-risk tool calls for external approval.
- `bypass`: explicit non-inspection outcome with a reason.

## 4. Development Roadmap

### P0: Data Classification and Structured Findings

Goal: turn the current raw scanner into an explainable data protection layer.

Deliverables:

- Add stable internal data classes for PII, secrets, system secrets, and business-sensitive data.
- Expand built-in detectors beyond the current PII patterns.
- Return structured findings with:
  - policy id
  - detector type
  - data class
  - action
  - direction
  - JSON Pointer location when available
  - match count
  - redaction count
  - severity
- Add audit fields for structured `finding_details` while keeping the current `findings` string list for compatibility.
- Add config examples for high-risk data protection.

Likely files:

- `internal/guard`
- `internal/audit`
- `internal/config`
- `docs/SPEC.md`

Acceptance criteria:

- A leaked API key is classified as `SECRET`, not generic regex output.
- An email in assistant output is classified as `PII`.
- Audit logs identify the policy, data class, action, and location.
- Redaction count is visible in JSON audit logs.

### P1: Schema-Aware LLM Policy Runtime

Goal: make `gorial` understand OpenAI-compatible request and response structure.

Deliverables:

- Add `internal/llm` document parsing for `/v1/chat/completions`.
- Extract:
  - request messages
  - message roles
  - system/developer/user/assistant content
  - tool definitions
  - assistant tool calls
  - tool call arguments
  - response choices
- Add target resolution for:
  - `request.raw`
  - `response.raw`
  - `request.messages[*].content`
  - `request.messages[?role=="system"].content`
  - `request.messages[?role=="user"].content`
  - `request.tools[*]`
  - `response.choices[*].message.content`
  - `response.choices[*].message.tool_calls[*].function.arguments`
- Add JSON Pointer locations for structured targets.
- Preserve raw-body fallback for unknown endpoints and malformed JSON.
- Introduce `policies:` as the preferred v1 config model.
- Convert legacy `guards:` into internal policies.

Likely files:

- `internal/llm/document.go`
- `internal/llm/openai_chat.go`
- `internal/llm/targets.go`
- `internal/policy/policy.go`
- `internal/policy/engine.go`
- `internal/schema/json_pointer.go`
- `internal/proxy/proxy.go`

Acceptance criteria:

- A policy can inspect only user messages without scanning system messages.
- A policy can redact secrets inside tool call arguments.
- A policy can detect system prompt leakage in assistant output.
- Structured redaction preserves valid JSON.

### P2: Agent Tool Boundary Controls

Goal: prevent untrusted web input from causing unsafe agent execution.

Deliverables:

- Add tool-call policy targets.
- Add tool name allowlist and denylist.
- Add URL/domain detector for browser, HTTP, fetch, webhook, and callback-like tools.
- Add argument-level regex checks.
- Add argument-level JSON schema checks.
- Add recipient checks for email, messaging, ticketing, and webhook tools.
- Add `audit_only` mode.
- Add `require_approval` as a policy action, even if the first implementation returns a deterministic approval-required response instead of integrating a dashboard.

Example policies:

- Block tool calls to non-allowlisted domains.
- Block outbound tool arguments containing PII or secrets.
- Require approval for external email, payment, deletion, shell, or write operations.
- Audit model-generated URLs before enforcement.

Likely files:

- `internal/policy`
- `internal/llm/targets.go`
- `internal/guard`
- `internal/proxy`
- `docs/SPEC.md`

Acceptance criteria:

- A malicious prompt cannot cause a tool call to an unapproved domain.
- Tool call arguments containing `SECRET` are blocked or redacted according to policy.
- High-risk tool calls can return `require_approval`.
- Benign tool calls to approved domains continue to pass.

### P3: Replay, Fixtures, and Benchmark Harness

Goal: make guardrail quality measurable in CI and against international benchmarks.

Deliverables:

- Add `gorial replay`.
- Add fixture format with expected decision, policies, data classes, and tool-call outcome.
- Add JSON and text reports.
- Add config diff mode.
- Add CI-friendly exit codes.
- Add benchmark adapters or fixture importers for:
  - OWASP LLM Top 10 risk categories
  - AgentDojo-style agent prompt-injection cases
  - garak-style vulnerability probes
  - custom PII and secret leakage corpora
- Add baseline metrics:
  - PII recall and precision
  - secret leakage recall
  - prompt-injection attack success rate
  - unsafe tool-call block rate
  - benign task pass rate
  - false positive rate
  - p95 latency
  - bypass rate

Likely files:

- `internal/replay/fixture.go`
- `internal/replay/runner.go`
- `internal/replay/report.go`
- `cmd/gorial/main.go`
- `testdata/replay`
- `benchmarks`

Acceptance criteria:

- CI fails when a fixture expected to block is allowed.
- CI fails when a fixture expected to pass is blocked.
- Reports show newly blocked, newly allowed, newly redacted, and unchanged cases.
- Benchmark results can be compared across policy changes.

### P4: Streaming-Safe Data Protection

Goal: remove the long-term blind spot in streaming responses.

Deliverables:

- Keep `pass_through` with explicit audit bypass.
- Add `buffer` mode for full-stream inspection before returning content.
- Add `incremental_redact` for rolling-window regex and PII redaction.
- Add `block_on_match` where operationally acceptable.
- Track streaming bypass and inspection rates in audit logs.

Acceptance criteria:

- Streaming pass-through always emits a bypass reason.
- Buffer mode can redact PII from streamed assistant responses.
- Incremental mode handles matches across chunk boundaries within documented limits.

### P5: External Detector Plugin Interfaces

Goal: support stronger semantic detection without compromising local-first defaults.

Deliverables:

- Add `external_process` detector.
- Add `external_http` detector.
- Add timeout, payload, and privacy controls.
- Mark all external detectors as explicit opt-in.
- Add sample integrations for a local classifier and an internal HTTP classifier.

Acceptance criteria:

- External detectors cannot run without explicit config.
- Timeouts and failures produce deterministic policy outcomes.
- Audit logs show when a detector is external.

## 5. Benchmark Strategy

No single benchmark covers the full `gorial` threat model. Use a matrix:

- OWASP LLM Top 10 2025 for risk taxonomy.
- AgentDojo for agentic prompt injection and tool-use robustness.
- garak for general LLM vulnerability probing.
- Custom PII and secret leakage fixtures for application-specific data protection.
- Optional promptfoo integration for app-level red-team workflows.

Initial benchmark categories:

- Direct prompt injection from web user input.
- Indirect prompt injection through retrieved or tool-provided content.
- PII leakage in assistant output.
- Secret leakage in tool arguments.
- System prompt leakage.
- Tool call to unapproved domain.
- Tool call with unsafe recipient.
- Benign task that must not be blocked.

## 6. Suggested Release Plan

### v0.3: Data-Aware Audit Baseline

- Structured findings.
- Data classes.
- Expanded secret and PII detectors.
- Audit compatibility layer.
- High-risk data policy examples.

### v0.4: Schema-Aware Policies

- OpenAI chat parser.
- Structured targets.
- JSON Pointer locations.
- Legacy guard conversion.
- Structured JSON redaction.

### v0.5: Agent Tool Boundary

- Tool-call targets.
- Domain allowlists.
- Tool name allowlists and denylists.
- Argument checks.
- `audit_only`.
- Initial `require_approval`.

### v0.6: Replay and Benchmarks

- Replay command.
- Fixture format.
- JSON/text reports.
- Benchmark fixture importers.
- CI examples.

### v0.7: Streaming Protection

- Streaming buffer mode.
- Incremental redaction.
- Streaming metrics and bypass reporting.

### v0.8: External Detector Plugins

- External process detector.
- External HTTP detector.
- Local classifier example.
- Privacy and timeout safeguards.

## 7. Near-Term Implementation Checklist

1. Add structured finding types and audit fields.
2. Add data class enum and detector labels.
3. Add `internal/policy` with legacy guard conversion.
4. Add `internal/llm` OpenAI chat parser.
5. Add JSON Pointer target resolution.
6. Add structured redaction tests.
7. Add tool-call argument target support.
8. Add domain allowlist detector.
9. Add replay fixture loader and runner.
10. Add initial fixtures for PII, secret, prompt injection, system prompt leak, and unsafe tool call.

## 8. Open Decisions

- Should `policies:` replace `guards:` in v1 while keeping `guards:` as legacy compatibility?
- Should `require_approval` return a standardized HTTP response first, or wait for an approval callback API?
- Should benchmark corpora live in this repo, or should importers fetch external suites on demand?
- Should `BUSINESS_SENSITIVE` rely on regex labels first, or require external classifiers from the start?
- Should payload capture for replay be opt-in per policy, per route, or globally?

