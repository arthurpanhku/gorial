# gorial Product Requirements Document

Last updated: 2026-06-16

## 1. Summary

`gorial` should become a tiny, self-hosted policy firewall for LLM traffic. It sits between applications and OpenAI-compatible model endpoints, understands LLM request and response structure, evaluates declarative policies, blocks or rewrites unsafe traffic, and leaves an audit trail that teams can replay and test.

The product wedge is not "more scanners than everyone else." The wedge is:

- A single static Go binary that is easy to run beside any LLM app.
- LLM-aware policy semantics instead of raw body filters only.
- Auditable, replayable decisions that make policy maintenance practical.
- A local-first operating model that fits security-conscious teams.

## 2. Why This Exists

LLM applications introduce a trust-boundary problem that normal HTTP proxies do not understand. The model consumes natural language, retrieved documents, tool outputs, system instructions, user prompts, and sometimes executable tool calls as one blended context. Because modern LLMs do not provide a hard internal separation between instruction and data, security must be enforced outside the model.

The market already has large AI gateways, scanner libraries, SaaS guardrail APIs, and red-team tools. `gorial` should occupy the practical middle:

- Smaller than a full AI gateway.
- More deployable than Python framework guardrails.
- More policy-oriented than detector libraries.
- More operational than one-off red-team scans.

## 3. Industry Reference Points

### Risk Frameworks

- [OWASP Top 10 for LLM Applications 2025](https://genai.owasp.org/llm-top-10/) prioritizes risks such as prompt injection, sensitive information disclosure, improper output handling, excessive agency, system prompt leakage, vector weaknesses, and unbounded consumption.
- [NCSC: Prompt injection is not SQL injection](https://www.ncsc.gov.uk/blog-post/prompt-injection-is-not-sql-injection) argues that LLMs lack a native security boundary between instructions and data, so defenses should reduce impact through architecture, least privilege, monitoring, and layered controls.

### Open Source and Product Patterns

- [LiteLLM](https://docs.litellm.ai/docs/simple_proxy) shows demand for OpenAI-compatible gateways that centralize model access, routing, budgets, logging, and guardrails.
- [LiteLLM Guardrails](https://docs.litellm.ai/docs/proxy/guardrails/quick_start) shows the config-driven gateway pattern, but its center of gravity is broad AI gateway operations.
- [NVIDIA NeMo Guardrails](https://docs.nvidia.com/nemo/guardrails/home) emphasizes programmable rails across input, retrieval, dialog, execution, and output. Its strength is application-level conversational control.
- [Protect AI LLM Guard](https://github.com/protectai/llm-guard) emphasizes scanner composition for sanitizing, detecting, and redacting prompts and responses.
- [Guardrails AI](https://github.com/guardrails-ai/guardrails) emphasizes validators, structured output checks, and corrective behavior around model calls.
- [promptfoo red teaming](https://www.promptfoo.dev/docs/red-team/) and [garak](https://github.com/NVIDIA/garak) show that AI safety must be tested continuously, not assumed.
- [Microsoft PyRIT](https://github.com/microsoft/PyRIT) shows the need for extensible AI red-team workflows that security engineers can automate.

### Papers and Research Signals

- [Greshake et al., 2023: Indirect Prompt Injection](https://arxiv.org/abs/2302.12173) demonstrates that malicious instructions can arrive through retrieved or external data, causing data theft, tool misuse, and application manipulation.
- [NeMo Guardrails paper](https://arxiv.org/pdf/2310.10501) frames programmable rails as external controls around LLM applications.
- [Evaluating the Efficacy of LLM Safety Solutions: The Palit Benchmark](https://arxiv.org/html/2505.13028v2) highlights that many tools claim prompt injection, PII, and jailbreak coverage, while documentation quality, maintenance, DoS coverage, and canary-word detection remain uneven.
- [CAPTURE benchmark](https://arxiv.org/html/2505.12368v1) emphasizes context-aware prompt-injection evaluation and the risk of over-defense.

## 4. Product Thesis

### First Principles

1. The LLM cannot be the security boundary.
2. Prompt injection cannot be fully solved by keyword filtering.
3. A useful gateway must understand the protocol and the application shape.
4. Security controls must be observable and testable, or they decay.
5. Teams adopt infrastructure that is boring to deploy and easy to reason about.

### Positioning

`gorial` is the local-first LLM policy firewall for teams that want production guardrails without adopting a heavyweight AI gateway or sending prompts to a third-party guardrail SaaS.

### Tagline

Tiny self-hosted policy firewall for LLM traffic.

## 5. Target Users

### Primary: Platform Engineer

Needs to give product teams one safe base URL for LLM traffic without rewriting every application.

Jobs:

- Deploy a gateway in Docker, Kubernetes, or as a sidecar.
- Apply team-wide defaults.
- Route traffic to existing OpenAI-compatible providers.
- Export logs to existing observability pipelines.

### Primary: Security Engineer

Needs to understand, tune, and prove that LLM traffic controls are active.

Jobs:

- Block common prompt injection and jailbreak attempts.
- Detect secret, PII, and system prompt leakage.
- Review why a decision happened.
- Run regression tests against policy changes.

### Secondary: AI Application Developer

Needs fast local feedback while building RAG, chat, and agent workflows.

Jobs:

- See which message or tool argument triggered a guard.
- Avoid false positives in benign workflows.
- Add custom regex or detector plugins.
- Replay sample traffic in CI.

## 6. Non-Goals

For the next two releases, `gorial` should not become:

- A multi-provider routing platform with budgets and virtual keys.
- A hosted dashboard SaaS.
- A general WAF.
- A complete model safety classifier vendor.
- A prompt engineering framework.
- A storage-heavy analytics product.

These may be integrations later, but they are distractions from the wedge.

## 7. Current State

The repository already provides:

- Reverse proxy using `net/http/httputil`.
- YAML config with `listen`, `target`, `log`, and `guards`.
- Regex and built-in PII guards.
- Inbound and outbound directions.
- Concurrent guard inspection with deterministic redaction merge.
- Structured JSON or text audit logging.
- Basic tests for proxy behavior and guard behavior.

Key limitations:

- Raw body inspection only, no schema-aware OpenAI parsing.
- Streaming responses pass through without outbound redaction.
- Findings do not include policy ids, locations, spans, severity, or redaction counts.
- No replay command, policy test harness, or CI-oriented workflow.
- No tool-call policy.
- No size limits, timeout controls, or DoS-oriented guardrails.
- No plugin interface beyond built-in Go guards.

## 8. Product Requirements

### P0: Productized Baseline

Goal: Make the current proxy safe and clear enough to run in real development environments.

Requirements:

- Keep single static binary and YAML-first configuration.
- Add config versioning: `version: "v1"`.
- Add startup config validation with actionable errors.
- Add request body max size and response body max size.
- Add guard timeout per request.
- Add stable policy ids.
- Add audit event ids and request fingerprints.
- Add a `gorial check -config config.yaml` command.
- Add a `gorial sample-config` command.

Acceptance criteria:

- Invalid policy fails before serving traffic.
- Audit logs can be joined by request id across inbound and outbound.
- Large payload behavior is explicit: block, pass, or bypass with audit reason.
- Existing config remains backward compatible for one release.

### P1: Schema-Aware LLM Policy Runtime

Goal: Move from generic body filter to LLM-aware controls.

Requirements:

- Parse OpenAI-compatible chat completion request bodies.
- Extract message fields: `role`, `content`, `name`, `tool_calls`, and `tool_call_id`.
- Extract tool definitions and tool call arguments when present.
- Extract response choices and assistant content.
- Add policy targets:
  - `request.raw`
  - `request.messages[*].content`
  - `request.messages[?role=="system"].content`
  - `request.messages[?role=="user"].content`
  - `request.tools[*]`
  - `response.choices[*].message.content`
  - `response.choices[*].message.tool_calls[*].function.arguments`
- Preserve raw-body fallback for unknown endpoints.
- Add finding locations using JSON Pointer where possible.

Acceptance criteria:

- A policy can block user messages without inspecting system messages.
- A policy can detect leaked system prompts in outbound content.
- A policy can redact secrets inside tool arguments.
- Audit logs identify exact logical field locations.

### P2: Replay and Policy Testing

Goal: Make policy changes safe to review.

Requirements:

- Add `gorial replay` command that reads audit payload samples or user-supplied fixtures.
- Add fixture format with expected decision.
- Add report output in text and JSON.
- Add baseline diff mode: compare old config vs new config on the same corpus.
- Add CI-friendly exit codes.

Acceptance criteria:

- Developers can run `gorial replay -config config.yaml -fixtures testdata/policies`.
- CI fails when a fixture expected to block is allowed.
- A config diff can show newly blocked, newly allowed, newly redacted, and unchanged cases.

### P3: Tool-Call and Agent Boundary Controls

Goal: Address excessive agency and unsafe tool use.

Requirements:

- Add tool-call allow/deny policy by tool name.
- Add argument-level regex and JSON schema checks.
- Add host/domain allowlist checks for browser, HTTP, webhook, or fetch-like tools.
- Add action mode: `block`, `redact`, `require_approval`, `audit_only`.
- Add policy examples for agent use cases.

Acceptance criteria:

- A policy can block tool calls that target unapproved domains.
- A policy can block shell-like or HTTP-like tool arguments containing secrets.
- A policy can run in `audit_only` to collect impact before enforcement.

### P4: Streaming-Safe Guardrails

Goal: Support common production LLM behavior without silently losing outbound control.

Requirements:

- Inspect Server-Sent Events streams incrementally.
- Support modes:
  - `streaming: pass_through`
  - `streaming: buffer`
  - `streaming: incremental_redact`
  - `streaming: block_on_match`
- Document trade-offs.

Acceptance criteria:

- Streaming pass-through always emits an audit event saying outbound inspection was bypassed.
- Buffer mode can redact complete streamed responses.
- Incremental mode supports regex and PII redaction on rolling windows.

## 9. Differentiators

### Differentiator 1: LLM-Aware But Deployment-Boring

Most guardrail frameworks live in application code or Python stacks. `gorial` should keep the boring deployment story of `nginx` or `caddy` while understanding LLM semantics.

### Differentiator 2: Policy Tests as First-Class Product

The best feature is not a scanner; it is the ability to prove that a policy change helps. Replay, fixtures, and diff reports should be first-class.

### Differentiator 3: Local-First Auditability

Security-conscious teams care where prompts go. `gorial` should not require sending prompts to a vendor for baseline controls. External classifiers can be plugins.

### Differentiator 4: Tool Boundary Control

Prompt injection matters most when the model can act. Tool-call policy lets `gorial` protect the dangerous edge where LLM output becomes system action.

## 10. User Stories

- As a platform engineer, I can place `gorial` in front of an OpenAI-compatible endpoint and keep existing SDK clients unchanged.
- As a security engineer, I can define a policy that blocks prompt injection attempts in user messages while allowing system prompts to contain security instructions.
- As a developer, I can see the JSON Pointer location that triggered a finding.
- As a reviewer, I can run a replay suite before merging a policy change.
- As an agent developer, I can deny outbound tool calls to unknown domains.
- As an operator, I can prove that a streaming response bypassed outbound inspection because of configured mode, not accidental omission.

## 11. Metrics

### Adoption Metrics

- Time from install to first proxied request under 5 minutes.
- New user can run `gorial check` and fix config errors without reading code.
- Docker image starts with sample config in under 30 seconds.

### Runtime Metrics

- P95 guard overhead under 10 ms for regex and PII guards on bodies under 64 KB.
- P95 proxy overhead under 25 ms excluding upstream latency.
- Zero data races under `go test -race ./...`.

### Policy Quality Metrics

- Fixture pass rate.
- Number of audit-only findings promoted to enforcement.
- False-positive rate from replay corpus.
- Percent of findings with structured locations.

### Security Metrics

- Prompt injection fixture block rate.
- Secret leakage redaction rate.
- Tool-call policy violation block rate.
- Unknown or bypassed inspection rate.

## 12. Packaging

Must support:

- `go install github.com/arthurpanhku/gorial/cmd/gorial@latest`
- Static binary releases for Linux and macOS.
- Docker image.
- Kubernetes sidecar example.
- Helm chart later, not P0.

## 13. Documentation Requirements

P0 docs:

- Quickstart.
- Config reference.
- Policy examples.
- Audit log reference.
- Known limitations.

P1 docs:

- OpenAI-compatible schema support matrix.
- JSON Pointer target reference.
- Migration guide from raw regex guards to structured policies.

P2 docs:

- Replay command guide.
- Fixture format.
- CI examples for GitHub Actions.

## 14. Risks

- False positives can block legitimate traffic and cause teams to disable the gateway.
- Redaction can corrupt JSON if applied carelessly to structured fields.
- Streaming support can introduce latency or incomplete detection.
- Plugin systems can compromise the static-binary simplicity.
- External classifiers can leak data if enabled without clear policy.
- Overclaiming security guarantees will damage trust.

## 15. Product Principles

- Be explicit about bypasses.
- Prefer deterministic behavior.
- Make policy changes testable.
- Keep local controls local by default.
- Make every blocking decision explainable.
- Treat tool calls as the high-risk boundary.
- Underpromise detection accuracy, overdeliver operational clarity.

## 16. Release Plan

### v0.2: Productized Baseline

- Config versioning.
- Policy ids.
- Audit request ids.
- Body size limits.
- Guard timeout.
- `check` and `sample-config`.

### v0.3: Schema-Aware Policies

- OpenAI chat parser.
- Structured targets.
- Finding locations.
- Structured redaction for JSON fields.

### v0.4: Replay

- Fixture format.
- Replay command.
- Config diff report.
- CI examples.

### v0.5: Tool Boundary Controls

- Tool-call policies.
- Argument checks.
- Domain allowlists.
- `audit_only` and `require_approval` modes.

### v0.6: Streaming

- Buffered streaming mode.
- Incremental regex/PII redaction.
- Explicit streaming audit outcomes.

## 17. Open Questions

- Should policy syntax remain guard-oriented, or move to a richer `policies:` top-level while keeping `guards:` as legacy?
- Should structured policies support a CEL-like expression language, or only YAML fields?
- Should replay store raw payload samples by default, or require explicit opt-in because of privacy risk?
- Should external classifier plugins run as subprocesses, HTTP services, or Go plugins?
- Should `require_approval` be in open-source core, or wait until there is an approval API/dashboard?

