# gorial PoC

This PoC gives people a visual way to see `gorial` block inbound prompt injection attempts and redact outbound secrets or PII.

The default setup uses a local mock OpenAI-compatible LLM, so no API key is required.

```text
browser -> PoC app (:3000) -> gorial (:8080) -> mock LLM (:9090)
```

## Run with the mock LLM

Use three terminals from the repository root.

Terminal 1:

```bash
go run ./examples/poc/mock-llm
```

Terminal 2:

```bash
go run ./cmd/gorial serve -config examples/poc/gorial.config.yaml
```

Terminal 3:

```bash
go run ./examples/poc/app
```

Open:

```text
http://localhost:3000
```

Try the sample buttons:

- `Clean request`: passes through to the mock LLM.
- `Inbound block`: gorial returns `403` before the mock LLM sees the request.
- `Outbound PII redaction`: the mock LLM returns email, SSN, and key-like text; gorial redacts it.
- `Outbound secret redaction`: gorial redacts an OpenAI-style key pattern.

Watch the gorial terminal for JSON audit events. Each response includes `X-Gorial-Request-ID`, and the UI displays that id.

![gorial PoC showing outbound redaction](screenshot.jpg)

## Run with a real OpenAI-compatible LLM

Copy and edit the real config:

```bash
cp examples/poc/real-llm.config.yaml examples/poc/local-real.config.yaml
```

Set `target` in `examples/poc/local-real.config.yaml` to your provider base URL, then run:

```bash
go run ./cmd/gorial serve -config examples/poc/local-real.config.yaml
```

In another terminal, run the app with your model and API key:

```bash
LLM_API_KEY="$OPENAI_API_KEY" \
LLM_MODEL="gpt-4o-mini" \
GORIAL_BASE_URL="http://localhost:8080" \
go run ./examples/poc/app
```

The app sends OpenAI-compatible `/v1/chat/completions` requests to gorial. gorial forwards the same request to your configured target.

## Ports

- PoC app: `:3000` via `POC_APP_ADDR`
- gorial: `:8080` via config
- mock LLM: `:9090` via `MOCK_LLM_ADDR`
