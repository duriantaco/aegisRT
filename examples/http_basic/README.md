# HTTP Target Example

Test any HTTP endpoint that speaks the OpenAI chat-completions protocol.

## Prerequisites

A running server that exposes `/v1/chat/completions`. Any of these work:

- **OpenAI API** -- set `url` to `https://api.openai.com/v1/chat/completions`
- **Azure OpenAI** -- use the Azure-specific endpoint URL
- **vLLM** -- `python -m vllm.entrypoints.openai.api_server --model <model>`
- **Ollama** -- `ollama serve` (OpenAI compat is on by default at port 11434)
- **LiteLLM proxy** -- `litellm --model gpt-4o-mini`
- **Your own FastAPI wrapper** -- any server that accepts the same JSON shape

## Quick start

```bash
# 1. Export your API key (if the server requires one)
export OPENAI_API_KEY="sk-..."

# 2. Edit aegisrt.yaml to set the correct url and model
#    (defaults: localhost:8000, gpt-4o-mini)

# 3. Run the security scan
aegisrt run -c examples/http_basic/aegisrt.yaml
```

## Configuration notes

| Field | Purpose |
|---|---|
| `target.url` | Full URL of the chat-completions endpoint |
| `target.headers` | Auth headers; `${OPENAI_API_KEY}` is expanded from the environment |
| `target.body_template` | The JSON body sent on each request; `{{prompt}}` is replaced by the probe payload |
| `target.timeout_seconds` | Per-request timeout |
| `target.retries` | Number of retries on transient failures |

## Output

Reports are written to `.aegisrt/runs/<run-id>/`:

- `report.json` -- machine-readable results
- `report.sarif.json` -- SARIF format for GitHub Code Scanning integration
- Terminal summary printed to stdout

## Adjusting probes

To run only a subset of probes, set `enabled: false` on the ones you want to
skip, or remove them from the `probes` list entirely.
