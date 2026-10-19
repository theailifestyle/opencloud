# Open Bedrock (model gateway)

> The generic gateway (`llm-gateway`) is **off by default**. Turn it on with `OC_GENERIC_GATEWAY=1` in `.env` and rerun `install.sh`. **Initiate AI** (the provider key, given only to apps you opt in) works without the gateway.

Console page: **Open Bedrock** (`/models`). Apps call one OpenAI-compatible URL, `LLM_GATEWAY_URL`
(`http://llm-gateway:8000/v1`, inside the app network only), with their own `LLM_GATEWAY_KEY`, and send an
**endpoint name** as `model`. The gateway swaps in the provider model ID, adds the provider key, and forwards.

## Provider (Initiate AI)
- On **Open Bedrock** (`/models`), under **Initiate AI**, pick a provider (OpenRouter, OpenAI or Anthropic Claude) and paste its key.
  The provider's OpenAI-compatible chat URL is filled in for you; you can override it.
- The page then shows only `set`, the provider and when the key was last changed. Paste a new key to replace it, or tick
  **remove key**.
- Set it at install (`OC_LLM_UPSTREAM_URL`, `OC_LLM_PROVIDER_KEY` in `.env`, or the installer asks) or later in the console.
- The key is write-only: stored in `secrets/platform/llm-upstream-key` (0400, readable only by the gateway's user),
  never shown and never written to the audit log (it records only `key=changed`/`cleared`).
- **Apps that run their own AI code** can use the same key instead of keeping a copy. On the app's service page,
  under **AI provider key**, give it a name, e.g. `OPENROUTER_API_KEY`. The app then gets `/run/secrets/OPENROUTER_API_KEY`
  on every deploy, and restarts with the new value when the key is replaced. Removing the key removes the file. Only apps
  you opt in get the key.
- No key: **stub mode**. Requests still check app keys, endpoints and limits, and the reply echoes the prompt
  with `[stub]`. Useful for wiring an app before you pay for a provider.

## Endpoints
- Name (`chat-fast`) → provider model ID (`openai/gpt-4o-mini`), the apps allowed to use it, and a per-app
  requests-per-minute limit.
- An app gets its key under its service page (**Enable Open Bedrock**). It can call only the endpoints it is enabled on
  (others return 404, the same as unknown names). Over the limit: 429.
- `GET /v1/models` lists the endpoints that app can use.

## Usage
Per endpoint and app: requests, rejected (rate-limited), prompt tokens and completion tokens (as reported by the provider).
Prompts and completions are never logged or stored.

## Tested
tests/e2e.sh covers stub mode, a local mock provider (`tests/mock_openai.py`, which checks the provider key and
model ID), 404 for apps not enabled, 429 at the limit, usage counters, and that neither the key nor the prompt
appears in the console, gateway logs or audit log. A real provider has not been tested.
