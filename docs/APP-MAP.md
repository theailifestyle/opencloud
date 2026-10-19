# App Map

On each app's page, a flat diagram of what is deployed for it, each with live status:
Open ELB route (domains, health) → service (running, container health) → Postgres, buckets, and the
Open Bedrock endpoints the app is enabled on. Click the service to jump to its API endpoints.

## API endpoints
- **From an OpenAPI spec**: press *Discover* with the spec path (`/openapi.json` for FastAPI; or e.g. `/swagger.json`).
  The agent fetches it from the app over the internal network only (5 s timeout, size cap). The spec is untrusted input:
  only method, path and a short summary are kept, all of it is HTML-escaped, and nothing from it is rendered as HTML or links.
- **Manually**: add method, path and summary for apps without a spec.
- **Health**: tick *check* on an endpoint to probe it. Only `GET` endpoints without path parameters can be checked;
  POST/PUT/PATCH/DELETE are never called. Probes run every `OC_API_PROBE_INTERVAL` seconds (default 60) and right
  after you change a check. Shown: status code, latency, last checked (UTC).

tests/e2e.sh deploys examples/fastapi-app, discovers its endpoints, checks `/health`, refuses a POST check, and
verifies that `<script>` in an endpoint summary is shown escaped.
