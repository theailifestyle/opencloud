# Open ELB (load balancer)

Console page: **Open ELB** (`/loadbalancers`). One route per **External** app, served by Caddy (the only public entry point, 80/443). Internal apps are not listed. How the edge fits the rest of the machine is [ARCHITECTURE.md](ARCHITECTURE.md).

The deployer writes each change to that app's Caddy site file, checks it with `caddy validate`, then reloads. If validation or the reload fails, the previous file is put back and reloaded, and the console shows the error. Every change is audit-logged (domains, redirect, health settings, canary weight).

| Setting | What it does |
|---|---|
| Domains | `<app>.<apps domain>` always; add custom domains (comma or space separated). A name used by the console, the S3 host or another app is refused. Point the custom domain's DNS at the server; Caddy gets the certificate. |
| HTTP→HTTPS redirect | On (default): plain HTTP gets a 308 to HTTPS. Off: the app is also served on plain HTTP. |
| Health check | Path (e.g. `/health`) and interval in seconds. Caddy probes each backend and stops sending traffic to one that fails. Shown on the page as healthy / needs attention. |
| Canary | 0–50 % of requests go to the previous release, which runs as a second container beside the current one (random choice over 20 weighted slots, so 5 % steps; stock Caddy `weighted_round_robin` stuck to one backend for long runs in testing). Needs two deploys first. Set it back to 0 to stop the old container. Roll back from the app page if the new version is bad. |

Shown per route: domains, target (app, current and previous release), TLS status per domain, health.
Internal apps have no edge route, so they aren't listed. Below the routes, the page lists hand-written `site-*.caddy` routes (read-only) and an **Edge config** panel with every site file. That panel is read-only and redacted: `basic_auth`/`forward_auth` blocks, lines mentioning auth, tokens, secrets, passwords, keys or cookies, `{env.*}` placeholders and long secret-like strings are replaced with `[redacted]` (agent `GET /edge-config`).

Not available with stock Caddy: per-route rate limiting (needs a plugin) and sticky sessions across releases.
Canary split is per request, not per user.

## Hand-written sites

If an app is served only by a hand-written site, set it to **Internal**. Open Cloud then writes no `<app>.caddy` file for it, so it doesn't also get an unused `<app>.<apps domain>` route.

The console's Routes page covers most cases. When a site needs something it can't express (extra request headers, body size limits, a redirect-only host, a custom header policy), add a Caddy file by hand:

1. Create `$OC_ROOT/caddy/sites/site-<name>.caddy` (root-owned, mode 644). Use the `site-` prefix. App names cannot start with `site-`, so a delete cannot target that file. Open Cloud writes `<app>.caddy` for each app, with `# opencloud:app=<app>` on the first line, and removes that file only when it wrote it. A hand-written file, including every `site-*.caddy`, is left in place. One that still proxies to the deleted app is named in the result.
2. Point upstreams at `app-<app>:<port>`. Every app is reachable under that name on the edge network.
3. `import security_headers` works in any site file. Snippets that only your files use can live in a file that sorts first, for example `00-snippets.caddy`.
4. Check the file and apply it:
   ```
   docker exec oc-edge caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile
   docker exec oc-edge caddy reload --config /etc/caddy/Caddyfile
   ```

Each domain belongs in one site only. If you also add a hand-written domain on the Routes page, Caddy rejects the change and Open Cloud rolls it back.
