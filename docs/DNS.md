# DNS and domains

Open Cloud does not create or edit DNS records. You add them at your DNS provider. The console then shows, for each name the edge knows, whether it resolves to this server, where the edge sends it, and whether a certificate exists.

## Records for a fresh install

Set the names in `.env`. The examples are the placeholders from `.env.example`.

| Setting | Example | What to add at your DNS provider |
|---|---|---|
| `OC_CONSOLE_HOST` | `console.example.com` | A record (and AAAA if you have IPv6) to this server |
| `OC_APPS_DOMAIN` | `apps.example.com` | Wildcard A record `*.apps.example.com` to the same address |
| `OC_S3_HOST` | `s3.apps.example.com` | No extra record if it sits under the apps wildcard. Add one if you chose a different host |
| `OC_PUBLIC_IP` | empty, or `203.0.113.10` | Not a DNS record. Optional. The DNS page compares lookups to it. `203.0.113.0/24` is a documentation range; use your server's address or leave the setting empty |

The wildcard is how external apps get a hostname. An app named `my-app` with visibility External is `https://my-app.apps.example.com` without another record. Each of those names gets its own Let's Encrypt certificate the first time it is requested. The wildcard is not itself a certificate.

Internal apps are not in DNS. They have no public name.

Create the console and wildcard records before `sudo ./install.sh` with `OC_TLS=acme`, so the first certificate request succeeds. `http://` on port 80 is how the certificate is issued, and it redirects to HTTPS afterwards.

`OC_S3_PUBLIC=0` skips the public S3 site, so `OC_S3_HOST` needs no record and no certificate. Apps still reach storage on the internal network.

## The DNS page

Console page: **DNS** (`/dns`). It follows each domain the edge knows about through the whole chain, one row per domain:

| Column | Where it comes from |
|---|---|
| Domain | Every host in the edge site files (`$OC_ROOT/caddy/sites/*.caddy`) plus the console host. |
| Resolves to | Looked up by the agent on this server (the console's own network has no outside DNS). |
| Routed to | The app (`<app>.caddy`, written by Open ELB), the static site (`site-static-<n>.caddy`), or the upstream of a hand-managed `site-*.caddy` file. |
| Certificate | `issued` (Let's Encrypt certificate on the edge), `preview` (`tls internal` in the file), or `pending`. |
| Status | Problems, or `ok`. |
| Config | The site file, read-only and redacted the same way as the Open ELB **Edge config** panel. |

Problems flagged:

- **no DNS record**: the edge routes the name, but it doesn't resolve.
- **DNS points elsewhere**: it resolves, but not to `OC_PUBLIC_IP`. (Without `OC_PUBLIC_IP` this check is skipped.)
- **certificate pending or failed**: DNS points here but no Let's Encrypt certificate exists yet. A few minutes after
  DNS changes this is normal; if it stays, check `docker logs oc-edge`.
- **preview certificate on, DNS is ready**: switch the site to a real certificate.

## Guided actions

No raw Caddy editing. Each action rewrites only that app's or site's own edge file, runs `caddy validate`, reloads,
and puts the previous file back (and reloads) if validation or the reload fails. The setting is saved only after the
edge accepted the change. Every action is audit-logged.

- **Add a domain** to an external app (adds a custom domain to its Open ELB route) or a static site. Names already
  used by another file, the console or the S3 host are refused.
- **Switch to real certificate** (static sites with the preview certificate on): refused until every domain of the
  site resolves to this server; then the edge gets Let's Encrypt certificates on the next visit.
- **Redirect www to the main domain** (static sites with both `example.com` and `www.example.com`): `www` gets its own
  block that answers with a 301 to the main domain, keeping the path. **Stop redirecting www** undoes it.

Hand-managed `site-*.caddy` files are shown read-only and never changed by the console. Open Cloud never creates or
changes DNS records at your registrar or DNS provider; you add the A records yourself.

Agent API (token-protected, internal network only): `GET /dns`, `POST /domain-add {"target": "app:<n>"|"site:<n>", "domain"}`,
`POST /sites/<n>/real-cert`, `POST /sites/<n>/www-redirect {"on"}`.
