# Static sites

Host plain HTML/CSS/JS sites (no server code) on Open Cloud, each on its own domain with automatic HTTPS. Buckets and keys for apps are [STORAGE.md](STORAGE.md). Domains and the wildcard apps name are [DNS.md](DNS.md).

## How it works

- **Storage.** Every upload goes into the private object-storage bucket `sites`, at `sites/<site>/<release>/`. Only the
  storage admin identity can read it. Apps can't create a bucket named `sites`, and anonymous requests to the bucket get 403
  (with `OC_S3_PUBLIC=0` the S3 endpoint isn't published at all).
- **Serving.** The agent also unpacks each release to `$OC_ROOT/sites/<site>/releases/<release>/` and swaps the
  `current` symlink in one step, so visitors see the old site or the new one, never a mix. The edge mounts
  `$OC_ROOT/sites` read-only at `/srv/sites` and serves `current` with Caddy `file_server`. The edge never talks to object
  storage, so a site can't be used to list the bucket, read another site's prefix or reach the storage API.
- **Edge file.** Attaching domains writes `caddy/sites/site-static-<site>.caddy`, built only from validated
  fields. It is checked with `caddy validate` before the reload, and the old file is restored if the check fails.
- The last 3 releases are kept, both on disk and in the bucket.

## Defaults

- `index.html` is served for `/` and for folders. A missing path returns 404 with `404.html` (the site's own file, or a
  plain default page).
- No directory listing, and dotfiles are hidden (`hide .*`). The request body limit is 1 KB, since sites take no posts.
- Same security headers as the other public sites: HSTS, nosniff, `X-Frame-Options SAMEORIGIN`, a Referrer-Policy and a
  Permissions-Policy with camera, microphone and location off. The `Server` header is removed.
- Caching: HTML pages and 404s get `no-cache` (always revalidated, ETag/Last-Modified). Other files get
  `public, max-age=3600`.
- Upload limits: 10 MB per upload, 50 MB unpacked, 2000 files. Zip entries with `..`, absolute paths, backslashes,
  drive letters or symlinks are rejected, and nothing is written for a rejected upload. One wrapping folder in a zip is
  stripped. `index.html` is required at the top level.
- Every create, upload (including rejected ones), domain change and delete is written to the audit log
  (`site-create`, `site-upload`, `site-domains`, `site-delete`).

## Using it (console → Static sites)

1. **Create site:** enter a name (a-z, 0-9, -).
2. **Upload:** one `.html` file (saved as `index.html`) or a `.zip`. Each upload replaces the whole site.
3. **Domains:** enter space-separated hosts and save. The page shows the A record each domain needs.
   Tick **DNS not ready (preview certificate)** while DNS doesn't point here yet. The site then uses a local certificate
   instead of retrying Let's Encrypt. Untick it once DNS resolves, and the edge gets a real certificate on the next visit.
4. **Delete site:** removes the edge file, the files on disk and the bucket prefix.

On the **DNS** page (see [DNS.md](DNS.md)) each site also gets **Switch to real certificate** (only once every domain resolves to this server) and, when both `example.com` and `www.example.com` are attached, **Redirect www to the main domain** (`www` gets its own block with a 301 to the main domain, keeping the path). The redirect setting is kept when you save domains again.

Agent API (token-protected, internal network only): `GET /sites`, `POST /sites {"name"}`,
`POST /sites/<n>/upload {"filename","data": base64}`, `POST /sites/<n>/domains {"domains","tls_internal","www_redirect"}`,
`POST /sites/<n>/real-cert`, `POST /sites/<n>/www-redirect {"on"}`, `POST /sites/<n>/delete`.

## How to point a domain

1. Sign in to your domain registrar (or DNS provider) and open the domain's DNS records.
2. Delete any default parking or redirect records for `@` and `www`.
3. Add an **A record**: host `@`, value = the server's public IP (shown on the Static sites page), TTL automatic.
4. Add an **A record**: host `www`, same IP (only if you want `www` too).
5. If the domain uses custom nameservers, add the records at that DNS provider instead.
6. Wait until `dig +short example.com @1.1.1.1` returns the server IP (usually minutes, up to a few hours).
7. In the console, set the site's domains to `example.com www.example.com`, untick the preview certificate box and save.
   The first HTTPS visit gets a Let's Encrypt certificate.
