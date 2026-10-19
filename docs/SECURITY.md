# Security model

## Boundaries
- **One front door.** Only `edge` (Caddy) publishes host ports (80/443). Apps, databases, console,
  agent, builder, storage and gateway publish none (checked by `tests/e2e.sh`).
- **Console** (public, via Caddy): no Docker socket, read-only filesystem, unprivileged user. It talks
  to the agent over an internal-only network with a generated token.
- **Agent**: the only container with the Docker socket (so it is root-equivalent on the host). It has no
  ports, is not on the app network, and offers a fixed list of validated actions. It never runs
  caller-supplied commands. Its action list is the trust boundary.
- **Apps**: deploys with host ports, host networking or privileged mode are refused. `cap_drop: ALL`
  with five add-backs most images need (NET_BIND_SERVICE, CHOWN, SETUID, SETGID, DAC_OVERRIDE),
  `no-new-privileges`, memory/CPU/pid limits, rotated logs. Root filesystems are **writable by default**; an app opts
  in to `read_only` (with `tmpfs` paths) and a Docker `health` check in `app.json` or a shipped `opencloud.json`
  (see APP-GUIDE). With a health check, deploys (`compose up --wait`) wait until the app is healthy.
- **Databases**: one per app on its own `internal: true` network. The app connects as `app_runtime`
  (no superuser, CREATEDB or CREATEROLE; only CONNECT, schema USAGE, table DML and sequence USAGE/SELECT, with
  default privileges for new tables). The owner role `app` stays inside the DB container for schema changes.
- **Secrets**: generated on install; each file is mode 0400 and owned by the single container user
  that reads it. The admin password is stored only as a scrypt hash.
- **Two-step login (TOTP, RFC 6238)**: optional, set up in the console under **Two-step login** (QR code + setup key
  shown only in that browser page; it turns on only after a correct code). Sign-in is one form with the password and
  the code, checked password first, so there is no half-signed-in session. Codes are accepted one step either side
  (+/-30 s) and each works once (the last used step is stored, so this survives restarts). 8 one-time recovery codes
  are shown once; only their SHA-256 hashes are kept. The per-IP (5 per 5 min) and account-wide (20 per 15 min) limits
  count every failed sign-in, whichever factor was wrong. Turning it on ends other sessions. The secret lives in
  `$OC_ROOT/secrets/console/totp.json` (console-owned, 0600, under the root-only secrets directory), not encrypted:
  the console must read it, so a key on the same machine would add nothing. Break-glass: `sudo ./opencloud disable-totp`. See [LOGIN.md](LOGIN.md).
- **Admin password changes**: the installer-generated password is single-use in practice. `install.sh` and
  `reset-password` create `$OC_ROOT/secrets/console/must-change-password`; while it exists, a signed-in session can
  only reach the change form and Sign out. A change needs the current password, the new one twice (12+ characters,
  different from the current one) and the CSRF token. The console writes the new scrypt hash atomically, deletes the
  flag, ends every other session and issues a new session cookie. The audit log records the event, never the value.
  - *Tradeoff:* to do this, the console (uid 10001) owns `$OC_ROOT/secrets/console/` (0700) and its files (0600)
    and mounts that directory read-write; before, the hash was a root-provisioned read-only file mount. A compromised
    console could therefore replace the admin hash (it could already act as the admin through the agent, so this
    adds little), and it holds the two-step login secret in the same directory, but it still can't read any other secret: the agent token and watch token stay
    read-only single-file mounts. The flag can only be set from the host (`install.sh`, `reset-password`).
- **Object storage**: anonymous access off; each app key is limited to that app's buckets. SeaweedFS's
  internal master/filer/volume ports bind to loopback inside its container.
- **Audit log**: a local consistency check (hash chain), not tamper-proof; append-only through the API. Root on the host can still edit the file;
  it catches accidental or partial edits, but root can rewrite the whole file and chain undetected.

## Build sandbox
App Dockerfiles are untrusted code. They build in **`oc-builder`, a rootless BuildKit container**, not in
the host Docker daemon:
- unprivileged container, runs as uid 1000, no Docker socket, no host bind mounts (state in a volume)
- memory/CPU/pid limits (`OC_BUILD_MEMORY`, `OC_BUILD_CPUS`, 1000 pids)
- only on the agent's egress network: apps can't reach it, and the agent listens only on `oc_control`, so builds can't reach the agent API
- no BuildKit entitlements granted (no `network.host`, no `security.insecure`)
- the agent loads the finished image into Docker and starts it with the app hardening above

Tradeoffs (why it's "hardened", not "isolated"):
- Rootless BuildKit needs `seccomp=unconfined` and `apparmor=unconfined` to create user namespaces,
  and runs with `--oci-worker-no-process-sandbox`. A build step that escapes the build would land in
  the builder container as uid 1000, not on the host. But this container has a weaker seccomp
  profile than the default.
- Builds have internet access (they need it to fetch packages), so a malicious Dockerfile can make
  outbound requests. It can't reach apps, databases or the console. It shares the `egress` network with the agent,
  The deployer binds only to its `oc_control` address (`OC_AGENT_BIND`), so port 7000 isn't reachable
  from the builder.
- One shared builder: build caches are shared between apps.
- The strongest option would be a separate VM or a gVisor/Kata runtime per build. That's out of scope for a
  single-machine install.
**Bottom line:** only deploy repositories you trust.

### Hosts that restrict unprivileged user namespaces (Ubuntu 23.10+, 24.04)
`kernel.apparmor_restrict_unprivileged_userns=1` stops rootless BuildKit even with `apparmor=unconfined`
(`rootlesskit: fork/exec /proc/self/exe: permission denied`, container restarting). Open Cloud does **not** turn the
sysctl off. `install.sh` installs `deploy/apparmor/opencloud-builder` to `/etc/apparmor.d/` and loads it, and
`oc-builder` runs under that named profile (`OC_BUILDER_APPARMOR=opencloud-builder`, set by `compose-env.sh`).
The profile is unconfined like before plus `userns`, so the exception covers only processes in the builder
container; everything else on the host keeps the restriction. Remove: `sudo apparmor_parser -R
/etc/apparmor.d/opencloud-builder && sudo rm /etc/apparmor.d/opencloud-builder` (then the builder can't start).

## Host sources and mounts (opt-in)
For apps that already live on the server (built from a folder, reading secret files, attached to an existing
network), four allowlists in `.env` widen what an app may get. All are empty by default, which keeps the old
behaviour (public Git only, own `/data`, own secrets, `oc_edge` only).
- `OC_LOCAL_SOURCES`: folders an app's source may come from. The agent mounts them read-only, resolves symlinks,
  refuses `..` and anything outside, and copies the folder (symlinks kept as links) into the app's build dir.
  The build sees only that copy.
- `OC_ALLOWED_EXTERNAL_NETWORKS`: existing Docker networks an app may join (alias `app-<name>`). `host`, `bridge`
  and `none` are always refused. Joining a network puts the app next to whatever else is on it; allow only the
  networks you mean (e.g. your proxy's network or a shared LLM gateway network).
- `OC_ALLOWED_SECRET_PATHS`: exact secret files (or folders of them) an app may mount **read-only** at
  `/run/secrets/<name>`. The agent checks that the path is a file and never opens it, so values stay where they
  are. Ownership and mode are left as they are on the host.
- `OC_ALLOWED_DATA_ROOTS`: folders an app may mount (read-write, or `:ro`). Open Cloud doesn't chown them and
  doesn't back them up (your existing backups keep covering them). Container paths under `/run/secrets`, `/proc`,
  `/sys`, `/dev`, `/etc`, `/usr`, `/bin`, `/lib` are refused.
The allowlists are rechecked before every deploy, redeploy and rollback, so shrinking one takes effect at the next
start. Tradeoff: the agent (already root with the Docker socket) gets read-only views of the allowlisted paths.

## Known limits
- Apps share one network (`oc_edge`) with each other, the gateway and the S3 endpoint.
- Single admin account. No per-user roles.
- Backups stay on the machine unless you copy them off ([RESTORE.md](RESTORE.md)).
- Object storage backups are best effort while running.
- The installer prints firewall guidance but doesn't apply it. Docker-published ports bypass `ufw`.
  Open Cloud publishes only 80/443.

## Hardening a fresh install

Do these after [INSTALL.md](INSTALL.md). None of them are applied for you.

1. Replace the installer password at the first sign-in (the console refuses to do anything else until you do) and turn on two-step login ([LOGIN.md](LOGIN.md)).
2. Allow only SSH, 80, and 443 in the host firewall. Do not publish other Docker ports.
3. Leave `OC_ALLOWED_SECRET_PATHS`, `OC_ALLOWED_DATA_ROOTS`, `OC_ALLOWED_EXTERNAL_NETWORKS`, and `OC_LOCAL_SOURCES` empty unless an app on this server truly needs a path or network that already exists. Those lists are read from `.env` on every deploy.
4. Copy the restic repository and its password off the machine ([RESTORE.md](RESTORE.md)).
5. Deploy Git repositories you trust. The builder is hardened, not a separate machine.
6. Set `OC_S3_PUBLIC=0` if browsers do not need presigned URLs.
7. Keep the host and Docker updated, and re-run `sudo ./install.sh` after you pull ([UPGRADING.md](UPGRADING.md)).

Report a vulnerability privately through [GitHub private vulnerability reporting](https://github.com/theailifestyle/opencloud/security/advisories/new), as described in [SECURITY.md](../SECURITY.md). Do not open a public issue for it.

## Network layout
- `oc_console` (internal): edge and console only. Apps on `oc_edge` cannot reach the console.
- The console trusts `X-Forwarded-For` only from peers that resolve from `OC_TRUSTED_PROXY_HOSTS` (default `oc-edge`; fail-closed). External-proxy mode must set it to the proxy's container name.
- Login is limited per IP and per account (20 failures / 15 min).
- The agent binds only to its `oc_control` address (`OC_AGENT_BIND`), so the builder (shared egress network) cannot reach port 7000.
- Known gap: apps still share `oc_edge`, so they can reach each other as `app-NAME:PORT`. "Internal" means no public address, not isolation.
