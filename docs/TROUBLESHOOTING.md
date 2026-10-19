# Troubleshooting

Commands assume you are in the Open Cloud directory and `.env` exists. `$OC_ROOT` is the path from that file.

## Installer

**`Docker is required` or Compose v2 is missing.** Install Docker Engine and the Compose plugin before `./install.sh`. The first run only writes `.env` after that check passes.

**`Run install.sh with sudo`.** Secret files are owned by the unprivileged user inside each container. The installer needs root to `chown` them.

**`OC_PROXY_NETWORK is required` / network not found.** `OC_EDGE_MODE=external` is set. A fresh install should leave `OC_EDGE_MODE=internal` so Open Cloud's Caddy owns ports 80 and 443.

**`allowlisted path ... must exist`.** `OC_LOCAL_SOURCES`, `OC_ALLOWED_DATA_ROOTS`, or `OC_ALLOWED_SECRET_PATHS` names a path that is missing, relative, or contains `..`. Empty is the right value until you mean to allow something.

**Installer password did not appear.** It is printed only when the hash file is created. A second run stays quiet. `sudo ./opencloud reset-password` prints a new one.

## Builder keeps restarting

Log line `rootlesskit ... fork/exec /proc/self/exe: permission denied` means the host blocks user namespaces and the AppArmor profile is not loaded. Re-run `sudo ./install.sh`. Then:

```bash
sudo aa-status | grep opencloud-builder
sudo docker inspect oc-builder --format '{{.AppArmorProfile}}'
```

The inspect output should be `opencloud-builder`. The package `apparmor_parser` has to be installed.

## Certificates

**Browser warning on `console.localhost`.** `OC_TLS=internal` uses Caddy's local CA. That warning is expected.

**`certificate pending` on the DNS page.** The name does not yet have a Let's Encrypt certificate. Confirm the A record, wait a few minutes, and read `sudo docker logs oc-edge`. A wildcard certificate is not requested: each external app gets a certificate for its own hostname the first time it is served.

**Let's Encrypt keeps retrying the S3 hostname.** Set `OC_S3_PUBLIC=0` and re-run `sudo ./install.sh` if that name has no DNS record.

**`preview certificate on, DNS is ready`.** The static site still has the preview box ticked after DNS started pointing here. Use **Switch to real certificate** on the DNS page.

## Apps

**Build failed.** Open the job under **Deployments**. The Dockerfile must be at the root, or at the path you set. Builds are limited by `OC_BUILD_MEMORY` and `OC_BUILD_CPUS`.

**502 or unhealthy.** The process is not listening on `$PORT` and `0.0.0.0`, or it crashed. **Logs** on the service page is stdout and stderr. An Internal app has no public URL; a 502 on `<name>.apps.example.com` means it is still Internal, or the route was not written.

**Killed and restarting.** Raise memory on the service page. The default is 512 MB.

**Permission denied on `/data`.** Redeploy. The deployer hands `/data` to the user in the image, including files restored from a backup.

**Secret missing.** Creating a database, bucket, or secret restarts the app. Read the file at startup or on each use. `PORT` is the only value passed as an environment variable.

**Open Bedrock 404.** Wrong endpoint name, the generic gateway is off, or this app is not in the endpoint's enabled list. **429** means the per-app rate limit.

**S3 `SignatureDoesNotMatch` or bucket not found.** Path-style addressing, `S3_ENDPOINT` from inside the app, and a bucket that belongs to this app.

## Login

**Wrong password or code**, and you are sure of both. Check the server clock (`timedatectl`). TOTP allows one 30-second step of skew. Twenty failures in fifteen minutes pause sign-in until the window clears.

**Stuck on Choose your password.** That is the first-login gate. It stays until the new password is saved. See [LOGIN.md](LOGIN.md).

**Lost the authenticator.** `sudo ./opencloud disable-totp`, then sign in with the password and turn two-step login on again.

## Backups and disk

**Alarm `backup_stale`.** Nothing runs backups for you. Use **Back up now**, or the cron example in [RESTORE.md](RESTORE.md).

**Backup succeeded but the disk died.** The restic repository lives under `$OC_ROOT/backups/restic` on the same disk. Copy it, and the restic password, somewhere else.

## Where to look

```bash
sudo docker compose ps
sudo docker logs oc-edge
sudo docker logs oc-agent
sudo docker logs oc-console
```

`oc-agent` is the deployer. App logs are also under **Open CloudWatch → Logs**, with common secret shapes redacted.
