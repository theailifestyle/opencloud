# Install

This is a fresh install on a new server. Open Cloud's own Caddy listens on ports 80 and 443. You need a domain you can edit, unless you are only trying it on localhost.

Placeholders below match `.env.example`. Use your own names.

## What you need

- A Linux server with a public IPv4 address. Ubuntu 24.04 or Debian 12/13 is a good fit. 2 vCPU, 4 GB RAM, and 40 GB disk is a comfortable start. 2 GB RAM is the minimum and is tight once a build starts.
- Docker Engine and the Compose v2 plugin (`docker compose version` prints v2). Install them from [Docker's documentation](https://docs.docker.com/engine/install/). The distribution's `docker.io` package is often too old or split from the Compose plugin.
- Python 3 (already present on those releases) and `sudo`.
- Ports 80 and 443 free (`ss -ltn` should not show them).
- A domain. Create these DNS records before the first real-certificate install, or Let's Encrypt will fail and Caddy will retry:
  - `console.example.com` → A record to the server's public IP
  - `*.apps.example.com` → A record to the same IP

  The wildcard is the apps domain. An external app named `my-app` is then `https://my-app.apps.example.com` with no further DNS records. Details: [DNS.md](DNS.md).

Ubuntu 23.10 and 24.04 block unprivileged user namespaces. You do not turn that off. `install.sh` installs an AppArmor profile that allows user namespaces for the builder container only. The `apparmor_parser` package ships with Ubuntu.

## Configure

```bash
git clone <repository-url> open-cloud
cd open-cloud
./install.sh
```

The first run needs Docker already installed. It copies `.env.example` to `.env` and stops. Edit `.env`:

| Variable | Example | Purpose |
|---|---|---|
| `OC_ROOT` | `/srv/opencloud` | Data, secrets, and backups. Must not be inside the git checkout |
| `OC_CONSOLE_HOST` | `console.example.com` | Name you open in a browser |
| `OC_APPS_DOMAIN` | `apps.example.com` | External apps are `<name>.apps.example.com` |
| `OC_S3_HOST` | `s3.apps.example.com` | Public S3 hostname for presigned URLs. Covered by the wildcard |
| `OC_ACME_EMAIL` | `admin@example.com` | Let's Encrypt account email |
| `OC_TLS` | `acme` | `acme` for real certificates, `internal` for Caddy's local CA |
| `OC_PUBLIC_IP` | empty, or your server's IP | Optional. The DNS page uses it to flag names that point somewhere else |

Leave `OC_LLM_PROVIDER_KEY` and `OC_SMTP_PASSWORD` empty and set them in the console later. If you do put them in `.env`, delete them from the file after install. The installer stores them as secret files and will not overwrite those files on a later run.

`OC_ALLOWED_SECRET_PATHS`, `OC_ALLOWED_DATA_ROOTS`, `OC_ALLOWED_EXTERNAL_NETWORKS`, and `OC_LOCAL_SOURCES` stay empty. Filling them in lets an app mount a path or join a network that already exists on that server. They are read from `.env` on every deploy. See [SECURITY.md](SECURITY.md#host-sources-and-mounts-opt-in).

Set `OC_S3_PUBLIC=0` if you do not want a public object-storage site. Apps still use storage inside the server, and the edge does not request a certificate for `OC_S3_HOST`.

## Start

```bash
sudo ./install.sh
```

The installer:

- creates `$OC_ROOT` and generates tokens (mode 0400, one owner per file)
- creates the admin password, prints it once, and sets the must-change flag
- renders the Caddyfile from `edge/Caddyfile.template` using the hostnames in `.env`
- loads the builder AppArmor profile when this kernel requires it
- builds the platform images and starts the stack

Running it again does not rotate secrets or replace `.env`. See [UPGRADING.md](UPGRADING.md).

Lost the password before you changed it: `sudo ./opencloud reset-password`.

## Firewall

The installer prints these commands and does not run them. Docker-published ports bypass `ufw`. Open Cloud publishes only 80 and 443, so do not publish anything else.

```bash
sudo ufw default deny incoming
sudo ufw allow 22/tcp
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw enable
```

Allow SSH before you enable `ufw`, or you will lock yourself out. A provider firewall that already allows only 22, 80, and 443 is enough on its own.

## Sign in

Open `https://console.example.com`. Use the password from the installer. The console then asks you to choose your own. After that, turn on two-step login. Both steps are in [LOGIN.md](LOGIN.md).

Deploy a first app with [DEPLOY.md](DEPLOY.md). Copy backups off the machine ([RESTORE.md](RESTORE.md)). A box-ticking pass over the same steps is [FRESH-VM-CHECKLIST.md](FRESH-VM-CHECKLIST.md).

## Try it without a public domain

In `.env`:

```bash
OC_ROOT=/tmp/oc-root
OC_CONSOLE_HOST=console.localhost
OC_APPS_DOMAIN=localhost
OC_S3_HOST=s3.localhost
OC_TLS=internal
OC_ACME_EMAIL=admin@example.com
```

`sudo ./install.sh`, then open `https://console.localhost` and accept Caddy's local certificate. `*.localhost` is not a real wildcard in public DNS. This mode is for the machine you are sitting at.

## What `./opencloud` does

```text
./opencloud install | status | reset-password | disable-totp | down
```

`install` is `install.sh`. `status` and `down` are `docker compose ps` and `docker compose down`. `reset-password` and `disable-totp` are described in [LOGIN.md](LOGIN.md).

## Files the installer writes

Under `$OC_ROOT` (not in git):

- `secrets/platform/` tokens, the restic password, the provider key file
- `secrets/console/` admin password hash, must-change flag, two-step login
- `secrets/storage/s3.json` storage admin identity
- `caddy/Caddyfile` rendered from your hostnames
- `apps/`, `data/`, `pgdata/`, `sites/`, `storage/`, `backups/`, `audit/`, `watch/`, `gateway/`

`observe.compose.yaml` and `host-mounts.compose.yaml` appear only when you turn on observe mode or an allowlist. They are generated from `.env` and are not part of this repository.
