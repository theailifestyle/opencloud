# Upgrading

Upgrading means a newer copy of this repository on a server that already runs Open Cloud. Apps are not rebuilt by the installer. You redeploy them from the console when you want the new image.

## Steps

```bash
cd open-cloud
git pull
sudo ./install.sh
```

`install.sh` is safe to run again.

- It does not overwrite `.env`.
- It does not rotate tokens, the admin password, the provider key, or the restic password when those files already exist.
- It re-renders the edge Caddyfile from the current `.env` and `edge/Caddyfile.template`.
- It rebuilds the platform images (console, deployer, gateway, watch) and recreates containers whose definition changed.
- It reloads the builder AppArmor profile when this kernel requires it.

The admin password is printed only when there is no hash yet. A quiet second run is the normal one.

Then check:

```bash
sudo docker compose ps
```

Edge, console, deployer (`oc-agent`), builder, and storage should be up. The generic gateway is up only when `OC_GENERIC_GATEWAY=1`.

## What you do by hand

- **Apps.** Platform containers restarting does not redeploy apps. Open each app and **Redeploy** when its build or base image should change. **Roll back** returns to the previous app image.
- **Image pins.** `OC_SEAWEEDFS_TAG` and `OC_BUILDKIT_TAG` in `.env` are the versions you get. Bump them on purpose.
- **SMTP and provider key.** If `OC_SMTP_PASSWORD` or `OC_LLM_PROVIDER_KEY` is still in `.env` after the first install, delete those lines. The secrets on disk are what the services read.
- **Allowlists.** Shrinking `OC_ALLOWED_SECRET_PATHS`, `OC_ALLOWED_DATA_ROOTS`, or `OC_ALLOWED_EXTERNAL_NETWORKS` takes effect the next time that app starts. Re-run `install.sh` after editing `.env` so the deployer sees the new list.

## Reboot

Containers are `restart: unless-stopped`. After `sudo reboot` they come back without another install. External apps are served again once Docker and the edge are up. There is no separate boot script.

## Older auth files

Installs created by an earlier version of this software may still have `admin-password.scrypt` or `totp-secret` under `$OC_ROOT/secrets/platform/`. `install.sh` moves those into `$OC_ROOT/secrets/console/` once. A fresh install never has them. Two-step login is set up in the console either way ([LOGIN.md](LOGIN.md)).

## When a restart is not enough

A change to an app's Dockerfile, its Git revision, or its `opencloud.json` is a **Redeploy**, not an installer run. A change to a secret, database, or bucket is the button on the service page. That restarts the app container so the new file is visible.
