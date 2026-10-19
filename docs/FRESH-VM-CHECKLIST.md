# Fresh install checklist

Use this after [INSTALL.md](INSTALL.md) to check a brand-new machine. Tick each box and note the date, OS, and VM size. A real public certificate is not covered by the automated tests.

## 0. Before you start
- [ ] VM: Ubuntu 24.04 or Debian 12/13, 2 vCPU, 4 GB RAM, 40 GB disk, public IPv4 (IPv6 optional)
- [ ] A test domain you control, e.g. `example.com`, with `console.example.com`, `*.apps.example.com` → VM IP
- [ ] `dig +short console.example.com` and `dig +short anything.apps.example.com` return the VM IP
- [ ] Provider firewall / security group: inbound 22, 80, 443 only

## 1. Base system
- [ ] `sudo apt update && sudo apt -y upgrade`, reboot if needed
- [ ] Create a non-root sudo user; SSH key login works (don't change SSH hardening as part of this test)
- [ ] Install Docker Engine + Compose v2 from Docker's docs; `docker compose version` prints v2.x
- [ ] `python3 --version` works
- [ ] `ufw allow 22,80,443/tcp && ufw enable` (or the provider firewall only)
- [ ] `ss -ltn` shows nothing on 80/443 yet

## 2. Install
- [ ] `git clone https://github.com/theailifestyle/opencloud.git && cd opencloud && ./install.sh` creates `.env` and stops
- [ ] Edit `.env`: `OC_CONSOLE_HOST`, `OC_APPS_DOMAIN`, `OC_S3_HOST`, `OC_ACME_EMAIL`, `OC_TLS=acme`
- [ ] `sudo ./install.sh` exits 0 and prints the admin password once. Save it in a password manager
- [ ] `sudo ./install.sh` again: exits 0, no new password, `sudo sha256sum $OC_ROOT/secrets/platform/* $OC_ROOT/secrets/console/*` unchanged
- [ ] `sudo docker compose ps`: edge, console, agent, builder, storage all running (llm-gateway only if `OC_GENERIC_GATEWAY=1`)/healthy
- [ ] `sudo docker ps --format '{{.Names}} {{.Ports}}'`: only `oc-edge` shows host ports, 80 and 443

## 3. Real HTTPS (the part not yet verified anywhere)
- [ ] `curl -sI https://console.example.com` returns 200 with a **publicly trusted** certificate (no `-k`)
- [ ] `sudo docker logs oc-edge | grep -i "certificate obtained"` for the console host
- [ ] After deploying an app, its `https://<app>.apps.example.com` gets its own certificate within a minute
- [ ] `https://s3.apps.example.com` (OC_S3_HOST) has a valid certificate
- [ ] `http://console.example.com` redirects to HTTPS

## 4. Console smoke test (browser)
- [ ] A wrong password is refused. The right one signs in and goes straight to **Choose your password**; every other page redirects there until you set a new one. Afterwards the installer password is refused
- [ ] **Two-step login**: scan the QR code, confirm with password + code, save the recovery codes. Sign out and back in with the code. A reused code is refused; a recovery code works once
- [ ] App Runner: deploy `https://github.com/traefik/whoami` on port 80. The job reaches **succeeded**, and the URL serves
- [ ] Set a secret. Its name appears, its value never does
- [ ] Create a Postgres database. `DATABASE_URL` appears in the secrets list
- [ ] Create a bucket. The S3 key secrets appear
- [ ] Set limits to 256 MB / 0.5 CPU. `docker inspect` shows them
- [ ] Redeploy, then Roll back. Both are recorded in Releases
- [ ] Back up now. A snapshot is listed
- [ ] Audit log: entries for all of the above, chain **intact**
- [ ] DNS page: lists the console and the app with the VM's IP resolving

## 5. Automated checks on the VM
- [ ] `python3 -m unittest discover -s tests`: all pass
- [ ] For a local-cert run, use a second `.env` with `OC_TLS=internal` and `*.localhost` names on a separate VM,
      or skip this. `tests/e2e.sh` assumes `--resolve` to 127.0.0.1 with self-signed certs

## 6. Restore drill
- [ ] Follow [RESTORE.md](RESTORE.md): restore one app's `/data`, one database dump, and object storage
- [ ] Copy the restic repo + password off the VM. Restore a snapshot from the copy on another machine
- [ ] Optional: the "Rebuild a whole machine" steps on a second fresh VM (not yet tested by anyone)

## 7. Reboot and upgrade
- [ ] `sudo reboot`. Everything comes back on its own (`restart: unless-stopped`), and the apps serve
- [ ] `git pull && sudo ./install.sh`: exits 0, apps keep serving

## 8. Tear down
- [ ] `sudo ./opencloud down`, delete DNS records, destroy the VM
- [ ] Record results, OS/Docker versions and anything that differed from these steps
