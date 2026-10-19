# Changelog

## 0.1.0 — 2026-10-19

First public release.

- Console with one admin login, a required password change on first sign-in, and optional two-step login
- App Runner: build a public Git repository (or an allowlisted server folder) and run it. New apps are Internal unless you choose External
- Open ELB: Caddy on ports 80 and 443, automatic HTTPS, custom domains, health checks, canary
- Managed Postgres 17, one database per app, runtime role separate from the owner role
- Open S3 (SeaweedFS) with per-app keys, plus static sites
- Open Bedrock: one provider key for opted-in apps, and an optional generic gateway
- Open CloudWatch: metrics, redacted logs, alarms, email, and an event feed
- DNS page (read-only view of DNS, route, and certificate; it does not change DNS records)
- Encrypted restic backups and Postgres dumps
- Installer, `.env.example`, and guides for a fresh server

Installs created by earlier versions of this software keep working when `install.sh` is run again: existing `.env` and secrets are left in place, and an admin hash or two-step secret still stored under `secrets/platform/` is moved into `secrets/console/`.
