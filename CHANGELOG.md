# Changelog

## Unreleased

- Delete an app from its service page. The deployer removes that app's containers, edge route, database, buckets, secrets, and files. A final backup (database dump, bucket objects, app definition, and `/data`) is on by default and is written under `$OC_ROOT/backups/deleted/`. Host mounts and hand-written edge files are left in place. Deploy jobs and release records are kept and marked deleted.
- App names cannot start with `site-`. Delete refuses a name that is not an app unless a delete was already recorded, and it removes an edge file only when the deployer wrote that file. A bucket shared with another key (including by `Write`, `List`, `Tagging`, or `Admin` on that bucket) is not deleted. The database dump runs only inside that app's Postgres container as the user `app`.
- The final backup of an app downloads every object in its buckets. A backup that fails is renamed to end with `-incomplete` and is not used; the app stays.

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
