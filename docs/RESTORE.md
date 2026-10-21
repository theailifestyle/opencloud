# Backups and restore

## Schedule

Nothing in Open Cloud runs a backup on a timer. Use **Back up now** on the console's Backups page, or call the deployer from the host once a day. The deployer listens only on the internal `oc_control` network, so the call goes through Docker:

```bash
#!/bin/sh
# /usr/local/sbin/opencloud-backup — run from cron as root, from a clone of this repository
set -eu
cd /path/to/opencloud
set -a; . ./.env; set +a
token=$(cat "$OC_ROOT/secrets/platform/agent-token")
docker run --rm --network oc_control curlimages/curl -fsS --max-time 3600 \
  -X POST -H "Authorization: Bearer $token" http://agent:7000/backup
```

`15 3 * * * root /usr/local/sbin/opencloud-backup` is a reasonable crontab line. Without some schedule, the `backup_stale` alarm has nothing to watch.

## What is backed up
"Back up now" (console → Backups) creates an encrypted restic snapshot of:
- `apps/` (app config, releases), `data/` (every app's `/data`), `secrets/`, `caddy/`, `audit/`
- `storage/` (object storage files, copied while running, see below)
- `backups/postgres/`: a `pg_dumpall` of every app database, taken just before the snapshot

Raw Postgres data directories are not backed up; the dumps are. Old snapshots are pruned to
`OC_BACKUP_KEEP_DAILY` (default 7).

Deleting an app can also write a one-app folder `$OC_ROOT/backups/deleted/<name>-<time>/` (mode 0700). That folder is the final backup from **Delete app**: `app.json`, `database.sql` (`pg_dump` of that app only), `buckets/<bucket>/` (one file per object key), and `data/`. It is not inside the restic repository. Secret files are not in it. Copy it off the machine the same way if you might restore that app later. A folder ending in `-incomplete`, with an `INCOMPLETE` file inside, is a backup that did not finish. The app was not deleted. Do not treat that folder as a complete copy.

The repository is `$OC_ROOT/backups/restic` and its password is `$OC_ROOT/secrets/platform/restic-password`.
**Both are on the same disk.** Copy them elsewhere, or a dead disk takes the backups with it:
```bash
sudo rsync -a $OC_ROOT/backups/restic/ user@backup.example.com:open-cloud-backup/
sudo cat $OC_ROOT/secrets/platform/restic-password   # store this in your password manager
```

## Running restic
Restic is inside the agent container, so you don't need to install it. In the repo directory:
```bash
set -a; . ./.env; set +a
r() { sudo docker exec -e RESTIC_REPOSITORY=$OC_ROOT/backups/restic \
        -e RESTIC_PASSWORD_FILE=$OC_ROOT/secrets/platform/restic-password oc-agent restic "$@"; }
r snapshots                                   # list; pick an ID (or use "latest")
r restore latest --target /tmp/restore        # files land in the agent at /tmp/restore$OC_ROOT/...
```
`$OC_ROOT` is mounted at the same path in the agent, so you can restore straight into a scratch
folder under it instead: `r restore latest --target $OC_ROOT/restore-scratch`.

## Restore one app's files
```bash
r restore latest --target $OC_ROOT/restore-scratch --include $OC_ROOT/data/<app>
sudo rsync -a --delete $OC_ROOT/restore-scratch$OC_ROOT/data/<app>/ $OC_ROOT/data/<app>/
sudo ./opencloud status    # then Redeploy in the console; it re-applies ownership to the app's user
```

## Restore a database
Load the dump into the app's Postgres. Drop the current database first; the dump recreates it with its tables:
```bash
r restore latest --target $OC_ROOT/restore-scratch --include $OC_ROOT/backups/postgres
sudo docker exec oc-app-<app>-db-1 psql -U app -d postgres -c 'DROP DATABASE IF EXISTS app WITH (FORCE)'
sudo cat $OC_ROOT/restore-scratch$OC_ROOT/backups/postgres/oc-app-<app>-db-1.sql \
  | sudo docker exec -i oc-app-<app>-db-1 psql -U app -d postgres
```
Errors like "role app already exists" are expected and harmless. To check a dump without
touching the live database, load it into a throwaway container instead
(`docker run -d --name pgcheck --network none -e POSTGRES_PASSWORD=x postgres:17-alpine`).

## Restore object storage
Object storage files are copied while SeaweedFS is running. That's **best effort**: objects
written during the backup may be missing from it, but the tests check that the restored store
starts healthy and every object that is present is intact. For a guaranteed-consistent copy,
`docker stop oc-storage` before "Back up now" and start it afterwards.
```bash
r restore latest --target $OC_ROOT/restore-scratch --include $OC_ROOT/storage
sudo docker stop oc-storage
sudo rsync -a --delete $OC_ROOT/restore-scratch$OC_ROOT/storage/ $OC_ROOT/storage/
sudo docker start oc-storage
```
Bucket keys live in `secrets/storage/s3.json`. Restore that too if the keys changed since the backup.

## Rebuild a whole machine
1. New machine: install Docker, clone your fork, copy your old `.env`, run `sudo ./install.sh`.
2. `sudo docker compose stop console agent storage`
3. Copy the restic repo back to `$OC_ROOT/backups/restic`, and put your saved password in
   `$OC_ROOT/secrets/platform/restic-password` (overwrite the newly generated one).
4. `sudo docker compose start agent`, then `r restore latest --target /` (this writes every backed-up path back under `$OC_ROOT`).
5. Fix file owners and restart everything: `sudo ./install.sh && sudo docker compose restart`.
6. Bring back each app: in the console open it and **Redeploy** (rebuilds from Git; if it has a
   database, load its dump as above).
7. Point DNS at the new machine.

Clean-machine rebuilds are documented but **not yet tested end to end** (see the fresh-VM checklist).
`tests/e2e.sh` tests file, database and object storage restores on a running install.
