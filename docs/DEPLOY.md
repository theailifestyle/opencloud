# Deploy an app

App Runner takes a public Git repository (or, if you allow it, a folder already on the server), builds the Dockerfile, and runs the image. The **deployer** does the build, the start, the stop, and the rollback. You do not SSH in and run Docker yourself.

Open **App Runner** in the console. The same steps, from the app's point of view, are [APP-GUIDE.md](APP-GUIDE.md).

## Create

- **Name**: lowercase letters, digits, hyphens. `console`, `s3`, `storage`, and `llm-gateway` are reserved. A name cannot start with `site-`: that prefix is for hand-written edge files (`caddy/sites/site-*.caddy`) and static sites (`site-static-*.caddy`).
- **Source**: a public `https://` Git URL, plus an optional branch or tag. The Dockerfile is at the repository root unless you give a path such as `backend/Dockerfile`.
- **Port**: the port the process listens on. The container gets that number as the environment variable `PORT`. Default 8080.
- **Visibility**: Internal or External. The default is Internal.

**Deploy** starts a background job. **Deployments** shows the log tail if the build fails. A second deploy of the same app is refused while the first job is still running.

## Internal and External

**Internal** is the default for a new app. The deployer does not write a public route. Nothing on the internet can open it. Other apps on this server reach it at `http://app-<name>:<port>`. Use Internal for workers, databases' companion services, and anything that should not have its own hostname.

**External** is public at `https://<name>.<OC_APPS_DOMAIN>`. With the example config that is `https://my-app.apps.example.com`. The wildcard DNS record covers it. See [DNS.md](DNS.md). Custom domains are added later on the Open ELB page.

You can switch an existing app on its service page. Switching to Internal removes the public route the deployer wrote for that app. Switching to External creates it. A hand-written edge file can still publish an Internal app; that is [OPEN-ELB.md](OPEN-ELB.md#hand-written-sites). Switching to Internal does not delete a route file the deployer did not write.

## After the first deploy

On the service page:

- **Create Postgres database** and **Create bucket** attach those and restart the app with new secret files. No rebuild.
- **Secrets** are write-only names at `/run/secrets/NAME`.
- **Redeploy** builds the current Git revision again.
- **Roll back** starts the previous image. You need two successful deploys before rollback has somewhere to go.
- **Resources** changes memory and CPU (default 512 MB and 1 CPU).

`/data` survives redeploy and rollback. Everything else in the container is replaced.

## Delete

On the service page, **Delete app** asks the deployer to remove that one app. Type the app name to confirm. There is no separate "delete the database" or "delete the bucket" button: deleting the app removes those too.

What is removed:

- The app's containers and its private database network (`oc-app-<name>`)
- Its edge route, when the deployer wrote `caddy/sites/<name>.caddy`. That file starts with `# opencloud:app=<name>`. An older file is removed only when it is still exactly the generated route. The edge is reloaded after a removal.
- Its Postgres data directory and database credentials
- Its buckets and its S3 access key (object storage is restarted when the key changes)
- Its secret files, its managed `/data` directory, and its folder under `apps/`

What is kept:

- Deploy jobs and release records. They stay, and the app is marked deleted. Open CloudWatch metrics, logs, and alarms for the app are kept too. The console revokes that app's CloudWatch subscriber key after a successful delete.
- Host folders and host secret files mounted from outside Open Cloud (`OC_ALLOWED_DATA_ROOTS`, `OC_ALLOWED_SECRET_PATHS`). The page lists them before you confirm, and the result lists them again.
- Hand-written edge files (`site-*.caddy`), a symlinked route file, and any `<name>.caddy` the deployer did not write. Each one is listed and left as it is. A file that still proxies to the app is named in the result.
- Other apps, the shared `sites` bucket, the provider key, and anything outside `$OC_ROOT`

**Take a final backup first** is on unless you untick it. The deployer writes a root-only folder under `$OC_ROOT/backups/deleted/<name>-<time>/` with the app definition (`app.json`), a `pg_dump` of that app's database, a copy of every object in its buckets (keys and paths unchanged), and a copy of managed `/data`. Secret files are not copied. If the backup fails, the app is not deleted. The partial folder is renamed to end with `-incomplete` and contains an `INCOMPLETE` file; it is not a finished backup. The dump runs as the database owner `app`, and only inside the container `oc-app-<name>-db-1` after the deployer has checked that it is this app's Postgres (compose project `oc-app-<name>`, label `opencloud.backup=postgres`, a `postgres` image, and `POSTGRES_USER=app`). The console shows the path when the delete finishes. This folder is not part of the restic snapshot; copy it off the machine if you need it. See [RESTORE.md](RESTORE.md).

A bucket is removed only when this app's key is the only identity with `Read`, `Write`, `List`, `Tagging`, or `Admin` on that bucket. The platform admin key is bare `Admin` and does not count, and neither does a wildcard. The shared `sites` bucket is never removed. An action that does not name a real bucket is ignored.

The deployer refuses the delete while a build or deploy for that app is still running. It also refuses a name that is not an app (no `app.json` and no app folder), unless it already recorded a delete for that name (`releases/<name>/DELETING` or `DELETED`). If a delete stops halfway, run it again: steps that are already done are skipped, and it does not touch the other app. A failed backup stops the delete before anything is removed.

To try it on a server: deploy an app (the examples under `examples/` work), give it a database and a bucket, then open its service page. Leave the backup box ticked, type the app name, and choose **Delete app**. The App Runner page should name a folder under `$OC_ROOT/backups/deleted/`. `sudo ls` that folder (mode 0700) and confirm `app.json`, `database.sql`, `buckets/`, and `data/`. The app should be gone from App Runner, its route file gone, and its containers gone (`sudo docker ps -a --filter name=oc-app-<name>`). The Deployments page still lists its jobs, marked deleted. Calling the deployer again with the same name returns success and does not remove anything else. Untick the backup box on a second app if you want to see a delete that writes no folder.

## Server folder

If the code is already on the server and is not a public Git URL, set `OC_LOCAL_SOURCES` in `.env` to the parent directory and re-run `sudo ./install.sh`. The create form then offers that folder. The deployer copies it into the build. It does not build from a path outside the allowlist. Leave this empty on a fresh install.

## What the app must do

Listen on `0.0.0.0:$PORT` with plain HTTP. Put a cheap `GET /health` in the app if you can. Optional `opencloud.json` next to the Dockerfile:

```json
{"health": {"path": "/health", "tool": "python"}, "read_only": true, "tmpfs": ["/tmp"]}
```

`tool` is `python`, `node`, or `wget`. A copy of that file is [examples/opencloud.json.example](../examples/opencloud.json.example). Working apps: [examples/fastapi-app](../examples/fastapi-app), [examples/express-app](../examples/express-app), [examples/cloudwatch-consumer](../examples/cloudwatch-consumer).

How `DATABASE_URL`, S3 settings, and the other files show up is [APP-GUIDE.md](APP-GUIDE.md).
