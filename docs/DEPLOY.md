# Deploy an app

App Runner takes a public Git repository (or, if you allow it, a folder already on the server), builds the Dockerfile, and runs the image. The **deployer** does the build, the start, the stop, and the rollback. You do not SSH in and run Docker yourself.

Open **App Runner** in the console. The same steps, from the app's point of view, are [APP-GUIDE.md](APP-GUIDE.md).

## Create

- **Name**: lowercase letters, digits, hyphens. `console`, `s3`, `storage`, and `llm-gateway` are reserved.
- **Source**: a public `https://` Git URL, plus an optional branch or tag. The Dockerfile is at the repository root unless you give a path such as `backend/Dockerfile`.
- **Port**: the port the process listens on. The container gets that number as the environment variable `PORT`. Default 8080.
- **Visibility**: Internal or External. The default is Internal.

**Deploy** starts a background job. **Deployments** shows the log tail if the build fails. A second deploy of the same app is refused while the first job is still running.

## Internal and External

**Internal** is the default for a new app. The deployer does not write a public route. Nothing on the internet can open it. Other apps on this server reach it at `http://app-<name>:<port>`. Use Internal for workers, databases' companion services, and anything that should not have its own hostname.

**External** is public at `https://<name>.<OC_APPS_DOMAIN>`. With the example config that is `https://my-app.apps.example.com`. The wildcard DNS record covers it. See [DNS.md](DNS.md). Custom domains are added later on the Open ELB page.

You can switch an existing app on its service page. Switching to Internal removes the public route. Switching to External creates it. A hand-written edge file can still publish an Internal app; that is [OPEN-ELB.md](OPEN-ELB.md#hand-written-sites).

## After the first deploy

On the service page:

- **Create Postgres database** and **Create bucket** attach those and restart the app with new secret files. No rebuild.
- **Secrets** are write-only names at `/run/secrets/NAME`.
- **Redeploy** builds the current Git revision again.
- **Roll back** starts the previous image. You need two successful deploys before rollback has somewhere to go.
- **Resources** changes memory and CPU (default 512 MB and 1 CPU).

`/data` survives redeploy and rollback. Everything else in the container is replaced.

## Server folder

If the code is already on the server and is not a public Git URL, set `OC_LOCAL_SOURCES` in `.env` to the parent directory and re-run `sudo ./install.sh`. The create form then offers that folder. The deployer copies it into the build. It does not build from a path outside the allowlist. Leave this empty on a fresh install.

## What the app must do

Listen on `0.0.0.0:$PORT` with plain HTTP. Put a cheap `GET /health` in the app if you can. Optional `opencloud.json` next to the Dockerfile:

```json
{"health": {"path": "/health", "tool": "python"}, "read_only": true, "tmpfs": ["/tmp"]}
```

`tool` is `python`, `node`, or `wget`. A copy of that file is [examples/opencloud.json.example](../examples/opencloud.json.example). Working apps: [examples/fastapi-app](../examples/fastapi-app), [examples/express-app](../examples/express-app), [examples/cloudwatch-consumer](../examples/cloudwatch-consumer).

How `DATABASE_URL`, S3 settings, and the other files show up is [APP-GUIDE.md](APP-GUIDE.md).
