# Prepare your app for Open Cloud

The console has the same guide under **App Runner → Prepare your app** (`/guide`).

## 1. What the repo needs
- A public HTTPS Git URL with a **`Dockerfile` at the repo root**. App Runner builds it as is, with no build args.
- The app **listens on `$PORT`**. That's the port you enter when you create the app (default 8080), and it's
  set as the environment variable `PORT`. Listen on `0.0.0.0`, not `127.0.0.1`.
- A cheap **health path** (e.g. `GET /health` → 200). Set it under Open ELB → your route. Until you do,
  the console's health column probes `/`.
- Plain HTTP inside the container. TLS is handled by the edge.
- Optional, recommended: an **`opencloud.json`** next to the Dockerfile (or the same keys in the app's `app.json`):
  ```json
  {"health": {"path": "/health", "tool": "python"}, "read_only": true, "tmpfs": ["/tmp"]}
  ```
  `tool` is what the image has for the check: `python`, `node` or `wget`. With `health`, deploys wait until the app
  is healthy. `read_only` makes the root filesystem read-only; list writable scratch paths under `tmpfs` (64 MB each).
  Test it first: some images write at startup (for example nginx needs `/var/cache/nginx` and `/var/run`).
- Schema changes: run them as the owner role, e.g. `docker exec -i oc-app-<app>-db-1 psql -U app -d app < migration.sql`.
  The app's own role can read and write rows but can't create or alter tables.

## 2. Steps
1. **Create the app.** App Runner → name + repo URL + port → **Deploy**. New apps are **Internal** (no public address) unless you choose **External** (`https://<name>.<apps domain>`). See [DEPLOY.md](DEPLOY.md).
2. **Add what it needs** on the service page: **Create Postgres database**, **Create bucket**, **Enable Open Bedrock**,
   and **Save secret** for your own settings. Each of these restarts the app with the new values. No rebuild needed.
3. **Deploy again** (Redeploy) whenever you push code. **Roll back** returns to the previous image. The deployer does both.
4. **Delete** on the service page removes the app (containers, route, database, bucket, secrets, and files). Type the app name. Leave the backup box ticked unless you have already copied what you need. See [DEPLOY.md](DEPLOY.md).

## 3. How values arrive: files, not environment variables
Everything except `PORT` arrives as a **file**: `/run/secrets/<NAME>`. The file holds the value, with no trailing newline.

| Feature | File in `/run/secrets/` | Value |
|---|---|---|
| Postgres | `DATABASE_URL` | `postgresql://app_runtime:<password>@db:5432/app` (non-superuser; DML only) |
| Bucket | `S3_ENDPOINT` | `http://storage:8333` (use from inside the app) |
| | `S3_PUBLIC_ENDPOINT` | `https://<s3 host>` (use for presigned URLs that browsers open) |
| | `S3_ACCESS_KEY_ID`, `S3_SECRET_ACCESS_KEY` | this app's key (works only on this app's buckets) |
| Open Bedrock | `LLM_GATEWAY_URL` | `http://llm-gateway:8000/v1` (OpenAI-compatible base URL) |
| | `LLM_GATEWAY_KEY` | this app's gateway key |
| Your secrets | `<NAME>` | whatever you saved |

**Not injected:** the bucket *name* (you choose it, so save it as a secret like `S3_BUCKET` if you want it
configurable) and the Open Bedrock *endpoint names* (created on the Open Bedrock page, e.g. `chat-fast`; use one as
`model`). The endpoint must list your app under "enabled apps", or calls return 404.
S3 notes: use **path-style** addressing and any region (e.g. `us-east-1`).

## 4. Reading them
Python:
```python
from pathlib import Path
def secret(name, default=None):
    p = Path("/run/secrets") / name
    return p.read_text() if p.exists() else default

import os, psycopg, boto3
from botocore.config import Config
from openai import OpenAI
port = int(os.environ["PORT"])
db = psycopg.connect(secret("DATABASE_URL"))
s3 = boto3.client("s3", endpoint_url=secret("S3_ENDPOINT"), region_name="us-east-1",
                  aws_access_key_id=secret("S3_ACCESS_KEY_ID"), aws_secret_access_key=secret("S3_SECRET_ACCESS_KEY"),
                  config=Config(s3={"addressing_style": "path"}))
llm = OpenAI(base_url=secret("LLM_GATEWAY_URL"), api_key=secret("LLM_GATEWAY_KEY"))
reply = llm.chat.completions.create(model="chat-fast", messages=[{"role": "user", "content": "hi"}])
```
Node:
```js
const fs = require("fs");
const secret = (n, d) => { try { return fs.readFileSync(`/run/secrets/${n}`, "utf8"); } catch { return d; } };
const port = Number(process.env.PORT);
const { Pool } = require("pg");               const db = new Pool({ connectionString: secret("DATABASE_URL") });
const { S3Client } = require("@aws-sdk/client-s3");
const s3 = new S3Client({ endpoint: secret("S3_ENDPOINT"), region: "us-east-1", forcePathStyle: true,
  credentials: { accessKeyId: secret("S3_ACCESS_KEY_ID"), secretAccessKey: secret("S3_SECRET_ACCESS_KEY") } });
const OpenAI = require("openai");
const llm = new OpenAI({ baseURL: secret("LLM_GATEWAY_URL"), apiKey: secret("LLM_GATEWAY_KEY") });
```

## 5. My app expects other names (or environment variables)
- **Different names:** save extra secrets with the names your app wants, e.g. `DB_HOST=db`, `DB_PORT=5432`,
  `DB_USER=app_runtime`, `DB_NAME=app`. The database password is only inside `DATABASE_URL`, and secrets are write-only, so
  parse it from that file rather than re-typing it. Schema changes still use the owner role `app` inside the database container ([DATABASES.md](DATABASES.md)).
- **Must be environment variables:** export the files in a small entrypoint script:
  ```sh
  #!/bin/sh
  for f in /run/secrets/*; do export "$(basename "$f")=$(cat "$f")"; done
  exec "$@"
  ```
  In the Dockerfile: `COPY entrypoint.sh /entrypoint.sh` and `ENTRYPOINT ["/entrypoint.sh"]`, then keep your `CMD`.
  (This needs a shell in the image, so not `scratch`.)

## 6. Persistent files: `/data`
`/data` survives redeploys and rollbacks and is included in backups. It's owned by the user your image runs as
(`USER` in the Dockerfile), including files restored from a backup. Everything outside `/data` is reset on every deploy.

## 7. Troubleshooting

Install, certificates, and login: [TROUBLESHOOTING.md](TROUBLESHOOTING.md).

- **Build failed:** the job page (Deployments) shows the end of the build log. The Dockerfile must be at the root.
  Builds run with limited memory/CPU (`OC_BUILD_MEMORY`/`OC_BUILD_CPUS`).
- **Deployed but 502 / unhealthy:** the app isn't listening on `$PORT` on `0.0.0.0`, or crashed. Check **Logs** on the service page.
- **Killed / restarting:** raise memory under Resources (default 512 MB).
- **Permission denied on `/data`:** redeploy. Ownership is re-applied to the image's user on every deploy.
- **Secret not found:** secrets and database/bucket/gateway values appear after the action that creates them, and the app is
  restarted automatically. Read them at startup or on each use.
- **Open Bedrock 404:** the endpoint name is wrong, or your app isn't in its enabled apps. **429**: over the endpoint's
  per-app requests/minute.
- **S3 SignatureDoesNotMatch / bucket not found:** use path-style addressing, the internal `S3_ENDPOINT` from inside the app,
  and a bucket that belongs to this app.

## 8. Monitoring and events (Open CloudWatch)
- Nothing to add for metrics or logs: CPU, memory, restarts and health are collected automatically, and stdout/stderr
  become searchable logs. Mark a cheap `GET /health` as a health check in the App Map to also get latency and the `unhealthy` alarm.
- Don't print secrets. Common shapes are redacted before storage, but redaction is pattern-based.
- **Events for your app:** on Open CloudWatch > Event feed, click **Create subscriber key**. Your app then gets
  `/run/secrets/CLOUDWATCH_URL` and `/run/secrets/CLOUDWATCH_KEY`.
  - Python, Server-Sent Events:
    ```python
    req = urllib.request.Request(secret("CLOUDWATCH_URL") + "/v1/stream?topics=alarms,deploys",
                                 headers={"Authorization": "Bearer " + secret("CLOUDWATCH_KEY")})
    for line in urllib.request.urlopen(req):   # "event: alarms" / "data: {...}" lines
        print(line.decode().rstrip())
    ```
  - Webhook to your own app: `POST $CLOUDWATCH_URL/v1/subscriptions {"url": "http://app-<name>:<port>/hook", "topics": ["alarms"]}`.
    Verify `X-OC-Signature` = `sha256=` + HMAC-SHA256(key, `X-OC-Timestamp` + "." + body).
  - Full examples: [examples/cloudwatch-consumer](../examples/cloudwatch-consumer) (Python app, SSE and webhook) and its `node/consumer.js`.
    Details: [MONITORING.md](MONITORING.md).
