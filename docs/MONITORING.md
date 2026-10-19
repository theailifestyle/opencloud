# Open CloudWatch: metrics, logs, alarms, email and an event feed

Open CloudWatch is Open Cloud's equivalent of **CloudWatch / Cloud Monitoring** plus a small **EventBridge / SNS**.
It is one small built-in service (`oc-watch`, Python standard library + SQLite). There's no Prometheus or Grafana.
The console page is **Open CloudWatch**, with tabs for Metrics & alarms, Logs, Email and Event feed.

## How it works
- `oc-watch` has **no Docker socket**. Every `OC_WATCH_INTERVAL` seconds (default 60) it asks the agent for a snapshot
  using its own **read-only token**. That token can call only `GET /watch-stats`, `POST /watch-logs`, `GET|POST /audit`
  and `GET /jobs` on the agent. It can't deploy, change secrets or read app secrets.
- All data lives in `$OC_ROOT/watch/watch.db` (SQLite, owned by the watch user, directory `0700`).
- Retention: metrics and events are kept `OC_WATCH_RETENTION_DAYS` (default 7), logs `OC_WATCH_LOG_RETENTION_DAYS` (default 7).
  Older rows are purged hourly.

## Metrics
Every sample stores:
- **Per app:** CPU % (of the app's CPU limit), memory % (of its memory limit), restart count, healthy (0/1),
  health-check latency (from the App Map checks you mark), and Open Bedrock request count.
- **Host:** disk used %, hours since the last successful backup, and whether the last backup failed.

Charts are flat inline SVG (no JavaScript, no CDN). Ranges: 1 h, 6 h, 24 h, 7 d.

An app counts as **healthy** when its `web` container is running, Docker health is `healthy` or none, and every App Map
health check answered below 400.

## Logs (CloudWatch Logs)
- App containers (`oc-app-*`) and platform containers (`oc-*`) are collected with `docker logs --timestamps --since`,
  at most 2000 lines per container per interval.
- **Search** by app (or all including platform), level (error / warn / info / debug, detected from the text), text
  (literal match, no wildcards) and time (quick ranges, or from/to in UTC).
- **Secrets are redacted before anything is stored:**
  - passwords in connection strings (`postgresql://app:***@db/app`)
  - `NAME=value` / `NAME: value` / JSON pairs whose name contains PASSWORD, SECRET, TOKEN, API_KEY, `_KEY`, DATABASE_URL or AUTHORIZATION
  - `Bearer`/`Basic` credentials
  - `sk-…` provider keys and `AKIA…` cloud keys
  - PEM private keys

  Redaction is pattern-based. A secret printed with no recognizable name or shape (say, a bare random string) is not caught,
  so don't log secrets.

## Alarms
| Type | Fires when | Settings |
|---|---|---|
| `unhealthy` | the app is unhealthy for N minutes | app, N |
| `cpu` / `mem` | CPU / memory % of the limit stays over X for N minutes | app, X, N |
| `disk` | host disk over X % (default 85) | X |
| `backup_failed` | the last backup attempt failed after the last success | (none) |
| `backup_stale` | no successful backup for X hours (default 26) | X |
| `restart_loop` | the app restarted X+ times within the last N minutes (default 3 in 10) | app, X, N |

- States are **OK** and **ALARM**. Every change is written to the alarm history and published on the `alarms` topic.
- Email: an alarm email when a rule enters ALARM, and a **resolved** email when it returns to OK (if the alarm was emailed).
- **Cooldown** (minutes, default 30): no second alarm email for the same rule within the cooldown. The state and events still change.
- Each time a rule starts or stops breaching its threshold, an event is published on the `metrics` topic, even before
  the N minutes are up.

## Email
Set the defaults in `.env` (`OC_SMTP_HOST`, `OC_SMTP_PORT`, `OC_SMTP_TLS` = starttls/ssl/none, `OC_SMTP_USER`,
`OC_SMTP_FROM`, `OC_SMTP_TO`). Settings changed on the console's Email tab override them.

The password is **write-only**. `OC_SMTP_PASSWORD` is moved to `$OC_ROOT/watch/smtp-password` (0600) by
`install.sh`; delete it from `.env` afterwards. The console only shows whether one is set.

**Send test email** sends one immediately and shows whether it worked. The tests use a local mock SMTP server
(`tests/mock_smtp.py`), never a real account.

## Event feed (EventBridge / SNS style)
Topics:
- `alarms`: alarm state changes
- `metrics`: threshold crossings
- `deploys`: deploy, redeploy and rollback jobs (running, succeeded, failed)
- `audit`: console actions on an app

**Subscriber keys.** On Event feed, click **Create subscriber key** for an app. The key is stored by the watch service and
delivered to the app as two secrets: `/run/secrets/CLOUDWATCH_URL` (`http://cloudwatch:8100`) and
`/run/secrets/CLOUDWATCH_KEY`. Creating or rotating a key restarts the app. The key is never shown.

**Scope.** An app only ever sees events about itself. Host-level events (disk, backups) and other apps' events are admin-only.

API (send `Authorization: Bearer <CLOUDWATCH_KEY>`), reachable only on the internal network:
| Call | What |
|---|---|
| `GET /v1/stream?topics=alarms,deploys` | Server-Sent Events. Send `Last-Event-ID` to resume, and the backlog since that id is replayed. Pings every 15 s. |
| `GET /v1/events?topics=…&after=ID` | Poll as JSON (max 100 per call). |
| `POST /v1/subscriptions` `{"url": "http://app-<you>:<port>/hook", "topics": ["alarms"]}` | Webhook. URLs must point at your own app on the internal network (no other hosts, no query strings). At most 10. |
| `GET /v1/subscriptions`, `POST /v1/subscriptions/delete {"id": N}` | List or remove. |

**Webhooks** are `POST`ed as JSON `{"id", "topic", "ts", "data"}` with these headers:
- `X-OC-Timestamp`
- `X-OC-Signature: sha256=HMAC_SHA256(CLOUDWATCH_KEY, timestamp + "." + body)`
- `X-OC-Topic`
- `X-OC-Event-Id`

Verify the signature, and reject timestamps older than 5 minutes. A non-2xx answer is retried after 2, 4, 8 and 16 s
(5 attempts), then marked failed (visible on the Event feed tab).

Examples (the e2e test runs all three paths):
- [examples/cloudwatch-consumer](../examples/cloudwatch-consumer): a deployable Python app (standard library only). It
  follows the SSE stream, registers a webhook from the `WEBHOOK_URL` secret, verifies signatures, and shows what arrived at `GET /received`.
- [examples/cloudwatch-consumer/node/consumer.js](../examples/cloudwatch-consumer/node/consumer.js): a dependency-free Node SSE consumer.

## Audit
Every change made in the console is audit-logged without secret values: SMTP settings (`password=changed|unchanged|cleared`),
alarm creation and deletion, and subscriber key creation, rotation and revocation. So are apps creating or deleting webhook subscriptions.

## Not there yet
- One instance and one SQLite file. There's no high availability, and metrics are not exported to other tools.
- Charts are per app and per metric. There are no custom dashboards or metric math.
- Email is the only notification channel. Slack and SMS would subscribe through the webhook feed.
- No scheduled backups are built in yet, so `backup_stale` only helps if you run backups (console "Back up now", or a cron job calling it).
