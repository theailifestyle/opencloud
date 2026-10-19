"""Open CloudWatch: metrics, logs, alarms, email and an app event feed in one small service.

Reads platform state from the agent with a read-only token, keeps everything in one SQLite file,
and serves two APIs on :8100. The admin API (console only, watch token) lives under /admin. The subscriber API
(per-app key) under /v1 is reachable by apps as http://cloudwatch:8100.
"""
import hashlib, hmac, json, os, re, secrets, smtplib, sqlite3, threading, time, urllib.error, urllib.request
from email.message import EmailMessage
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs

TOPICS = ("alarms", "metrics", "deploys", "audit")
KINDS = {"unhealthy": None, "cpu": 80.0, "mem": 80.0, "disk": 85.0, "backup_failed": None, "backup_stale": 26.0, "restart_loop": 3.0}
APP_KINDS = {"unhealthy", "cpu", "mem", "restart_loop"}
NAME = re.compile(r"^[a-z][a-z0-9-]{1,30}$")
MAX_ATTEMPTS = 5
LOCK = threading.RLock()


class Bad(Exception):
    pass


# ---- redaction and parsing -------------------------------------------------

REDACT = [
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?(-----END [A-Z ]*PRIVATE KEY-----|$)", re.S), "[redacted key block]"),
    (re.compile(r"\b([a-z][a-z0-9+.-]*://[^:/\s@]+):[^@\s]+@", re.I), r"\1:***@"),
    (re.compile(r"\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]{8,}", re.I), r"\1 ***"),
    (re.compile(r"""(["']?)\b([\w-]*(?:password|passwd|pwd|secret|token|api[_-]?key|_key|database_url|authorization)[\w-]*)\1\s*[=:]\s*("[^"]*"|'[^']*'|\S+)""", re.I), r"\1\2\1=***"),
    (re.compile(r"\bsk-[A-Za-z0-9_-]{16,}"), "sk-***"),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "AKIA***"),
]
LEVELS = [("error", re.compile(r"\b(error|err|fatal|critical|panic|traceback|exception)\b", re.I)),
          ("warn", re.compile(r"\bwarn(ing)?\b", re.I)), ("debug", re.compile(r"\bdebug\b", re.I))]


def redact(text):
    for rx, rep in REDACT:
        text = rx.sub(rep, text)
    return text


def parse_level(text):
    return next((lv for lv, rx in LEVELS if rx.search(text)), "info")


# ---- storage ---------------------------------------------------------------

SCHEMA = """
create table if not exists metrics (ts integer, scope text, name text, value real);
create index if not exists metrics_i on metrics (scope, name, ts);
create table if not exists logs (ts real, app text, container text, level text, text text);
create index if not exists logs_i on logs (ts);
create table if not exists rules (id integer primary key, name text, kind text, target text, threshold real, minutes real,
  cooldown real, state text default 'OK', breach_since real, since real, last_notified real, notified integer default 0, value real);
create table if not exists history (id integer primary key, ts real, rule_id integer, name text, state text, value real, reason text);
create table if not exists events (id integer primary key, ts real, topic text, app text, data text);
create table if not exists keys (app text primary key, key text, hash text, created real);
create table if not exists subs (id integer primary key, app text, url text, topics text, created real);
create table if not exists deliveries (id integer primary key, sub_id integer, event_id integer, attempts integer default 0,
  next_try real, status text default 'pending', last_code integer);
create table if not exists settings (k text primary key, v text);
"""


def open_db(path):
    db = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
    db.row_factory = sqlite3.Row
    if path != ":memory:":
        db.execute("pragma journal_mode=wal")
    db.executescript(SCHEMA)
    return db


def setting(db, k, default=None):
    r = db.execute("select v from settings where k=?", (k,)).fetchone()
    return json.loads(r["v"]) if r else default


def set_setting(db, k, v):
    db.execute("insert or replace into settings values (?, ?)", (k, json.dumps(v)))


def record_metrics(db, ts, samples):
    with LOCK:
        db.executemany("insert into metrics values (?, ?, ?, ?)", [(int(ts), s, n, float(v)) for s, n, v in samples])


def series(db, scope, name, since):
    return [(r[0], r[1]) for r in db.execute("select ts, value from metrics where scope=? and name=? and ts>=? order by ts", (scope, name, since))]


def purge(db, now, metric_days=7, log_days=7):
    with LOCK:
        db.execute("delete from metrics where ts < ?", (now - metric_days * 86400,))
        db.execute("delete from events where ts < ?", (now - metric_days * 86400,))
        db.execute("delete from deliveries where status != 'pending' and event_id not in (select id from events)")
        db.execute("delete from logs where ts < ?", (now - log_days * 86400,))


def ingest_logs(db, lines):
    """Every line is redacted before it is stored. Raw text never reaches the database."""
    rows = []
    for x in lines:
        t = redact(str(x["text"])[:4000])
        rows.append((float(x["ts"]), x.get("app", ""), x.get("container", ""), parse_level(t), t))
    with LOCK:
        db.executemany("insert into logs values (?, ?, ?, ?, ?)", rows)


def query_logs(db, app=None, level=None, q=None, since=None, until=None, limit=200):
    sql, args = "select ts, app, container, level, text from logs where 1=1", []
    for cond, val in (("app=?", app), ("level=?", level), ("ts>=?", since), ("ts<=?", until)):
        if val not in (None, ""):
            sql += " and " + cond
            args.append(val)
    if q:
        sql += " and text like ? escape '\\'"
        args.append("%" + q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%")
    sql += " order by ts desc limit ?"
    args.append(max(1, min(int(limit), 1000)))
    with LOCK:
        return [dict(r) for r in db.execute(sql, args)]


# ---- alarms ----------------------------------------------------------------

def save_rule(db, r):
    kind = r.get("kind")
    name = str(r.get("name", "")).strip()
    if kind not in KINDS:
        raise Bad("unknown alarm type")
    if not 1 <= len(name) <= 60 or not name.isprintable():
        raise Bad("alarm name: 1-60 printable characters")
    target = str(r.get("target", "") or "")
    if kind in APP_KINDS and not NAME.match(target):
        raise Bad("this alarm type needs an app name")
    if kind not in APP_KINDS:
        target = ""
    try:
        threshold = float(r["threshold"]) if r.get("threshold") not in (None, "") else KINDS[kind]
        minutes = float(r.get("minutes") or (10 if kind == "restart_loop" else 0))
        cooldown = float(r.get("cooldown") or 30)
    except (TypeError, ValueError):
        raise Bad("threshold, minutes and cooldown must be numbers")
    if minutes < 0 or cooldown < 0 or minutes > 1440 or cooldown > 10080:
        raise Bad("minutes 0-1440, cooldown 0-10080")
    with LOCK:
        db.execute("insert into rules (name, kind, target, threshold, minutes, cooldown, state, since) values (?, ?, ?, ?, ?, ?, 'OK', ?)",
                   (name, kind, target, threshold, minutes, cooldown, time.time()))


def delete_rule(db, rid):
    with LOCK:
        db.execute("delete from rules where id=?", (int(rid),))


def rules(db):
    with LOCK:
        return [dict(r) for r in db.execute("select * from rules order by id")]


def history(db, limit=50):
    with LOCK:
        return [dict(r) for r in db.execute("select * from history order by id desc limit ?", (limit,))]


def describe(r):
    t, th, m, k = r["target"], r["threshold"] or 0, r["minutes"] or 0, r["kind"]
    if k == "unhealthy":
        return f"{t} unhealthy for {m:g} min"
    if k in ("cpu", "mem"):
        return f"{t} {'CPU' if k == 'cpu' else 'memory'} > {th:g}% for {m:g} min"
    if k == "disk":
        return f"disk > {th:g}%"
    if k == "backup_failed":
        return "last backup failed"
    if k == "backup_stale":
        return f"no successful backup for {th:g} h"
    return f"{t} restarted {th:g}+ times in {m:g} min"


def check(db, r, snap, now):
    """Returns (breaching, value). breaching is None when there is no data."""
    app = snap.get("apps", {}).get(r["target"]) if r["target"] else None
    k, th, bk = r["kind"], r["threshold"], snap.get("backup", {})
    if k in APP_KINDS and app is None:
        return None, None
    if k == "unhealthy":
        return not app["healthy"], 0.0 if app["healthy"] else 1.0
    if k in ("cpu", "mem"):
        return app[k] > th, app[k]
    if k == "disk":
        return snap["disk_pct"] > th, snap["disk_pct"]
    if k == "backup_failed":
        return (bk.get("last_failure") or 0) > (bk.get("last_success") or 0), float(bk.get("last_failure") or 0)
    if k == "backup_stale":
        age = (now - bk["last_success"]) / 3600 if bk.get("last_success") else float("inf")
        return age > th, age if age != float("inf") else -1.0
    if k == "restart_loop":
        start = now - r["minutes"] * 60
        row = db.execute("select value from metrics where scope=? and name='restarts' and ts<=? order by ts desc limit 1", (f"app:{r['target']}", start)).fetchone()
        base = row[0] if row else db.execute("select min(value) from metrics where scope=? and name='restarts' and ts>?", (f"app:{r['target']}", start)).fetchone()[0]
        if base is None:
            return None, None
        inc = app["restarts"] - base
        return inc >= th, float(inc)
    return None, None


def evaluate(db, now, snap, publish, notify):
    """OK/ALARM state machine per rule: breach for `minutes` -> ALARM; recovery -> OK and a 'resolved' email.
    Alarm emails within `cooldown` minutes of the previous one are suppressed (state and events still change)."""
    with LOCK:
        for r in rules(db):
            breach, value = check(db, r, snap, now)
            if breach is None:
                continue
            was = r["breach_since"] is not None
            bs = (r["breach_since"] if was else now) if breach else None
            if breach != was:
                publish("metrics", {"app": r["target"], "rule": r["name"], "kind": r["kind"], "breaching": breach, "value": value, "condition": describe(r)})
            state, notified, last = r["state"], r["notified"], r["last_notified"]
            wait = 0 if r["kind"] == "restart_loop" else r["minutes"] * 60  # restart_loop: minutes is the counting window
            new = "ALARM" if breach and now - bs >= wait else "OK" if not breach else state
            if new != state:
                reason = describe(r) + (f" (value {value:.4g})" if value is not None else "")
                db.execute("insert into history (ts, rule_id, name, state, value, reason) values (?, ?, ?, ?, ?, ?)", (now, r["id"], r["name"], new, value, reason))
                publish("alarms", {"app": r["target"], "rule": r["name"], "kind": r["kind"], "state": new, "previous": state, "value": value, "reason": reason})
                if new == "ALARM":
                    notified = 0
                    if last is None or now - last >= r["cooldown"] * 60:
                        notify(f"[ALARM] {r['name']}", f"{reason}\nTime: {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime(now))}")
                        notified, last = 1, now
                elif notified:
                    notify(f"[RESOLVED] {r['name']}", f"{describe(r)} is back to OK.\nTime: {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime(now))}")
                    notified = 0
                since = now
            else:
                since = r["since"]
            db.execute("update rules set state=?, breach_since=?, since=?, notified=?, last_notified=?, value=? where id=?",
                       (new, bs, since, notified, last, value, r["id"]))


# ---- pub/sub ---------------------------------------------------------------

def publish(db, topic, data):
    with LOCK:
        cur = db.execute("insert into events (ts, topic, app, data) values (?, ?, ?, ?)", (time.time(), topic, data.get("app") or "", json.dumps(data)))
        eid = cur.lastrowid
        if data.get("app"):
            for s in db.execute("select id, topics from subs where app=?", (data["app"],)).fetchall():
                if topic in s["topics"].split(","):
                    db.execute("insert into deliveries (sub_id, event_id, next_try) values (?, ?, 0)", (s["id"], eid))
        return eid


def events_for(db, app, topics, after, limit=100):
    """Apps only ever see events about themselves; host-level events (no app) are admin-only."""
    topics = [t for t in topics if t in TOPICS]
    if not app or not topics:
        return []
    with LOCK:
        rows = db.execute(f"select * from events where app=? and id>? and topic in ({','.join('?' * len(topics))}) order by id limit ?", (app, int(after), *topics, limit))
        return [{"id": r["id"], "ts": r["ts"], "topic": r["topic"], "data": json.loads(r["data"])} for r in rows]


def recent_events(db, limit=30):
    with LOCK:
        return [{"id": r["id"], "ts": r["ts"], "topic": r["topic"], "app": r["app"], "data": json.loads(r["data"])}
                for r in db.execute("select * from events order by id desc limit ?", (limit,))]


def create_key(db, app):
    if not NAME.match(app or ""):
        raise Bad("invalid app name")
    k = "ocw_" + secrets.token_urlsafe(32)
    with LOCK:
        db.execute("insert or replace into keys values (?, ?, ?, ?)", (app, k, hashlib.sha256(k.encode()).hexdigest(), time.time()))
    return k


def revoke_key(db, app):
    with LOCK:
        db.execute("delete from keys where app=?", (app,))
        for s in db.execute("select id from subs where app=?", (app,)).fetchall():
            db.execute("delete from deliveries where sub_id=?", (s["id"],))
        db.execute("delete from subs where app=?", (app,))


def key_app(db, key):
    with LOCK:
        r = db.execute("select app from keys where hash=?", (hashlib.sha256((key or "").encode()).hexdigest(),)).fetchone()
    return r["app"] if r else None


def sign(key, ts, body):
    return "sha256=" + hmac.new(key.encode(), ts.encode() + b"." + body, hashlib.sha256).hexdigest()


def verify(key, ts, body, sig):
    return hmac.compare_digest(sign(key, ts, body), sig or "")


def webhook_ok(app, url):
    """Webhooks may only target the subscribing app itself on the internal network (no SSRF)."""
    return bool(re.fullmatch(rf"http://app-{re.escape(app)}:[0-9]{{2,5}}(/[A-Za-z0-9._~/-]*)?", url or ""))


def subscribe(db, app, url, topics):
    topics = sorted({t for t in topics if t in TOPICS})
    if not webhook_ok(app, url):
        raise Bad(f"webhook URL must be http://app-{app}:<port>/<path> (your own app, internal network)")
    if not topics:
        raise Bad(f"topics: any of {', '.join(TOPICS)}")
    with LOCK:
        if db.execute("select count(*) from subs where app=?", (app,)).fetchone()[0] >= 10:
            raise Bad("at most 10 webhook subscriptions per app")
        return db.execute("insert into subs (app, url, topics, created) values (?, ?, ?, ?)", (app, url, ",".join(topics), time.time())).lastrowid


def deliver(db, now, post):
    """Send due webhook deliveries; on failure retry with backoff 2, 4, 8, 16 s, then give up."""
    with LOCK:
        due = db.execute("""select d.id, d.attempts, s.url, s.app, e.id eid, e.topic, e.ts, e.data, k.key from deliveries d
            join subs s on s.id=d.sub_id join events e on e.id=d.event_id join keys k on k.app=s.app
            where d.status='pending' and d.next_try<=? order by d.id limit 20""", (now,)).fetchall()
    for d in due:
        body = json.dumps({"id": d["eid"], "topic": d["topic"], "ts": d["ts"], "data": json.loads(d["data"])}).encode()
        ts = str(int(now))
        try:
            code = post(d["url"], body, {"Content-Type": "application/json", "X-OC-Topic": d["topic"], "X-OC-Event-Id": str(d["eid"]),
                                         "X-OC-Timestamp": ts, "X-OC-Signature": sign(d["key"], ts, body)})
        except OSError:
            code = None
        n = d["attempts"] + 1
        status = "done" if code and 200 <= code < 300 else "failed" if n >= MAX_ATTEMPTS else "pending"
        with LOCK:
            db.execute("update deliveries set attempts=?, status=?, next_try=?, last_code=? where id=?", (n, status, now + 2 ** n, code, d["id"]))


def audit_app(entry):
    t = entry.get("target", "")
    m = re.match(r"/apps/([a-z][a-z0-9-]{1,30})(/|$| )", t) or (re.match(r"/apps name=([a-z][a-z0-9-]{1,30})\b", t))
    return m.group(1) if m else ""


# ---- service ---------------------------------------------------------------

AGENT = os.environ.get("OC_AGENT_URL", "http://agent:7000")
DATA = Path(os.environ.get("OC_WATCH_DATA", "/var/lib/watch"))
INTERVAL = int(os.environ.get("OC_WATCH_INTERVAL", "60"))
RETENTION = float(os.environ.get("OC_WATCH_RETENTION_DAYS", "7"))
LOG_RETENTION = float(os.environ.get("OC_WATCH_LOG_RETENTION_DAYS", "7"))
SMTP_KEYS = ("host", "port", "user", "from", "to", "tls")
DB = None
TOKEN = ""


def agent(method, path, body=None):
    req = urllib.request.Request(AGENT + path, method=method, data=json.dumps(body).encode() if body is not None else None,
                                 headers={"Authorization": "Bearer " + TOKEN, "Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=60) as r:
        return json.loads(r.read())


def smtp_settings():
    env = {k: os.environ.get(f"OC_SMTP_{k.upper()}", "") for k in SMTP_KEYS}
    env["port"] = env["port"] or "587"
    env["tls"] = env["tls"] or "starttls"
    return {**env, **setting(DB, "smtp", {})}


def smtp_password_file():
    return DATA / "smtp-password"


def send_mail(subject, body):
    s = smtp_settings()
    if not s["host"] or not s["to"]:
        raise Bad("email is not configured (SMTP host and recipient)")
    msg = EmailMessage()
    msg["Subject"], msg["From"], msg["To"] = subject, s["from"] or "open-cloud@localhost", s["to"]
    msg.set_content(body + "\n\n-- Open CloudWatch")
    pw = smtp_password_file().read_text() if smtp_password_file().exists() else ""
    cls = smtplib.SMTP_SSL if s["tls"] == "ssl" else smtplib.SMTP
    with cls(s["host"], int(s["port"]), timeout=15) as c:
        if s["tls"] == "starttls":
            c.starttls()
        if s["user"]:
            c.login(s["user"], pw)
        c.send_message(msg)


def notify(subject, body):
    try:
        send_mail(subject, body)
        set_setting(DB, "last_email", {"ts": time.time(), "subject": subject, "ok": True})
    except (Bad, OSError, smtplib.SMTPException) as e:
        set_setting(DB, "last_email", {"ts": time.time(), "subject": subject, "ok": False, "error": str(e)[:200]})


def pub(topic, data):
    publish(DB, topic, data)


def observed_samples(s):
    """Metrics for containers Open Cloud only observes (OC_OBSERVE=1), scoped observed:<name>."""
    out = []
    for c in s.get("observed") or []:
        sc = "observed:" + c["name"]
        healthy = c["status"] == "running" and c["health"] in ("healthy", "none")
        out += [(sc, "cpu", c["cpu"]), (sc, "mem", c["mem"]), (sc, "restarts", c["restarts"]), (sc, "healthy", 1.0 if healthy else 0.0)]
    return out


def collect_once(now):
    s = agent("GET", "/watch-stats")
    samples = [("host", "disk_pct", s["disk_pct"])]
    bk = s["backup"]
    samples.append(("host", "backup_failed", 1.0 if (bk.get("last_failure") or 0) > (bk.get("last_success") or 0) else 0.0))
    if bk.get("last_success"):
        samples.append(("host", "backup_age_h", (now - bk["last_success"]) / 3600))
    for n, a in s["apps"].items():
        samples += [(f"app:{n}", "cpu", a["cpu"]), (f"app:{n}", "mem", a["mem"]), (f"app:{n}", "restarts", a["restarts"]), (f"app:{n}", "healthy", 1.0 if a["healthy"] else 0.0)]
        if a.get("latency_ms") is not None:
            samples.append((f"app:{n}", "latency_ms", a["latency_ms"]))
    req = {}
    for k, u in (s.get("usage") or {}).items():
        app = k.split("|")[-1]
        req[app] = req.get(app, 0) + u.get("requests", 0)
    samples += [(f"app:{a}", "bedrock_requests", v) for a, v in req.items()]
    samples += observed_samples(s)
    with LOCK:
        evaluate(DB, now, s, pub, notify)  # before recording, so restart_loop compares with older samples
        record_metrics(DB, now, samples)
        set_setting(DB, "snapshot", {**s, "ts": now})
    since = setting(DB, "log_since", now - 300)
    lines = agent("POST", "/watch-logs", {"since": since})["lines"]
    if lines:
        ingest_logs(DB, lines)
        with LOCK:
            set_setting(DB, "log_since", max(x["ts"] for x in lines))
    if now - setting(DB, "purged", 0) > 3600:
        purge(DB, now, RETENTION, LOG_RETENTION)
        set_setting(DB, "purged", now)


def events_once():
    a = agent("GET", "/audit")
    seen = setting(DB, "audit_seen", None)
    if seen is None:
        seen = a["count"]  # start the feed now; don't replay history
    new = a["entries"][: max(0, a["count"] - seen)][::-1]
    for x in new:
        pub("audit", {"app": audit_app(x), "event": x["event"], "target": x["target"], "outcome": x["outcome"], "time": x["time"]})
    jobs = setting(DB, "jobs_seen", None)
    current = {j["id"]: j["status"] for j in agent("GET", "/jobs")}
    if jobs is not None:
        for j in agent("GET", "/jobs") if any(jobs.get(i) != st for i, st in current.items()) else []:
            if jobs.get(j["id"]) != j["status"]:
                pub("deploys", {"app": j["app"], "job": j["id"], "kind": j["kind"], "status": j["status"], "error": redact(j.get("error", ""))[:300]})
    with LOCK:
        set_setting(DB, "audit_seen", a["count"])
        set_setting(DB, "jobs_seen", current)


def http_post(url, body, headers):
    req = urllib.request.Request(url, data=body, method="POST", headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status
    except urllib.error.HTTPError as e:
        return e.code


def loop(fn, every):
    def run():
        while True:
            try:
                fn()
            except Exception as e:  # keep the loop alive; the error is visible in the platform logs
                print(f"{fn.__name__}: {type(e).__name__}: {str(e)[:200]}", flush=True)
            time.sleep(every)
    threading.Thread(target=run, daemon=True).start()


def overview(q):
    hours = max(1, min(int(q.get("hours", "6")), int(RETENTION * 24)))
    since = time.time() - hours * 3600
    snap = setting(DB, "snapshot", {})
    with LOCK:
        apps = {n: {m: series(DB, f"app:{n}", m, since) for m in ("cpu", "mem", "latency_ms", "restarts", "bedrock_requests")} for n in snap.get("apps", {})}
        host = {m: series(DB, "host", m, since) for m in ("disk_pct", "backup_age_h")}
        observed = {c["name"]: {m: series(DB, "observed:" + c["name"], m, since) for m in ("cpu", "mem")} for c in snap.get("observed") or []}
        keys = [{"app": r["app"], "created": r["created"]} for r in DB.execute("select app, created from keys order by app")]
        subs = [{**dict(r), "delivered": DB.execute("select count(*) from deliveries where sub_id=? and status='done'", (r["id"],)).fetchone()[0],
                 "failed": DB.execute("select count(*) from deliveries where sub_id=? and status='failed'", (r["id"],)).fetchone()[0]}
                for r in DB.execute("select id, app, url, topics from subs order by id")]
    s = smtp_settings()
    return {"hours": hours, "interval": INTERVAL, "retention_days": RETENTION, "log_retention_days": LOG_RETENTION, "snapshot": snap, "apps": apps, "host": host, "observed": observed,
            "rules": [{**r, "condition": describe(r)} for r in rules(DB)], "history": history(DB), "keys": keys, "subs": subs,
            "events": recent_events(DB), "topics": TOPICS, "smtp": {**s, "password_set": smtp_password_file().exists() and smtp_password_file().stat().st_size > 0},
            "last_email": setting(DB, "last_email")}


def set_smtp(b):
    s = {k: str(b.get(k, "")).strip() for k in SMTP_KEYS}
    if s["host"] and not re.fullmatch(r"[A-Za-z0-9.-]{1,253}", s["host"]):
        raise Bad("invalid SMTP host")
    if not re.fullmatch(r"[0-9]{1,5}", s["port"] or "587"):
        raise Bad("invalid SMTP port")
    if s["tls"] not in ("starttls", "ssl", "none"):
        raise Bad("TLS: starttls, ssl or none")
    for k in ("from", "to", "user"):
        if len(s[k]) > 200 or any(c in s[k] for c in "\r\n"):
            raise Bad(f"invalid {k}")
    pw = str(b.get("password", ""))
    if len(pw) > 500 or "\n" in pw:
        raise Bad("invalid password")
    with LOCK:
        set_setting(DB, "smtp", s)
        if pw or b.get("clear_password"):
            f = smtp_password_file()
            fd = os.open(f, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w") as fh:
                fh.write(pw)
    return {"ok": True}


def smtp_test(b):
    try:
        send_mail("Open CloudWatch test email", "This is a test email from Open CloudWatch. Alarm notifications will arrive like this.")
    except (OSError, smtplib.SMTPException) as e:
        raise Bad(f"sending failed: {type(e).__name__}: {str(e)[:200]}")
    return {"ok": True}


ADMIN = {
    ("GET", "/admin/overview"): lambda b, q: overview(q),
    ("GET", "/admin/logs"): lambda b, q: query_logs(DB, q.get("app"), q.get("level"), q.get("q"), float(q["since"]) if q.get("since") else None,
                                                    float(q["until"]) if q.get("until") else None, int(q.get("limit", "200"))),
    ("POST", "/admin/rules"): lambda b, q: save_rule(DB, b) or {"ok": True},
    ("POST", "/admin/rules-delete"): lambda b, q: delete_rule(DB, b.get("id", 0)) or {"ok": True},
    ("POST", "/admin/smtp"): lambda b, q: set_smtp(b),
    ("POST", "/admin/smtp-test"): lambda b, q: smtp_test(b),
    ("POST", "/admin/keys"): lambda b, q: {"key": create_key(DB, b.get("app", ""))},
    ("POST", "/admin/keys-revoke"): lambda b, q: revoke_key(DB, b.get("app", "")) or {"ok": True},
}


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def reply(self, code, data):
        b = json.dumps(data).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def bearer(self):
        a = self.headers.get("Authorization", "")
        return a[7:] if a.startswith("Bearer ") else ""

    def handle_any(self, method):
        path, _, qs = self.path.partition("?")
        q = {k: v[0] for k, v in parse_qs(qs).items()}
        try:
            n = int(self.headers.get("Content-Length") or 0)
            body = json.loads(self.rfile.read(min(n, 100000)) or b"{}") if method == "POST" else {}
            if path == "/healthz":
                return self.reply(200, {"ok": True})
            if path.startswith("/admin/"):
                if not hmac.compare_digest(self.bearer(), TOKEN):
                    return self.reply(401, {"error": "unauthorized"})
                fn = ADMIN.get((method, path))
                return self.reply(200, fn(body, q)) if fn else self.reply(404, {"error": "not found"})
            app = key_app(DB, self.bearer())
            if not app:
                return self.reply(401, {"error": "unauthorized: send Authorization: Bearer <CLOUDWATCH_KEY>"})
            topics = [t for t in q.get("topics", ",".join(TOPICS)).split(",") if t]
            if (method, path) == ("GET", "/v1/events"):
                return self.reply(200, events_for(DB, app, topics, int(q.get("after", "0") or 0)))
            if (method, path) == ("GET", "/v1/stream"):
                return self.stream(app, topics, int(self.headers.get("Last-Event-ID") or q.get("after") or 0))
            if (method, path) == ("GET", "/v1/subscriptions"):
                with LOCK:
                    return self.reply(200, [dict(r) for r in DB.execute("select id, url, topics from subs where app=?", (app,))])
            if (method, path) == ("POST", "/v1/subscriptions"):
                sid = subscribe(DB, app, str(body.get("url", "")), body.get("topics") or [])
                agent_audit("subscribe", f"app:{app}", f"webhook id={sid} url={body.get('url')} topics={','.join(body.get('topics') or [])}")
                return self.reply(200, {"id": sid})
            if (method, path) == ("POST", "/v1/subscriptions/delete"):
                with LOCK:
                    DB.execute("delete from deliveries where sub_id in (select id from subs where id=? and app=?)", (int(body.get("id", 0)), app))
                    DB.execute("delete from subs where id=? and app=?", (int(body.get("id", 0)), app))
                agent_audit("unsubscribe", f"app:{app}", f"webhook id={body.get('id')}")
                return self.reply(200, {"ok": True})
            self.reply(404, {"error": "not found"})
        except Bad as e:
            self.reply(400, {"error": str(e)})
        except (ValueError, KeyError, TypeError) as e:
            self.reply(400, {"error": f"bad request: {type(e).__name__}"})

    def stream(self, app, topics, after):
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Connection", "close")
        self.end_headers()
        self.close_connection = True
        last_ping = time.time()
        try:
            self.wfile.write(b": connected\n\n")
            self.wfile.flush()
            while True:
                for ev in events_for(DB, app, topics, after):
                    self.wfile.write(sse(ev["id"], ev["topic"], {**ev["data"], "_ts": ev["ts"]}))
                    after = ev["id"]
                self.wfile.flush()
                if time.time() - last_ping > 15:
                    self.wfile.write(b": ping\n\n")
                    self.wfile.flush()
                    last_ping = time.time()
                time.sleep(1)
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass

    def do_GET(self):
        self.handle_any("GET")

    def do_POST(self):
        self.handle_any("POST")

    def log_message(self, fmt, *a):  # method and path only, never headers or bodies
        if self.path == "/healthz":
            return
        print(f"{self.command} {self.path.split('?')[0]} {a[1] if len(a) > 1 else ''}", flush=True)


def sse(eid, topic, data):
    return f"id: {eid}\nevent: {topic}\ndata: {json.dumps(data)}\n\n".encode()


def agent_audit(event, ip, target):
    try:
        agent("POST", "/audit", {"event": event, "ip": ip, "target": target})
    except (OSError, ValueError):
        print("audit append failed", flush=True)


if __name__ == "__main__":
    TOKEN = Path(os.environ.get("OC_WATCH_TOKEN_FILE", "/run/oc/watch-token")).read_text().strip()
    DATA.mkdir(parents=True, exist_ok=True)
    DB = open_db(str(DATA / "watch.db"))
    loop(lambda: collect_once(time.time()), INTERVAL)
    loop(events_once, 3)
    loop(lambda: deliver(DB, time.time(), http_post), 1)
    srv = ThreadingHTTPServer(("0.0.0.0", 8100), Handler)
    srv.daemon_threads = True
    srv.serve_forever()
