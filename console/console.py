"""Open Cloud console. One admin login; talks to the agent, never to Docker."""
import base64, calendar, hashlib, hmac, html, json, os, re, secrets, socket, struct, threading, time, urllib.error, urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, quote

AGENT = os.environ.get("OC_AGENT_URL", "http://agent:7000")
WATCH = os.environ.get("OC_WATCH_URL", "http://watch:8100")
APPS_DOMAIN = os.environ.get("OC_APPS_DOMAIN", "localhost")
CONSOLE_HOST = os.environ.get("OC_CONSOLE_HOST", "console.localhost")
PUBLIC_IP = os.environ.get("OC_PUBLIC_IP", "")
SESSION_TTL = 8 * 3600
sessions = {}   # token -> {"csrf": str, "expires": float}
attempts = {}   # ip -> [timestamps]
# Reverse proxies in front of the console (oc-edge or an external Caddy). Each appends the address it saw to
# X-Forwarded-For, so the client's real address is the Nth entry from the right; anything left of it is client-supplied.
OBSERVE = os.environ.get("OC_OBSERVE", "0") == "1"
TRUSTED_PROXIES = int(os.environ.get("OC_TRUSTED_PROXIES", "1"))
# Generic OpenAI-compatible gateway (oc-llm-gateway): optional, off unless OC_GENERIC_GATEWAY=1.
GENERIC_GATEWAY = os.environ.get("OC_GENERIC_GATEWAY", "0") == "1"
def e(v):
    return html.escape(str(v))


def hash_password(pw, salt=None):
    salt = salt or secrets.token_bytes(16)
    d = hashlib.scrypt(pw.encode(), salt=salt, n=2**14, r=8, p=1)
    return f"scrypt${salt.hex()}${d.hex()}"


def verify_password(pw, stored):
    try:
        _, salt, digest = stored.strip().split("$")
        return hmac.compare_digest(hash_password(pw, bytes.fromhex(salt)).split("$")[2], digest)
    except ValueError:
        return False


HASH_FILE = Path(os.environ.get("OC_ADMIN_HASH_FILE", "/run/oc/auth/admin-password.scrypt"))
# Set by install.sh / reset-password: the installer-generated password must be replaced before anything else.
MUST_CHANGE_FILE = Path(os.environ.get("OC_MUST_CHANGE_FILE", str(HASH_FILE.parent / "must-change-password")))
MIN_PASSWORD = 12


def must_change(flag=None):
    return (flag or MUST_CHANGE_FILE).exists()


def allowed_while_must_change(path):
    return path in ("/account/password", "/logout")


def password_problem(current, new, confirm, stored):
    """Why the change is refused, or None. Never echoes the values."""
    if not verify_password(current, stored):
        return "The current password is wrong."
    if len(new) < MIN_PASSWORD:
        return f"The new password needs at least {MIN_PASSWORD} characters."
    if new != confirm:
        return "The two new passwords don't match."
    if new == current:
        return "The new password must be different from the current one."
    return None


def set_password(new, hash_file=None, flag=None):
    """Atomically replace the scrypt hash (0600, same directory), then clear the must-change flag."""
    hash_file, flag = Path(hash_file or HASH_FILE), Path(flag or MUST_CHANGE_FILE)
    h = hash_password(new)
    tmp = hash_file.with_name(hash_file.name + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fh:
        fh.write(h + "\n"); fh.flush(); os.fsync(fh.fileno())
    os.replace(tmp, hash_file)
    flag.unlink(missing_ok=True)
    return h


def totp(secret_b32, counter):
    """RFC 6238 TOTP (SHA-1, 6 digits, 30 s)."""
    key = base64.b32decode(secret_b32.upper() + "=" * (-len(secret_b32) % 8))
    d = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    o = d[-1] & 15
    return f"{(struct.unpack('>I', d[o:o + 4])[0] & 0x7FFFFFFF) % 1000000:06d}"


def verify_totp(secret_b32, code, now=None, last=0):
    """The matching counter (step -1/0/+1) if newer than `last`, else 0. Storing it makes each code work once."""
    step = int((now or time.time()) // 30)
    for c in (step - 1, step, step + 1):
        if c > last and hmac.compare_digest(totp(secret_b32, c), (code or "").strip()):
            return c
    return 0


# Two-step login, set up from the console (/account/2fa). Kept next to the password hash in the console-owned
# auth directory (700, file 600): {"secret": base32, "last": counter, "recovery": [sha256 of unused codes]}.
TOTP_FILE = Path(os.environ.get("OC_TOTP_FILE", str(HASH_FILE.parent / "totp.json")))
totp_lock = threading.Lock()


def load_totp(path=None):
    p = Path(path or TOTP_FILE)
    return json.loads(p.read_text()) if p.exists() else None


def save_totp(data, path=None):
    p = Path(path or TOTP_FILE)
    tmp = p.with_name(p.name + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fh:
        json.dump(data, fh); fh.flush(); os.fsync(fh.fileno())
    os.replace(tmp, p)


def recovery_hash(code):
    return hashlib.sha256(re.sub(r"[^0-9a-f]", "", (code or "").lower()).encode()).hexdigest()


def new_recovery_codes(n=8):
    return [f"{x[:4]}-{x[4:8]}-{x[8:]}" for x in (secrets.token_hex(6) for _ in range(n))]


def second_factor_ok(code, now=None, path=None):
    """True if two-step login is off, or `code` is a fresh TOTP code or an unused recovery code (then used up)."""
    with totp_lock:
        t = load_totp(path)
        if not t:
            return True
        c = verify_totp(t["secret"], (code or "").replace(" ", ""), now, t.get("last", 0))
        if c:
            t["last"] = c
        elif code and recovery_hash(code) in t["recovery"]:
            t["recovery"].remove(recovery_hash(code))
        else:
            return False
        save_totp(t, path)
        return True


def totp_qr(uri):
    import segno  # pinned in the console image; inline SVG, so the secret never leaves this page
    return segno.make(uri, error="m").svg_inline(scale=5, light="#fff")


def audit(event, ip, target="", outcome="ok"):
    try:
        agent("POST", "/audit", {"event": event, "ip": ip, "target": target, "outcome": outcome})
    except (RuntimeError, OSError):
        print("audit append failed", flush=True)


# X-Forwarded-For is trusted only when the TCP peer is the edge proxy itself (resolved by name on the
# console's own network). Anything else, e.g. an app container calling the console directly, is keyed by its
# real address. OC_TRUSTED_PROXY_HOSTS: space-separated names (default oc-edge; external mode: your proxy).
TRUSTED_PROXY_HOSTS = os.environ.get("OC_TRUSTED_PROXY_HOSTS", "oc-edge").split()
_proxy_cache = {"t": 0.0, "ips": set()}


def proxy_ips(now=None):
    now = now or time.time()
    if now - _proxy_cache["t"] > 30:
        ips = set()
        for h in TRUSTED_PROXY_HOSTS:
            try:
                ips.update(socket.gethostbyname_ex(h)[2])
            except OSError:
                pass  # unknown name: trust nobody (fail closed)
        _proxy_cache.update(t=now, ips=ips)
    return _proxy_cache["ips"]


def client_ip(xff, peer, trusted=None, proxies=None):
    trusted = TRUSTED_PROXIES if trusted is None else trusted
    if peer not in (proxy_ips() if proxies is None else proxies):
        return peer
    hops = [h.strip() for h in (xff or "").split(",") if h.strip()]
    return hops[-trusted] if trusted and len(hops) >= trusted else peer


def rate_limited(ip, now=None):
    now = now or time.time()
    recent = [t for t in attempts.get(ip, []) if now - t < 300]
    attempts[ip] = recent
    return len(recent) >= 5


# Account-wide limit on top of the per-IP one: there is one admin account, so many IPs guessing together
# still hit a ceiling. 20 failures in 15 minutes pauses all password logins until the window clears.
ACCOUNT_MAX_FAILURES, ACCOUNT_WINDOW = 20, 900
account_failures = []


def account_limited(now=None):
    now = now or time.time()
    account_failures[:] = [t for t in account_failures if now - t < ACCOUNT_WINDOW]
    return len(account_failures) >= ACCOUNT_MAX_FAILURES


def agent(method, path, body=None):
    req = urllib.request.Request(AGENT + path, method=method,
                                 data=json.dumps(body).encode() if body is not None else None,
                                 headers={"Authorization": "Bearer " + TOKEN, "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=1900) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as err:
        raise RuntimeError(json.loads(err.read() or b"{}").get("error", "agent error"))


def watch(method, path, body=None):
    req = urllib.request.Request(WATCH + path, method=method,
                                 data=json.dumps(body).encode() if body is not None else None,
                                 headers={"Authorization": "Bearer " + WATCH_TOKEN, "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as err:
        raise RuntimeError(json.loads(err.read() or b"{}").get("error", "Open CloudWatch error"))


def svg_chart(points, label, unit, w=300, h=80):
    """Flat inline SVG line chart (no scripts, no external assets). Every label is escaped."""
    head = f'<svg width="{w}" height="{h + 22}" viewBox="0 0 {w} {h + 22}" role="img" aria-label="{e(label)}"><text x="0" y="12" font-size="12" fill="#545b64">{e(label)}'
    if not points:
        return head + f'</text><rect x="0" y="18" width="{w}" height="{h}" fill="#fafafa" stroke="#eaeded"/><text x="{w // 2}" y="{h // 2 + 22}" font-size="12" fill="#879596" text-anchor="middle">no data</text></svg>'
    t0, t1 = points[0][0], max(points[-1][0], points[0][0] + 1)
    top = max(max(v for _, v in points), 1.0) * 1.1
    xy = " ".join(f"{(t - t0) / (t1 - t0) * w:.1f},{18 + h - v / top * h:.1f}" for t, v in points)
    last = points[-1][1]
    return (head + f' · now {last:.4g}{e(unit)} · max {max(v for _, v in points):.4g}{e(unit)}</text>'
            f'<rect x="0" y="18" width="{w}" height="{h}" fill="#fafafa" stroke="#eaeded"/>'
            f'<polyline fill="none" stroke="#0073bb" stroke-width="1.5" points="{xy}"/></svg>')


CW_TABS = [("/cloudwatch", "Metrics & alarms"), ("/cloudwatch/logs", "Logs"), ("/cloudwatch/notifications", "Email"), ("/cloudwatch/events", "Event feed")]
KIND_LABELS = {"unhealthy": "App unhealthy for N minutes", "cpu": "App CPU over X% (of its limit)", "mem": "App memory over X% (of its limit)",
               "disk": "Host disk over X%", "backup_failed": "Last backup failed", "backup_stale": "No successful backup for X hours",
               "restart_loop": "App restarted X times within N minutes"}


def utc(ts):
    return time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(ts)) if ts else "-"


def cw_tabs(cur):
    return '<p class=tabs>' + " ".join(f'<a href="{u}" class="{"on" if u == cur else ""}">{n}</a>' for u, n in CW_TABS) + "</p>"


def observed_card(o):
    """Containers Open Cloud only observes (OC_OBSERVE=1): metrics, no actions."""
    snap = {c["name"]: c for c in o["snapshot"].get("observed") or []}
    rows = "".join(f'<tr><td>{e(n)}<br><small class={state_cls(c["status"] == "running" and c["health"] in ("healthy", "none"))}>{e(c["status"])} · {e(c["health"])}</small>'
                   f'<br><small>restarts {e(c["restarts"])}</small></td><td>{svg_chart(o["observed"].get(n, {}).get("cpu", []), "CPU", "%")}</td>'
                   f'<td>{svg_chart(o["observed"].get(n, {}).get("mem", []), "Memory", "%")}</td></tr>' for n, c in sorted(snap.items()))
    return (f'<div class=card><b>Observed containers (read-only)</b> · not managed by Open Cloud; it never changes them. <a href="/observed">Details</a>'
            f'<table><tr><th>Container</th><th>CPU</th><th>Memory</th></tr>{rows}</table></div>') if rows else ""


def cw_view(path, csrf, q):
    if path == "/cloudwatch":
        hours = q.get("hours", "6")
        o = watch("GET", "/admin/overview?hours=" + quote(hours))
        snap = o["snapshot"]
        alarms = [r for r in o["rules"] if r["state"] == "ALARM"]
        ranges = " ".join(f'<a href="/cloudwatch?hours={h}" class="{"on" if str(o["hours"]) == h else ""}">{n}</a>' for h, n in (("1", "1 h"), ("6", "6 h"), ("24", "24 h"), ("168", "7 d")))
        bk = snap.get("backup", {})
        summary = (f'<div class=card><span class=tabs>{ranges}</span> · <b class={state_cls(not alarms)}>{len(alarms)} in ALARM</b> · '
                   f'Disk {e(snap.get("disk_pct", "-"))}% · Last backup {e(utc(bk.get("last_success")) + " UTC" if bk.get("last_success") else "never")} · '
                   f'collected every {o["interval"]} s · metrics kept {o["retention_days"]:g} d, logs {o["log_retention_days"]:g} d</div>')
        rows = ""
        for n, m in sorted(o["apps"].items()):
            a = snap.get("apps", {}).get(n, {})
            rows += (f'<tr><td><a href="/apps/{e(n)}">{e(n)}</a><br><small class={state_cls(a.get("healthy"))}>{"healthy" if a.get("healthy") else "unhealthy"}</small>'
                     f'<br><small>restarts {e(a.get("restarts", 0))}</small></td><td>{svg_chart(m["cpu"], "CPU", "%")}</td><td>{svg_chart(m["mem"], "Memory", "%")}</td>'
                     f'<td>{svg_chart(m["latency_ms"], "Health check latency", " ms")}</td></tr>')
        host = f'<div class=grid2>{svg_chart(o["host"]["disk_pct"], "Host disk used", "%")}{svg_chart(o["host"]["backup_age_h"], "Hours since last good backup", " h")}</div>'
        bedrock = "".join(f'<div>{svg_chart(m["bedrock_requests"], f"Open Bedrock requests: {n}", "")}</div>' for n, m in sorted(o["apps"].items()) if m["bedrock_requests"])
        rules = ""
        for r in o["rules"]:
            rules += (f'<tr><td>{e(r["name"])}</td><td>{e(r["condition"])}</td><td><b class={state_cls(r["state"] == "OK")}>{e(r["state"])}</b></td>'
                      f'<td>{e(utc(r["since"]))}</td><td>{r["cooldown"]:g} min</td><td>{form("/cloudwatch/rules-delete", csrf, f"<input type=hidden name=id value={int(r['id'])}>", "Delete", "ghost")}</td></tr>')
        apps = "".join(f"<option>{e(n)}</option>" for n in sorted(snap.get("apps", {})))
        kinds = "".join(f'<option value="{k}">{e(v)}</option>' for k, v in KIND_LABELS.items())
        new = form("/cloudwatch/rules", csrf, f'<input name=name placeholder="alarm name" required maxlength=60> <select name=kind>{kinds}</select> '
                   f'<select name=target><option value="">(host-level)</option>{apps}</select> <input name=threshold placeholder="X (default)" size=9> '
                   f'<input name=minutes placeholder="N min" size=6> <input name=cooldown placeholder="cooldown min (30)" size=14> ', "Create alarm")
        hist = "".join(f'<tr><td>{e(utc(h["ts"]))}</td><td>{e(h["name"])}</td><td><b class={state_cls(h["state"] == "OK")}>{e(h["state"])}</b></td><td>{e(h["reason"])}</td></tr>' for h in o["history"])
        return "Open CloudWatch", (cw_tabs(path) + summary +
                f'<div class=card><b>App metrics</b><table><tr><th>App</th><th>CPU</th><th>Memory</th><th>Health check</th></tr>{rows or "<tr><td colspan=4>No apps yet.</td></tr>"}</table></div>'
                f'<div class=card><b>Host and backups</b>{host}</div>' + observed_card(o) + (f'<div class=card><b>Open Bedrock usage</b><div class=grid2>{bedrock}</div></div>' if bedrock else "") +
                f'<div class=card><b>Alarms</b> (OK / ALARM; emails go to the address under Email; a resolved email follows every alarm email)<table><tr><th>Name</th><th>Condition</th><th>State</th><th>Since (UTC)</th><th>Cooldown</th><th></th></tr>{rules or "<tr><td colspan=6>No alarms yet.</td></tr>"}</table><p>{new}</p></div>'
                f'<div class=card><b>Alarm history</b><table><tr><th>Time (UTC)</th><th>Alarm</th><th>State</th><th>Reason</th></tr>{hist or "<tr><td colspan=4>No state changes yet.</td></tr>"}</table></div>')
    if path == "/cloudwatch/logs":
        rng = q.get("range", "60")
        since = time.time() - float(rng) * 60 if rng.replace(".", "").isdigit() else None
        def parse_t(v):
            try:
                return calendar.timegm(time.strptime(v, "%Y-%m-%dT%H:%M")) if v else None
            except ValueError:
                raise RuntimeError("times look like 2026-10-13T14:30 (UTC)")
        since = parse_t(q.get("from")) or since
        until = parse_t(q.get("to"))
        args = {"app": q.get("app", ""), "level": q.get("level", ""), "q": q.get("q", ""), "limit": "300"}
        if since:
            args["since"] = str(since)
        if until:
            args["until"] = str(until)
        lines = watch("GET", "/admin/logs?" + "&".join(f"{k}={quote(v)}" for k, v in args.items() if v))
        apps = sorted({a["name"] for a in agent("GET", "/apps")})
        opt = lambda v, n, cur: f'<option value="{e(v)}" {"selected" if v == cur else ""}>{e(n)}</option>'
        filt = (f'<form method=get action=/cloudwatch/logs><select name=app>{opt("", "all (apps + platform)", args["app"])}{"".join(opt(a, a, args["app"]) for a in apps)}</select> '
                f'<select name=level>{"".join(opt(v, n, args["level"]) for v, n in (("", "any level"), ("error", "error"), ("warn", "warn"), ("info", "info"), ("debug", "debug")))}</select> '
                f'<input name=q value="{e(args["q"])}" placeholder="contains text" size=24> <select name=range>{"".join(opt(v, n, rng) for v, n in (("15", "last 15 min"), ("60", "last hour"), ("360", "last 6 h"), ("1440", "last 24 h"), ("10080", "last 7 d")))}</select> '
                f'<input name=from value="{e(q.get("from", ""))}" placeholder="from 2026-10-13T14:30" size=20> <input name=to value="{e(q.get("to", ""))}" placeholder="to (UTC)" size=12> <button>Search</button></form>')
        rows = "".join(f'<tr><td><small>{e(utc(x["ts"]))}</small></td><td>{e(x["app"] or x["container"])}</td><td class={"bad" if x["level"] == "error" else ""}>{e(x["level"])}</td><td><code class=log>{e(x["text"][:600])}</code></td></tr>' for x in lines)
        return "Open CloudWatch Logs", (cw_tabs(path) + f'<div class=card>App and platform container logs, kept for the retention period and searchable here. Secrets are redacted before storage (connection-string passwords, <code>*_KEY</code>/<code>*TOKEN*</code>/<code>*PASSWORD*</code>/<code>*SECRET*</code> values, bearer tokens, provider and cloud keys, private keys).<p>{filt}</p></div>'
                f'<div class=card><small>{len(lines)} lines (newest first, max 300)</small><table><tr><th>Time (UTC)</th><th>Source</th><th>Level</th><th>Message</th></tr>{rows or "<tr><td colspan=4>No matching lines.</td></tr>"}</table></div>')
    if path == "/cloudwatch/notifications":
        o = watch("GET", "/admin/overview?hours=1")
        sm = o["smtp"]
        tls = "".join(f'<option {"selected" if sm["tls"] == t else ""}>{t}</option>' for t in ("starttls", "ssl", "none"))
        f = form("/cloudwatch/smtp", csrf, f'<p><label>SMTP host <input name=host value="{e(sm["host"])}" placeholder="smtp.example.com"></label> <label>port <input name=port value="{e(sm["port"])}" size=5></label> <label>TLS <select name=tls>{tls}</select></label></p>'
                 f'<p><label>User <input name=user value="{e(sm["user"])}" autocomplete=off></label> <label>Password (write-only) <input name=password type=password autocomplete=off placeholder="{"set (leave empty to keep)" if sm["password_set"] else "not set"}"></label> <label><input type=checkbox name=clear_password> clear</label></p>'
                 f'<p><label>From <input name=from value="{e(sm["from"])}" placeholder="alerts@example.com"></label> <label>To <input name=to value="{e(sm["to"])}" placeholder="you@example.com" size=30></label></p>', "Save email settings")
        le = o.get("last_email")
        last = f'Last email: {e(le["subject"])} at {e(utc(le["ts"]))} UTC: <b class={state_cls(le["ok"])}>{"sent" if le["ok"] else "failed"}</b> {e(le.get("error", ""))}' if le else "No email sent yet."
        return "Open CloudWatch email", cw_tabs(path) + f'<div class=card>Alarm and resolved notifications. Defaults come from <code>OC_SMTP_*</code> in <code>.env</code>; changes here override them. The password is never shown.{f}</div><div class=card>{form("/cloudwatch/smtp-test", csrf, "", "Send test email", "ghost")} {last}</div>'
    if path == "/cloudwatch/events":
        o = watch("GET", "/admin/overview?hours=1")
        keyed = {k["app"] for k in o["keys"]}
        rows = ""
        for a in sorted(x["name"] for x in agent("GET", "/apps")):
            act = (form("/cloudwatch/keys", csrf, f'<input type=hidden name=app value="{e(a)}">', "Rotate key", "ghost") + " " + form("/cloudwatch/keys-revoke", csrf, f'<input type=hidden name=app value="{e(a)}">', "Revoke", "ghost")) if a in keyed else form("/cloudwatch/keys", csrf, f'<input type=hidden name=app value="{e(a)}">', "Create subscriber key", "ghost")
            rows += f'<tr><td><a href="/apps/{e(a)}">{e(a)}</a></td><td>{"<b class=ok>active</b>" if a in keyed else "none"}</td><td>{act}</td></tr>'
        subs = "".join(f'<tr><td>{e(x["app"])}</td><td><code>{e(x["url"])}</code></td><td>{e(x["topics"])}</td><td>{x["delivered"]} delivered · {x["failed"]} failed</td></tr>' for x in o["subs"])
        evs = "".join(f'<tr><td><small>{e(utc(x["ts"]))}</small></td><td>{e(x["topic"])}</td><td>{e(x["app"] or "(host)")}</td><td><code class=log>{e(json.dumps(x["data"])[:300])}</code></td></tr>' for x in o["events"])
        return "Open CloudWatch event feed", (cw_tabs(path) +
                f'<div class=card>Topics: {", ".join(f"<code>{t}</code>" for t in o["topics"])}. Every alarm state change, metric threshold crossing, deploy job and audit event is published. '
                f'An app with a subscriber key gets <code>/run/secrets/CLOUDWATCH_URL</code> and <code>/run/secrets/CLOUDWATCH_KEY</code> and sees only events about itself: '
                f'<code>GET /v1/stream</code> (Server-Sent Events), <code>GET /v1/events?after=ID</code>, or <code>POST /v1/subscriptions</code> for HMAC-signed webhooks back to the app (retried 5 times). See docs/MONITORING.md.</div>'
                f'<div class=card><b>Subscriber keys</b> (creating or rotating restarts the app with the new key)<table><tr><th>App</th><th>Key</th><th></th></tr>{rows}</table></div>'
                f'<div class=card><b>Webhook subscriptions</b> (created by apps)<table><tr><th>App</th><th>URL</th><th>Topics</th><th>Deliveries</th></tr>{subs or "<tr><td colspan=4>None.</td></tr>"}</table></div>'
                f'<div class=card><b>Recent events</b><table><tr><th>Time (UTC)</th><th>Topic</th><th>App</th><th>Data</th></tr>{evs or "<tr><td colspan=4>No events yet.</td></tr>"}</table></div>')
    raise LookupError


GUIDE = """<div class=card><b>1. What the repo needs</b><ul>
<li>A public HTTPS Git URL with a <code>Dockerfile</code> at the repo root.</li>
<li>The app listens on <code>$PORT</code> (the port you enter, default 8080) on <code>0.0.0.0</code>, plain HTTP. TLS is handled by the edge.</li>
<li>A cheap health path, e.g. <code>GET /health</code> &rarr; 200. Set it under <a href="/loadbalancers">Open ELB</a>.</li></ul></div>
<div class=card><b>2. Steps</b><ol><li><b>Create the app</b>: App Runner &rarr; name, repo, port &rarr; Deploy. New apps are Internal (no public address) unless you pick External. An optional <code>opencloud.json</code> next to the Dockerfile can set a health check and a read-only root.</li>
<li><b>Add what it needs</b> on the service page: Postgres database, bucket, Open Bedrock, your own secrets. Each one restarts the app with the new values.</li>
<li><b>Redeploy</b> after pushing code; <b>Roll back</b> to return to the previous image.</li>
<li><b>Delete</b> on the service page removes that app. Type the app name to confirm. A final backup is on unless you turn it off.</li></ol></div>
<div class=card><b>3. How values arrive: files, not environment variables</b><p>Everything except <code>PORT</code> is a file at <code>/run/secrets/NAME</code> (no trailing newline).</p>
<table><tr><th>Feature</th><th>File</th><th>Value</th></tr>
<tr><td>Postgres</td><td><code>DATABASE_URL</code></td><td><code>postgresql://app_runtime:&lt;password&gt;@db:5432/app</code></td></tr>
<tr><td>Bucket</td><td><code>S3_ENDPOINT</code></td><td><code>http://storage:8333</code> (inside the app)</td></tr>
<tr><td></td><td><code>S3_PUBLIC_ENDPOINT</code></td><td>public S3 host, for presigned URLs</td></tr>
<tr><td></td><td><code>S3_ACCESS_KEY_ID</code>, <code>S3_SECRET_ACCESS_KEY</code></td><td>this app's key (only its buckets)</td></tr>
<tr><td>Open Bedrock</td><td><code>LLM_GATEWAY_URL</code></td><td><code>http://llm-gateway:8000/v1</code> (OpenAI-compatible)</td></tr>
<tr><td></td><td><code>LLM_GATEWAY_KEY</code></td><td>this app's gateway key</td></tr>
<tr><td>Open CloudWatch events</td><td><code>CLOUDWATCH_URL</code></td><td><code>http://cloudwatch:8100</code></td></tr>
<tr><td></td><td><code>CLOUDWATCH_KEY</code></td><td>this app's subscriber key (events about this app only)</td></tr>
<tr><td>Your secrets</td><td><code>NAME</code></td><td>what you saved</td></tr></table>
<p>Not injected: the bucket name (save it as a secret, e.g. <code>S3_BUCKET</code>) and Open Bedrock endpoint names (use one, e.g. <code>chat-fast</code>, as <code>model</code>; your app must be enabled on it). S3: use path-style addressing and any region.</p></div>
<div class=card><b>4. Reading them</b><p>Python</p><pre>from pathlib import Path
import os
def secret(name, default=None):
    p = Path("/run/secrets") / name
    return p.read_text() if p.exists() else default

port = int(os.environ["PORT"])
db_url = secret("DATABASE_URL")
from openai import OpenAI
llm = OpenAI(base_url=secret("LLM_GATEWAY_URL"), api_key=secret("LLM_GATEWAY_KEY"))
llm.chat.completions.create(model="chat-fast", messages=[{"role": "user", "content": "hi"}])</pre>
<p>Node</p><pre>const fs = require("fs");
const secret = (n, d) =&gt; { try { return fs.readFileSync(`/run/secrets/${n}`, "utf8"); } catch { return d; } };
const port = Number(process.env.PORT);
const { S3Client } = require("@aws-sdk/client-s3");
const s3 = new S3Client({ endpoint: secret("S3_ENDPOINT"), region: "us-east-1", forcePathStyle: true,
  credentials: { accessKeyId: secret("S3_ACCESS_KEY_ID"), secretAccessKey: secret("S3_SECRET_ACCESS_KEY") } });</pre></div>
<div class=card><b>5. My app expects other names or environment variables</b><ul>
<li>Other names: save extra secrets with those names, e.g. <code>DB_HOST=db</code>, <code>DB_PORT=5432</code>, <code>DB_USER=app_runtime</code>, <code>DB_NAME=app</code>. The password is only inside <code>DATABASE_URL</code> (secrets are write-only), so parse it from there.</li>
<li>Environment variables: add an entrypoint that exports the files, then <code>exec "$@"</code>:<pre>#!/bin/sh
for f in /run/secrets/*; do export "$(basename "$f")=$(cat "$f")"; done
exec "$@"</pre></li></ul></div>
<div class=card><b>6. Persistent files</b><p><code>/data</code> survives redeploys and rollbacks, is backed up, and is owned by your image's <code>USER</code>. Everything else is reset on deploy.</p></div>
<div class=card><b>7. Monitoring and events (<a href="/cloudwatch">Open CloudWatch</a>)</b><ul>
<li>Metrics (CPU, memory, restarts, health) and logs (stdout/stderr) are collected automatically. Mark <code>GET /health</code> as a health check in the App Map to get latency and the <code>unhealthy</code> alarm.</li>
<li>Don't print secrets. Common shapes (connection-string passwords, <code>*_KEY=</code>, tokens) are redacted before storage, but redaction is pattern-based.</li>
<li>Events for your app: Open CloudWatch &rarr; Event feed &rarr; <b>Create subscriber key</b>. Then follow the stream, or register a signed webhook back to your own app:</li></ul>
<p>Python (Server-Sent Events)</p><pre>req = urllib.request.Request(secret("CLOUDWATCH_URL") + "/v1/stream?topics=alarms,deploys",
                             headers={"Authorization": "Bearer " + secret("CLOUDWATCH_KEY")})
for line in urllib.request.urlopen(req):   # "event: alarms" / "data: {...}"
    print(line.decode().rstrip())</pre>
<p>Node (webhook: verify the signature)</p><pre>const want = "sha256=" + crypto.createHmac("sha256", secret("CLOUDWATCH_KEY"))
  .update(req.headers["x-oc-timestamp"] + "." + rawBody).digest("hex");
if (!crypto.timingSafeEqual(Buffer.from(want), Buffer.from(req.headers["x-oc-signature"] || ""))) return res.sendStatus(401);</pre>
<p>Register it with <code>POST $CLOUDWATCH_URL/v1/subscriptions {"url": "http://app-&lt;name&gt;:&lt;port&gt;/hook", "topics": ["alarms"]}</code>. Full examples: <code>examples/cloudwatch-consumer</code>.</p></div>
<div class=card><b>8. Troubleshooting</b><ul>
<li>Build failed: open the job on <a href="/jobs">Deployments</a> for the build log tail.</li>
<li>502 or unhealthy: not listening on <code>$PORT</code> / <code>0.0.0.0</code>, or crashed; check Logs on the service page.</li>
<li>Restarting or killed: raise memory under Resources.</li>
<li>Permission denied on <code>/data</code>: redeploy (ownership is re-applied).</li>
<li>Open Bedrock 404: wrong endpoint name or app not enabled; 429: over the per-app limit.</li>
<li>S3 signature or bucket errors: path-style, internal <code>S3_ENDPOINT</code>, a bucket owned by this app.</li></ul>
<p>Full version: <code>docs/APP-GUIDE.md</code> in the repo.</p></div>"""

CSS = """*{box-sizing:border-box}body{margin:0;font:14px/1.5 system-ui,sans-serif;color:#16191f;background:#f2f3f3}
header{background:#232f3e;color:#fff;display:flex;align-items:center;gap:24px;padding:0 20px;height:48px}
header b{color:#ff9900}header a{color:#fff;text-decoration:none}header form{margin-left:auto}
main{max-width:1100px;margin:24px auto;padding:0 20px}h1{font-size:22px;font-weight:600}
.card{background:#fff;border:1px solid #d5dbdb;padding:16px 20px;margin-bottom:16px}
table{width:100%;border-collapse:collapse}td,th{text-align:left;padding:8px;border-bottom:1px solid #eaeded}
th{color:#545b64;font-weight:600}input,select{padding:6px 8px;border:1px solid #aab7b8;font:inherit}
button{background:#ff9900;border:0;color:#16191f;padding:7px 14px;font-weight:600;cursor:pointer}
button.ghost{background:#fff;border:1px solid #545b64}.ok{color:#1d8102}.bad{color:#d13212}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(220px,1fr));gap:16px}
.svc{display:block;background:#fff;border:1px solid #d5dbdb;padding:16px;color:inherit;text-decoration:none}
.svc small{display:block;color:#545b64}pre{background:#16191f;color:#eaeded;padding:12px;overflow:auto;max-height:480px}
.flash{background:#fff;border-left:4px solid #0073bb;padding:10px 14px;margin-bottom:16px}.flash.err{border-color:#d13212}
code{background:#eaeded;padding:1px 4px}code.log{background:none;white-space:pre-wrap;word-break:break-all;font-size:12px}
.tabs a{margin-right:12px;color:#0073bb;text-decoration:none}.tabs a.on{color:#16191f;font-weight:600;border-bottom:2px solid #ff9900}
.grid2{display:grid;grid-template-columns:repeat(auto-fill,minmax(310px,1fr));gap:12px}
.map{display:flex;flex-wrap:wrap;gap:10px;align-items:stretch}.node{display:block;border:1px solid #aab7b8;background:#fff;padding:10px 12px;min-width:150px;color:inherit;text-decoration:none}
.node b{display:block}.node small{display:block;color:#545b64}.arrow{align-self:center;color:#545b64;font-weight:600}.stack{display:flex;flex-direction:column;gap:10px}"""

SERVICES = [("/apps", "App Runner", "Deploy apps from a Git URL (Cloud Run)"),
            ("/databases", "Managed Postgres", "One database per app (RDS / Cloud SQL)"),
            ("/secrets", "Secrets", "Write-only app secrets (Secret Manager)"),
            ("/storage", "Object Storage", "S3-compatible buckets (S3 / Cloud Storage)"),
            ("/jobs", "Deployments", "Build and rollback jobs (CodeBuild / Cloud Build)"),
            ("/audit", "Audit log", "Append-only console activity (CloudTrail / Audit Logs)"),
            ("/cloudwatch", "Open CloudWatch", "Metrics, logs, alarms, email and an app event feed (CloudWatch / Cloud Monitoring + EventBridge / SNS)"),
            ("/observed", "Observed (read-only)", "Containers on this machine that Open Cloud doesn't manage: state, health, metrics"),
            ("/status", "Status", "Containers, health, restarts, disk and memory right now"),
            ("/backups", "Backups", "Encrypted restic snapshots (AWS Backup)"),
            ("/models", "Open Bedrock", "Named model endpoints, per-app keys and usage (Bedrock / Vertex AI)"),
            ("/loadbalancers", "Open ELB", "Load balancer routes: domains, TLS, health, canary (Elastic Load Balancing / Cloud Load Balancing)"),
            ("/sites", "Static sites", "HTML/CSS/JS sites from private storage with HTTPS (S3 static website / Firebase Hosting)"),
            ("/dns", "DNS", "Records your routes need (Route 53 / Cloud DNS)")]


APP_FIELDS = ("name", "visibility", "source", "repo", "ref", "folder", "dockerfile", "port", "networks", "secret_mounts", "data_mounts", "env")


def app_runner_form(csrf, opts):
    """Create-service form. Host options (server folder, networks, mounts) appear only when allowlisted in .env."""
    src = (f'<p><label><input type=radio name=source value=git checked> Git repo</label> '
           f'<input name=repo placeholder="https://github.com/you/app" size=40> <input name=ref placeholder="branch (optional)"></p>')
    if opts.get("local_sources"):
        src += (f'<p><label><input type=radio name=source value=folder> Server folder</label> '
                f'<input name=folder placeholder="{e(opts["local_sources"][0])}/my-app" size=40> '
                f'<small>under {e(", ".join(opts["local_sources"]))}; copied read-only into the build</small></p>')
    inner = ('<p><input name=name placeholder="name (a-z, 0-9, -)" required pattern="[a-z][a-z0-9-]{1,30}"> '
             '<input name=port placeholder="port" value=8080 size=5> <input name=dockerfile placeholder="Dockerfile path (default: Dockerfile)" size=30></p>'
             '<p>Visibility: <label><input type=radio name=visibility value=internal checked> Internal</label> (no public address; still reachable by other apps on this server as <code>app-NAME:PORT</code>) '
             '<label><input type=radio name=visibility value=external> External</label> (public at <code>NAME.apps domain</code> and custom domains)</p>' + src)
    adv = ""
    if opts.get("networks"):
        adv += f'<p><label>Join networks <input name=networks placeholder="space separated" size=40></label> <small>allowed: {e(" ".join(opts["networks"]))}</small></p>'
    if opts.get("secret_paths"):
        adv += (f'<p><label>Secret files (one per line: /host/file=name &rarr; /run/secrets/name, read-only)<br><textarea name=secret_mounts rows=3 cols=70></textarea></label>'
                f'<br><small>allowed: {e(" ".join(opts["secret_paths"]))}</small></p>')
    if opts.get("data_roots"):
        adv += (f'<p><label>Data folders (one per line: /host/folder:/container/path, add :ro for read-only)<br><textarea name=data_mounts rows=2 cols=70></textarea></label>'
                f'<br><small>allowed: {e(" ".join(opts["data_roots"]))}</small></p>')
    adv += '<p><label>Environment (one per line: KEY=value, not secret)<br><textarea name=env rows=2 cols=70></textarea></label></p>'
    inner += f'<details><summary>Advanced: networks, mounts, environment</summary>{adv}</details>'
    return form("/apps", csrf, inner, "Deploy")


def page(title, body, csrf=None, flash=None, err=False):
    out = f"""<!doctype html><html><head><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1">
<title>{e(title)} · Open Cloud</title><style>{CSS}</style></head><body><header><a href="/"><b>Open Cloud</b></a>"""
    if csrf:
        out += "".join(f'<a href="{u}">{n}</a>' for u, n, _ in SERVICES[:3])
        out += '<a href="/account/password">Change password</a><a href="/account/2fa">Two-step login</a>'
        out += f'<form method=post action=/logout><input type=hidden name=csrf value="{e(csrf)}"><button class=ghost>Sign out</button></form>'
    out += "</header><main>"
    if flash:
        out += f'<div class="flash{" err" if err else ""}">{e(flash)}</div>'
    return out + f"<h1>{e(title)}</h1>{body}</main></body></html>"


SITE_UPLOAD_MAX = 10 * 1024 * 1024 + 65536


def parse_multipart(ctype, raw):
    """multipart/form-data -> (fields, {name: (filename, bytes)}). Uses the stdlib email parser (cgi is gone)."""
    from email.parser import BytesParser
    from email.policy import HTTP
    msg = BytesParser(policy=HTTP).parsebytes(b"Content-Type: " + ctype.encode() + b"\r\n\r\n" + raw)
    fields, files = {}, {}
    if not msg.is_multipart():
        return fields, files
    for part in msg.iter_parts():
        name = part.get_param("name", header="content-disposition")
        if not name:
            continue
        data = part.get_payload(decode=True) or b""
        fn = part.get_filename()
        if fn is not None:
            files[name] = (os.path.basename(fn), data)
        else:
            fields[name] = data.decode(errors="replace")
    return fields, files


def form(action, csrf, inner, label, cls=""):
    return f'<form method=post action="{e(action)}" style="display:inline"><input type=hidden name=csrf value="{e(csrf)}">{inner}<button class="{cls}">{e(label)}</button></form>'


def delete_form(app, csrf):
    """Typed confirmation. The deployer is what actually removes the app."""
    n = app["name"]
    kept = []
    for m in app.get("data_mounts") or []:
        src, tgt = m.get("source", ""), m.get("target", "")
        if src:
            kept.append(f"{src}:{tgt}" if tgt else src)
    for m in app.get("secret_mounts") or []:
        if m.get("source"):
            kept.append(m["source"])
    if app.get("site_domains"):
        kept.append("hand-written edge site (" + ", ".join(app["site_domains"]) + ")")
    left = ("<p>Left in place: " + ", ".join(f"<code>{e(x)}</code>" for x in kept) +
            ". These are outside this app's managed files and are not deleted.</p>") if kept else (
            "<p>Host data folders, host secret files, and hand-written edge files are not deleted. This app has none.</p>")
    inner = (
        "<p>This removes the app from this server:</p><ul>"
        "<li>Containers and the app's private network</li>"
        "<li>Its edge route (the edge is reloaded)</li>"
        "<li>Its Postgres database, data directory, and credentials</li>"
        "<li>Its buckets and S3 access key</li>"
        "<li>Its secret files, managed <code>/data</code> folder, and app folder</li></ul>"
        "<p>Deploy jobs and release records are kept and marked deleted.</p>" + left +
        '<p><label><input type=checkbox name=backup value=1 checked> Take a final backup first '
        "(database dump, bucket objects, app definition, and <code>/data</code>)</label></p>"
        f'<p><label>Type <code>{e(n)}</code> to confirm <input name=confirm required autocomplete=off size=24></label></p>'
    )
    return (f'<div class=card><b>Delete this app</b>'
            f'<form method=post action="/apps/{e(n)}/delete"><input type=hidden name=csrf value="{e(csrf)}">{inner}'
            f'<button>Delete app</button></form></div>')


def delete_flash(res):
    """Plain text for the console banner. Paths and mount sources only; never secret values."""
    parts = [f"Deleted {res.get('app', 'app')}."]
    parts.append(f"Backup: {res['backup_path']}" if res.get("backup_path") else "No backup was taken.")
    kept = [s.get("detail") for s in res.get("steps", []) if s.get("status") == "kept" and s.get("detail")]
    if kept:
        parts.append("Left in place: " + "; ".join(kept))
    failed = [s.get("step") for s in res.get("steps", []) if s.get("status") == "failed"]
    if failed:
        parts.append("Needs attention: " + ", ".join(failed))
    return " ".join(parts)[:500]


def job_app(j):
    name = e(j.get("app", ""))
    if j.get("app_deleted"):
        return f"{name} <small>(deleted)</small>"
    return f'<a href="/apps/{name}">{name}</a>'


PROVIDER_NAMES = {"openrouter": "OpenRouter", "openai": "OpenAI", "anthropic": "Anthropic Claude"}


def provider_form(csrf, g):
    """Initiate AI: pick a provider and paste its key. The key is write-only; only its status is shown."""
    cur = g.get("provider", "")
    opts = "".join(f'<option value="{k}"{" selected" if k == cur else ""}>{v}</option>' for k, v in PROVIDER_NAMES.items())
    status = (f'<b class=ok>set</b> · {e(PROVIDER_NAMES.get(cur, cur or "custom"))} · updated {e(g.get("key_updated") or "earlier")} (UTC)'
              if g["provider_key_set"] else "<b class=bad>not set</b>")
    return (f'<p>Key: {status}</p>' + form("/gateway/provider", csrf,
            f'<p><label>Provider <select name=provider>{opts}</select></label> '
            f'<label>API key <input name=key type=password autocomplete=off placeholder="{"paste to replace" if g["provider_key_set"] else "paste key"}" size=40></label> '
            f'<label><input type=checkbox name=clear_key> remove key</label></p>'
            f'<p><label>Provider URL (optional; blank uses the provider default)<br><input name=upstream_url value="{e(g["upstream_url"])}" size=60></label></p>', "Save provider"))


def link(a):
    """Public URL (hand-written site domain first), or the private address of an internal app."""
    if a.get("url"):
        return f'<a href="{e(a["url"])}">{e(a["url"])}</a>'
    return f'<small>internal: <code>app-{e(a["name"])}:{a["port"]}</code></small>'


def state_cls(ok):
    return "ok" if ok else "bad"


def render_map(m, csrf):
    """App Map: flat diagram + API endpoints. Every value (incl. the untrusted OpenAPI spec) is escaped."""
    n, r = m["app"], m["route"] or {}
    def node(title, lines, ok=None, href=None):
        status = "" if ok is None else f'<small class={state_cls(ok)}>{"healthy" if ok else "needs attention"}</small>'
        inner = f'<b>{e(title)}</b>' + "".join(f"<small>{e(x)}</small>" for x in lines) + status
        return f'<a class=node href="{e(href)}">{inner}</a>' if href else f"<div class=node>{inner}</div>"
    svc = m["services"]
    web = svc.get("web", {})
    lb = node("Open ELB route", r.get("hosts", []), r.get("health") == "healthy", f"/loadbalancers/{n}")
    backends = [node("Service (web)", [f"commit {m['commit'] or '-'}", web.get("status", "missing")],
                     web.get("status") == "running" and web.get("health") in ("healthy", "none"), "#api")]
    if "prev" in svc:
        backends.append(node("Canary (previous)", [f'{r.get("route", {}).get("canary_weight", 0)}% of traffic', svc["prev"]["status"]], svc["prev"]["status"] == "running"))
    deps = []
    if m["db"]:
        db = svc.get("db", {})
        deps.append(node("Postgres", ["DATABASE_URL", db.get("status", "missing")], db.get("health") == "healthy", "/databases"))
    deps += [node("Bucket", [b], None, "/storage") for b in m["buckets"]]
    if m["gateway_key"]:
        deps.append(node("Open Bedrock", m["endpoints"] or ["no endpoints enabled"], bool(m["endpoints"]), "/models"))
    diagram = (f'<div class=map>{lb}<span class=arrow>&rarr;</span><div class=stack>{"".join(backends)}</div>'
               + (f'<span class=arrow>&rarr;</span><div class=stack>{"".join(deps)}</div>' if deps else "") + "</div>")
    api = m["api"]
    rows = ""
    for x in api["endpoints"]:
        chk = api["checks"].get(x["path"]) if x["method"] == "GET" else None
        health = (f'<span class={state_cls(chk["code"] and chk["code"] < 400)}>{e(chk["code"] or "no answer")}</span> · {e(chk["ms"] if chk["ms"] is not None else "-")} ms · {e(chk["checked"] or "not yet")}' if chk else "")
        toggle = ""
        if x["method"] == "GET" and "{" not in x["path"]:
            toggle = form(f"/apps/{n}/api-check", csrf, f'<input type=hidden name=path value="{e(x["path"])}">' + ("" if chk else "<input type=hidden name=enabled value=1>"),
                          "Stop checking" if chk else "Use as health check", "ghost")
        rows += f'<tr><td><code>{e(x["method"])}</code></td><td><code>{e(x["path"])}</code></td><td>{e(x["summary"])}</td><td>{health}</td><td>{toggle}</td></tr>'
    disc = form(f"/apps/{n}/api-discover", csrf, f'<input name=spec_path value="{e(api["spec_path"])}" size=20> ', "Discover from OpenAPI", "ghost")
    add = form(f"/apps/{n}/api-endpoint", csrf, '<select name=method><option>GET</option><option>POST</option><option>PUT</option><option>PATCH</option><option>DELETE</option></select> <input name=path placeholder="/items/{id}" required> <input name=summary placeholder="description"> ', "Add endpoint", "ghost")
    probe = form(f"/apps/{n}/api-probe", csrf, "", "Check now", "ghost") if api["checks"] else ""
    return (f'<div class=card><b>App Map</b>{diagram}</div>'
            f'<div class=card id=api><b>API endpoints</b> <small>(source: {e(api["source"] or "none yet")})</small><p>{disc} {add} {probe}</p>'
            f'<table><tr><th>Method</th><th>Path</th><th>Summary</th><th>Health (status · latency · last checked UTC)</th><th></th></tr>{rows or "<tr><td colspan=5>No endpoints yet. Discover them from the app&#x27;s OpenAPI spec or add them by hand.</td></tr>"}</table>'
            f'<p><small>Only GET endpoints you mark are probed (every {e(os.environ.get("OC_API_PROBE_INTERVAL", "60"))} s, and on "Check now"). POST/PUT/PATCH/DELETE are never called.</small></p></div>')


def gb(n):
    return f"{n / 1e9:.1f} GB"


def view(path, csrf, q=None):
    if path.startswith("/cloudwatch"):
        return cw_view(path, csrf, q or {})
    if path == "/":
        cards = "".join(f'<a class=svc href="{u}"><b>{n}</b><small>{d}</small></a>' for u, n, d in SERVICES if u != "/observed" or OBSERVE)
        return "Console home", f"<div class=grid>{cards}</div>"
    if path == "/apps":
        rows = "".join(f'<tr><td><a href="/apps/{e(a["name"])}">{e(a["name"])}</a></td><td>{link(a)}</td><td>{e(a.get("visibility", "external"))}</td><td>{e(a.get("commit") or "")}</td><td>{"yes" if a.get("db") else "no"}</td></tr>' for a in agent("GET", "/apps"))
        try:
            opts = agent("GET", "/host-options")
        except RuntimeError:
            opts = {}
        deploy = app_runner_form(csrf, opts)
        return "App Runner", f'<div class=card><b>Create service</b><p>Public Git repo or an allowlisted server folder, with a Dockerfile. The app must listen on the port you give. New here? <a href="/guide">Prepare your app</a>.</p>{deploy}</div><div class=card><table><tr><th>Service</th><th>URL</th><th>Visibility</th><th>Commit</th><th>Database</th></tr>{rows or "<tr><td colspan=5>No services yet.</td></tr>"}</table></div>'
    m = re.fullmatch(r"/apps/([a-z][a-z0-9-]{1,30})", path)
    if m:
        n = m.group(1)
        a = next((x for x in agent("GET", "/apps") if x["name"] == n), None)
        if not a:
            raise RuntimeError("no such app")
        lim = form(f"/apps/{n}/limits", csrf, f'<input name=memory_mb type=number min=64 value="{a.get("memory_mb", 512)}" size=6> MB <input name=cpus type=number step=0.1 min=0.1 value="{a.get("cpus", 1.0)}" size=4> CPUs ', "Save limits", "ghost")
        bk = form(f"/apps/{n}/buckets", csrf, '<input name=bucket placeholder="bucket-name" required pattern="[a-z0-9][a-z0-9-]{2,62}"> ', "Create bucket", "ghost")
        rel = "".join(f'<tr><td>{e(r["time"])}</td><td>{e(r["action"])}</td><td>{e(r["image_tag"])}</td></tr>' for r in agent("GET", f"/apps/{n}/releases"))
        logs = agent("GET", f"/apps/{n}/logs")["logs"]
        sec = ", ".join(f"<code>{e(s)}</code>" for s in a["secrets"]) or "none"
        actions = form(f"/apps/{n}/redeploy", csrf, "", "Redeploy latest") + " " + form(f"/apps/{n}/rollback", csrf, "", "Roll back", "ghost")
        if not a.get("db"):
            actions += " " + form(f"/apps/{n}/db", csrf, "", "Create Postgres database", "ghost")
        if "LLM_GATEWAY_KEY" not in a["secrets"]:
            if GENERIC_GATEWAY:
                actions += " " + form(f"/apps/{n}/ai", csrf, "", "Enable Open Bedrock", "ghost")
        vis = a.get("visibility", "external")
        other = "external" if vis == "internal" else "internal"
        visf = form(f"/apps/{n}/visibility", csrf, f'<input type=hidden name=visibility value={other}>', f"Make {other}", "ghost")
        pk = form(f"/apps/{n}/provider-key", csrf, f'<input name=env value="{e(a.get("provider_key_env", ""))}" placeholder="OPENROUTER_API_KEY" pattern="[A-Z][A-Z0-9_]*"> ', "Save", "ghost")
        setsec = form(f"/apps/{n}/secrets", csrf, '<input name=key placeholder="NAME" required pattern="[A-Z][A-Z0-9_]*"> <input name=value type=password placeholder="value" required autocomplete=off> ', "Save secret")
        amap = render_map(agent("GET", f"/apps/{n}/map"), csrf)
        return f"Service: {n}", amap + f"""<div class=card><p>{link(a)} · source <code>{e(a.get("folder") or a["repo"])}</code> · port {a['port']}</p>{actions}</div>
<div class=card><b>Secrets</b> (mounted at <code>/run/secrets/NAME</code>; values are never shown): {sec}<p>{setsec}</p></div>
<div class=card><b>Visibility</b>: <b>{vis}</b>. {"No public route; other apps reach it as <code>app-" + e(n) + ":" + str(a["port"]) + "</code>. " + ("Served on " + e(", ".join(a.get("site_domains") or [])) + " by a hand-written edge site." if a.get("site_domains") else "") if vis == "internal" else "Public at " + e(a["url"]) + " and any custom domains."} {visf}</div>
<div class=card><b>AI provider key</b>: give this app the <a href="/models">Initiate AI</a> key as <code>/run/secrets/NAME</code>. Leave empty to stop. {pk}</div>
<div class=card><b>Resources</b> (applied on save; the app restarts): {lim}</div>
<div class=card><b>Object storage</b> (keys arrive as <code>S3_ACCESS_KEY_ID</code> / <code>S3_SECRET_ACCESS_KEY</code> secrets): {bk}</div>
<div class=card><b>Releases</b><table><tr><th>Time (UTC)</th><th>Action</th><th>Image</th></tr>{rel}</table></div>
<div class=card><b>Logs</b> (last 200 lines)<pre>{e(logs)}</pre></div>
{delete_form(a, csrf)}"""
    if path == "/storage":
        rows = "".join(f'<tr><td>{e(b["bucket"])}</td><td><a href="/apps/{e(b["app"])}">{e(b["app"])}</a></td></tr>' for b in agent("GET", "/buckets"))
        return "Object Storage", f'<div class=card>S3-compatible API (SeaweedFS). Apps use <code>http://storage:8333</code>; presigned URLs use <code>https://{e(os.environ.get("OC_S3_HOST", ""))}</code>. Each app gets its own access key, limited to its buckets. Create buckets on the service page. Apps also have a persistent <code>/data</code> directory.</div><div class=card><table><tr><th>Bucket</th><th>Owner app</th></tr>{rows or "<tr><td colspan=2>No buckets yet.</td></tr>"}</table></div>'
    if path == "/jobs":
        rows = "".join(f'<tr><td><a href="/jobs/{e(j["id"])}">{e(j["id"])}</a></td><td>{e(j["kind"])}</td><td>{job_app(j)}</td><td class={"bad" if j["status"] == "failed" else "ok"}>{e(j["status"])}</td><td>{e(j["started"])}</td></tr>' for j in agent("GET", "/jobs"))
        return "Deployments", f'<div class=card><table><tr><th>Job</th><th>Kind</th><th>App</th><th>Status</th><th>Started (UTC)</th></tr>{rows or "<tr><td colspan=5>No jobs yet.</td></tr>"}</table></div>'
    m = re.fullmatch(r"/jobs/([0-9a-f]{1,20})", path)
    if m:
        j = agent("GET", path)
        refresh = '<meta http-equiv=refresh content=3>' if j["status"] == "running" else ""
        return f"Job {j['id']}", f'{refresh}<div class=card>{e(j["kind"])} of {job_app(j)}: <b class={"bad" if j["status"] == "failed" else "ok"}>{e(j["status"])}</b> · started {e(j["started"])} · finished {e(j.get("finished", "-"))}</div>' + (f'<div class=card><pre>{e(j["error"])}</pre></div>' if j.get("error") else "")
    if path == "/audit":
        a = agent("GET", "/audit")
        rows = "".join(f'<tr><td>{e(x["time"])}</td><td>{e(x["event"])}</td><td>{e(x["target"])}</td><td>{e(x["outcome"])}</td><td>{e(x["ip"])}</td></tr>' for x in a["entries"])
        return "Audit log", f'<div class=card>{a["count"]} entries · local consistency check <b class={"ok" if a["intact"] else "bad"}>{"passed" if a["intact"] else "FAILED"}</b>. Entries are hash-chained and the console has no way to edit or delete them, but this is a local consistency check, not tamper-proof: root on the server can rewrite the whole file and chain.</div><div class=card><table><tr><th>Time (UTC)</th><th>Event</th><th>Target</th><th>Outcome</th><th>IP</th></tr>{rows}</table></div>'
    if path in ("/databases", "/secrets"):
        apps = agent("GET", "/apps")
        if path == "/databases":
            rows = "".join(f'<tr><td><a href="/apps/{e(a["name"])}">{e(a["name"])}</a></td><td>{"PostgreSQL 17, private network" if a.get("db") else "none"}</td></tr>' for a in apps)
            note = "Each app gets its own Postgres container on an internal-only network. The app receives <code>/run/secrets/DATABASE_URL</code>. Create one from the service page."
        elif path == "/secrets":
            rows = "".join(f'<tr><td><a href="/apps/{e(a["name"])}">{e(a["name"])}</a></td><td>{", ".join(e(s) for s in a["secrets"]) or "none"}</td></tr>' for a in apps)
            note = "Secrets are files readable only on this machine, mounted into the app. Set them on the service page."
        return path[1:].title(), f"<div class=card><p>{note}</p><table>{rows}</table></div>"
    if path == "/status":
        s = agent("GET", "/status")
        rows = "".join(f'<tr><td>{e(c["name"])}</td><td class={"ok" if c["status"] == "running" else "bad"}>{e(c["status"])}</td><td>{e(c["health"])}</td><td>{c["restarts"]}</td></tr>' for c in s["containers"])
        return "Status", f'<div class=card>Disk {gb(s["disk_used"])} / {gb(s["disk_total"])} · Memory free {gb(s["mem_available"])} / {gb(s["mem_total"])} · Load {s["load"][0]:.2f} · Last backup {e(s["last_backup"] or "never")}</div><div class=card><table><tr><th>Container</th><th>State</th><th>Health</th><th>Restarts</th></tr>{rows}</table></div>'
    if path == "/observed":
        o = agent("GET", "/observed")
        rows = "".join(f'<tr><td>{e(c["name"])}</td><td>{e(c["project"])}</td><td><small>{e(c["image"])}</small></td><td class={"ok" if c["status"] == "running" else "bad"}>{e(c["status"])}</td>'
                       f'<td>{e(c["health"])}</td><td>{c["restarts"]}</td><td>{c["cpu"]:.1f}%</td><td>{c["mem"]:.1f}%</td></tr>' for c in o["containers"])
        st, mk = o["platform"]["status"], o["platform"]["markers"]
        plat = "".join(f'<tr><td>{e(k)}</td><td>{e(v)}</td></tr>' for k, v in list((st or {}).items()) + list(mk.items()))
        return "Observed (read-only)", (f'<div class=card>Containers this machine runs that Open Cloud doesn\'t manage. Read-only: Open Cloud refuses any action on them. '
                f'Metrics and logs are in <a href="/cloudwatch">Open CloudWatch</a>.</div><div class=card><table><tr><th>Container</th><th>Project</th><th>Image</th><th>State</th><th>Health</th><th>Restarts</th><th>CPU</th><th>Memory</th></tr>'
                f'{rows or "<tr><td colspan=8>None.</td></tr>"}</table></div><div class=card><b>Platform status and backups</b> (read-only files)<table>{plat or "<tr><td>No status file or backup markers mounted.</td></tr>"}</table></div>')
    if path == "/backups":
        rows = "".join(f'<tr><td>{e(x["time"][:19])}</td><td>{e(x["short_id"])}</td></tr>' for x in reversed(agent("GET", "/backups")))
        return "Backups", f'<div class=card>Encrypted restic repository on this machine. Copy it off the machine for real disaster recovery. {form("/backups", csrf, "", "Back up now")}</div><div class=card><table><tr><th>Snapshot time (UTC)</th><th>ID</th></tr>{rows or "<tr><td colspan=2>No snapshots yet.</td></tr>"}</table></div>'
    if path == "/guide":
        return "Prepare your app", GUIDE
    if path == "/loadbalancers":
        rows = ""
        for r in agent("GET", "/routes"):
            c = r["route"]["canary_weight"] if r["previous_tag"] else 0
            target = f'{e(r["commit"] or "")}' + (f' · canary {c}% → previous' if c else "")
            tls = "<br>".join(f'{e(h)}: <span class={"ok" if s == "issued" else "bad"}>{e(s)}</span>' for h, s in r["tls"].items())
            rows += (f'<tr><td><a href="/loadbalancers/{e(r["app"])}">{e(r["app"])}</a></td><td>{"<br>".join(e(h) for h in r["hosts"])}</td>'
                     f'<td>{target}</td><td>{tls}</td><td class={"ok" if r["health"] == "healthy" else "bad"}>{e(r["health"])} '
                     f'<small>({e(r["route"]["health_path"] or "/")})</small></td><td>{"on" if r["route"]["redirect"] else "off"}</td></tr>')
        cfg = agent("GET", "/edge-config")
        hand = "".join(f'<tr><td>{e(c["file"])}</td><td>{"<br>".join(e(h) for h in c["hosts"])}</td><td>{e(" ".join(c["targets"]))}</td></tr>'
                       for c in cfg if not c["managed"])
        files = "".join(f'<details><summary>{e(c["file"])}{"" if c["managed"] else " (hand-managed)"}</summary><pre>{e(c["config"])}</pre></details>' for c in cfg)
        return "Open ELB (Elastic Load Balancing)", (f'<div class=card>One Caddy edge terminates TLS for every route. Edit a route to add custom domains, health checks or a canary. '
                f'Internal apps have no edge route and aren\'t listed. '
                f'Per-route rate limiting needs a Caddy plugin that the stock image doesn\'t include, so it isn\'t offered here (see docs/OPEN-ELB.md).</div>'
                f'<div class=card><table><tr><th>Route</th><th>Domains</th><th>Target</th><th>TLS</th><th>Health</th><th>HTTP→HTTPS</th></tr>{rows or "<tr><td colspan=6>No routes yet.</td></tr>"}</table></div>'
                + (f'<div class=card><b>Hand-managed routes</b> (read-only, edited on the server)<table><tr><th>File</th><th>Domains</th><th>Target</th></tr>{hand}</table></div>' if hand else "")
                + (f'<div class=card><b>Edge config</b> (read-only, secrets redacted){files}</div>' if files else ""))
    m = re.fullmatch(r"/loadbalancers/([a-z][a-z0-9-]{1,30})", path)
    if m:
        r = next((x for x in agent("GET", "/routes") if x["app"] == m.group(1)), None)
        if not r:
            raise RuntimeError("no such route")
        rc = r["route"]
        default, custom = r["hosts"][0], " ".join(rc["domains"])
        canary = (f'<p><label>Canary: send <input name=canary_weight type=number min=0 max=50 value="{rc["canary_weight"]}" size=3>% of traffic to the previous release (0 = off)</label></p>'
                  if r["previous_tag"] else '<p>Canary: needs a previous release (deploy twice). <input type=hidden name=canary_weight value=0></p>')
        inner = (f'<p>Default domain: <code>{e(default)}</code></p>'
                 f'<p><label>Custom domains (space or comma separated)<br><input name=domains value="{e(custom)}" size=60 placeholder="www.example.com"></label></p>'
                 f'<p><label><input type=checkbox name=redirect {"checked" if rc["redirect"] else ""}> Redirect HTTP to HTTPS</label></p>'
                 f'<p><label>Health check path <input name=health_path value="{e(rc["health_path"])}" placeholder="/health" size=20></label> '
                 f'<label>every <input name=health_interval type=number min=5 max=300 value="{rc["health_interval"]}" size=4> s</label></p>{canary}')
        return f"Open ELB route: {m.group(1)}", f'<div class=card>{form(f"/apps/{m.group(1)}/route", csrf, inner, "Save route")}</div><div class=card>Changes are rendered to Caddy config, checked with <code>caddy validate</code>, reloaded, and rolled back automatically if Caddy rejects them.</div>'
    if path == "/models":
        g = agent("GET", "/gateway")
        prov = provider_form(csrf, g)
        mode = "<b class=ok>provider</b>" if g["provider_key_set"] and g["upstream_url"] else "<b class=bad>stub</b> (no provider key/URL: replies are echoes)"
        eps = ""
        for n, ep in sorted(g["endpoints"].items()):
            edit = form("/gateway/endpoints", csrf, f'<input type=hidden name=name value="{e(n)}"><input name=model value="{e(ep["model"])}" size=24> <input name=apps value="{e(" ".join(ep["apps"]))}" size=20 placeholder="app names"> <input name=rpm type=number min=1 value="{ep["rpm"]}" size=5> rpm ', "Save", "ghost")
            delete = form("/gateway/endpoints", csrf, f'<input type=hidden name=name value="{e(n)}"><input type=hidden name=delete value=1>', "Delete", "ghost")
            eps += f'<tr><td><code>{e(n)}</code></td><td>{edit} {delete}</td></tr>'
        new = form("/gateway/endpoints", csrf, '<input name=name placeholder="chat-fast" required> <input name=model placeholder="provider/model-id" required size=24> <input name=apps placeholder="app names" size=20> <input name=rpm type=number min=1 value=60 size=5> rpm ', "Create endpoint")
        use = "".join(f'<tr><td><code>{e(k.split("|")[0])}</code></td><td>{e(k.split("|")[1])}</td><td>{u["requests"]}</td><td>{u["rejected"]}</td><td>{u["prompt_tokens"]}</td><td>{u["completion_tokens"]}</td></tr>' for k, u in sorted(g["usage"].items()))
        if not GENERIC_GATEWAY:
            return "Open Bedrock", (f'<div class=card><b>Initiate AI: provider and key</b><p>One key for this cloud. Apps that ask for it on their service page get it as <code>/run/secrets/&lt;NAME&gt;</code> (for example an AI gateway app you deploy). It is never shown again after saving. Apps using it: {e(", ".join(g.get("provider_key_apps") or []) or "none")}.</p>{prov}</div>'
                    '<div class=card>The built-in generic gateway (named model endpoints, per-app keys) is turned off on this install (<code>OC_GENERIC_GATEWAY=0</code>).</div>')
        return "Open Bedrock", (f'<div class=card>Apps call <code>http://llm-gateway:8000/v1/chat/completions</code> (OpenAI-compatible) with <code>/run/secrets/LLM_GATEWAY_KEY</code> and an endpoint name as <code>model</code>. Only the gateway holds the provider key. Mode: {mode}. Apps with keys: {e(", ".join(g["apps"]) or "none")} (enable on the service page).</div>'
                f'<div class=card><b>Initiate AI: provider and key</b><p>One key for this cloud. Open Bedrock uses it, and apps that ask for it on their service page get it as <code>/run/secrets/&lt;NAME&gt;</code>. It is never shown again after saving. Apps using it: {e(", ".join(g.get("provider_key_apps") or []) or "none")}.</p>{prov}</div>'
                f'<div class=card><b>Model endpoints</b> (name → provider model id, enabled apps, per-app limit)<table>{eps}</table><p>{new}</p></div>'
                f'<div class=card><b>Usage</b><table><tr><th>Endpoint</th><th>App</th><th>Requests</th><th>Rate-limited</th><th>Prompt tokens</th><th>Completion tokens</th></tr>{use or "<tr><td colspan=6>No calls yet.</td></tr>"}</table></div>')
    if path == "/sites":
        new = form("/sites", csrf, '<input name=name placeholder="site-name" required pattern="[a-z][a-z0-9-]{1,30}"> ', "Create site")
        rows = ""
        for s in agent("GET", "/sites"):
            n = e(s["name"])
            up = (f'<form method=post action="/sites/{n}/upload" enctype="multipart/form-data" style="display:inline"><input type=hidden name=csrf value="{e(csrf)}">'
                  f'<input type=file name=file accept=".html,.htm,.zip" required> <button class=ghost>Upload (replaces the site)</button></form>')
            dom = form(f"/sites/{n}/domains", csrf, f'<input name=domains value="{e(" ".join(s["domains"]))}" placeholder="example.com www.example.com" size=34> '
                       f'<label><input type=checkbox name=tls_internal value=1{" checked" if s.get("tls_internal") else ""}> DNS not ready (preview certificate)</label> ', "Save domains", "ghost")
            dns = "".join(f"<li><code>{e(d)}</code> → A record <code>{e(PUBLIC_IP or 'your server IP')}</code></li>" for d in s["domains"]) or "<li>No domains yet.</li>"
            dele = form(f"/sites/{n}/delete", csrf, "", "Delete site", "ghost")
            rows += (f'<div class=card><b>{n}</b> · {e(s.get("visibility", "external"))} · release <code>{e(s.get("release") or "none yet")}</code>'
                     f'<p>{up}</p><p>{dom}</p><b>DNS records to set</b><ul>{dns}</ul>{dele}</div>')
        return "Static sites", (f'<div class=card>Host plain HTML/CSS/JS sites. Files are kept in private object storage and served by the edge with HTTPS, '
                                f'security headers, caching, a 404 page and no directory listing. Upload one .html file (becomes index.html) or a .zip '
                                f'(max 10 MB, 50 MB unpacked) with index.html at the top. {new}</div>{rows or "<div class=card>No sites yet.</div>"}')
    if path == "/dns":
        rows = ""
        for r in agent("GET", "/dns"):
            to = (f'app <a href="/loadbalancers/{e(r["app"])}">{e(r["app"])}</a>' if r["app"] else f'static site <a href="/sites">{e(r["site"])}</a>' if r["site"]
                  else "console" if r["file"] == "Caddyfile" else f'{e(" ".join(r["targets"]))} <small>(hand-managed {e(r["file"])})</small>')
            cfg = f'<details><summary>{e(r["file"])}</summary><pre>{e(r["config"])}</pre></details>' if r["config"] else ""
            status = "<br>".join(f"<span class=bad>{e(x)}</span>" for x in r["problems"]) or "<span class=ok>ok</span>"
            rows += (f'<tr><td>{e(r["domain"])}</td><td>{e(", ".join(r["resolves"]) or "not resolving")}</td><td>{to}</td>'
                     f'<td class={"ok" if r["cert"] == "issued" else "bad"}>{e(r["cert"])}</td><td>{status}</td><td>{cfg}</td></tr>')
        apps = [a["name"] for a in agent("GET", "/apps") if a.get("visibility", "external") == "external"]
        sites = agent("GET", "/sites")
        opts = "".join(f'<option value="app:{e(n)}">app {e(n)}</option>' for n in apps) + "".join(f'<option value="site:{e(x["name"])}">static site {e(x["name"])}</option>' for x in sites)
        add = form("/dns/add", csrf, f'<select name=target required>{opts}</select> <input name=domain placeholder="example.com" required size=30> ', "Add domain") if opts else "No external apps or static sites yet."
        acts = ""
        for x in sites:
            n = e(x["name"])
            if x.get("tls_internal"):
                acts += f'<p>{n}: preview certificate is on. {form(f"/sites/{n}/real-cert", csrf, "", "Switch to real certificate", "ghost")}</p>'
            if any(d.startswith("www.") and d[4:] in x["domains"] for d in x["domains"]):
                on = bool(x.get("www_redirect"))
                acts += (f'<p>{n}: www {"redirects to the main domain" if on else "serves its own copy"}. '
                         f'{form(f"/sites/{n}/www-redirect", csrf, f"<input type=hidden name=on value={0 if on else 1}>", "Stop redirecting www" if on else "Redirect www to the main domain", "ghost")}</p>')
        return "DNS", (f'<div class=card>Each domain from DNS to app: what it resolves to (looked up from this server), where the edge sends it, its certificate and its Caddy config (read-only, secrets redacted). '
                       f'Point domains with an A record to <code>{e(PUBLIC_IP or "your server IP")}</code> at your DNS provider; a wildcard <code>*.{e(APPS_DOMAIN)}</code> covers every app. Open Cloud never changes DNS records.</div>'
                       f'<div class=card><table><tr><th>Domain</th><th>Resolves to</th><th>Routed to</th><th>Certificate</th><th>Status</th><th>Config</th></tr>{rows or "<tr><td colspan=6>No domains yet.</td></tr>"}</table></div>'
                       f'<div class=card><b>Add a domain</b> to an external app or a static site<p>{add}</p>{acts}'
                       f'<p><small>Each change is written to that app\'s or site\'s own edge file, checked with <code>caddy validate</code>, reloaded, and put back automatically if anything fails. Hand-managed files are never changed here.</small></p></div>')
    raise LookupError


def cw_key(f):
    """New subscriber key: stored by the watch service, delivered to the app as secrets (restarts it). Never shown."""
    app = f.get("app", "")
    key = watch("POST", "/admin/keys", {"app": app})["key"]
    agent("POST", f"/apps/{app}/secrets", {"key": "CLOUDWATCH_URL", "value": "http://cloudwatch:8100"})
    agent("POST", f"/apps/{app}/secrets", {"key": "CLOUDWATCH_KEY", "value": key})
    return {"ok": True}


ACTIONS = {"/cloudwatch/rules": lambda f: watch("POST", "/admin/rules", {k: f.get(k, "") for k in ("name", "kind", "target", "threshold", "minutes", "cooldown")}),
           "/cloudwatch/rules-delete": lambda f: watch("POST", "/admin/rules-delete", {"id": f.get("id", "0")}),
           "/cloudwatch/smtp": lambda f: watch("POST", "/admin/smtp", {**{k: f.get(k, "") for k in ("host", "port", "user", "from", "to", "tls", "password")}, "clear_password": bool(f.get("clear_password"))}),
           "/cloudwatch/smtp-test": lambda f: watch("POST", "/admin/smtp-test", {}),
           "/cloudwatch/keys": cw_key,
           "/cloudwatch/keys-revoke": lambda f: watch("POST", "/admin/keys-revoke", {"app": f.get("app", "")}),
           "/apps": lambda f: agent("POST", "/apps", {k: f.get(k, "") for k in APP_FIELDS}),
           "/backups": lambda f: agent("POST", "/backup", {}),
           "/gateway/provider": lambda f: agent("POST", "/gateway-provider", {"provider": f.get("provider", ""), "upstream_url": f.get("upstream_url", ""), "key": f.get("key", ""), "clear_key": bool(f.get("clear_key"))}),
           "/gateway/endpoints": lambda f: agent("POST", "/gateway-endpoint", {k: f.get(k, "") for k in ("name", "model", "apps", "rpm", "delete")})}


class Handler(BaseHTTPRequestHandler):
    def session(self):
        for part in self.headers.get("Cookie", "").split(";"):
            k, _, v = part.strip().partition("=")
            s = sessions.get(v) if k == "oc_session" else None
            if s and s["expires"] > time.time():
                return v, s
        return None, None

    def send(self, code, body="", headers=()):
        b = body.encode()
        self.send_response(code)
        for k, v in [("Content-Type", "text/html; charset=utf-8"), ("Cache-Control", "no-store"),
                     ("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'"),
                     *headers]:
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def redirect(self, to, headers=()):
        self.send(303, "", [("Location", to), *headers])

    def login_page(self, flash=None):
        code = '<p><input name=code autocomplete=one-time-code placeholder="6-digit code (or a recovery code)" required></p>' if load_totp() else ""
        self.send(200 if not flash else 401, page("Sign in", f'<div class=card><form method=post action=/login><p><input name=password type=password placeholder="Admin password" required autofocus></p>{code}<button>Sign in</button></form></div>', flash=flash, err=True))

    def password_page(self, csrf, flash=None, code=200):
        first = must_change()
        intro = ("<p>You signed in with the installer-generated password. Choose your own password to continue.</p>" if first
                 else "<p>Change the admin password.</p>")
        f = (f'<form method=post action=/account/password><input type=hidden name=csrf value="{e(csrf)}">'
             '<p><input name=current type=password placeholder="Current password" required autocomplete=current-password autofocus></p>'
             f'<p><input name=new type=password placeholder="New password (at least {MIN_PASSWORD} characters)" required minlength={MIN_PASSWORD} autocomplete=new-password></p>'
             '<p><input name=confirm type=password placeholder="New password again" required autocomplete=new-password></p>'
             '<button>Save password</button></form>')
        self.send(code, page("Choose your password" if first else "Change password", f"<div class=card>{intro}{f}</div>", csrf, flash, bool(flash)))

    def twostep_page(self, s, flash=None, code=200):
        t = load_totp()
        if t:
            body = (f'<div class=card><b class=ok>Two-step login is on.</b> Signing in needs your password and a code from your authenticator app. '
                    f'Unused recovery codes: {len(t["recovery"])}.</div><div class=card>Lost your phone? On the server, in the Open Cloud folder: '
                    '<code>sudo ./opencloud disable-totp</code>, then set it up again here.</div>')
            return self.send(code, page("Two-step login", body, s["csrf"], flash, bool(flash)))
        sec = s.setdefault("totp_pending", base64.b32encode(secrets.token_bytes(20)).decode())
        uri = f"otpauth://totp/OpenCloud:admin?secret={sec}&issuer=OpenCloud"
        body = ('<div class=card>Two-step login is <b>off</b>. Turn it on so signing in needs your password and a 6-digit code from an authenticator app '
                '(Google Authenticator, Microsoft Authenticator, Authy, 1Password, Bitwarden, ...).</div>'
                f'<div class=card><b>1. Scan this QR code</b> in your authenticator app<p>{totp_qr(uri)}</p>'
                f'<p>Or enter this setup key by hand (time-based, 6 digits, 30 seconds): <code>{e(" ".join(sec[i:i + 4] for i in range(0, len(sec), 4)))}</code></p></div>'
                '<div class=card><b>2. Confirm</b><form method=post action=/account/2fa>'
                f'<input type=hidden name=csrf value="{e(s["csrf"])}"><p><input name=password type=password placeholder="Admin password" required autocomplete=current-password></p>'
                '<p><input name=code inputmode=numeric autocomplete=one-time-code placeholder="6-digit code from the app" required></p>'
                '<button>Turn on two-step login</button></form><p><small>Other signed-in sessions end when it turns on.</small></p></div>')
        self.send(code, page("Two-step login", body, s["csrf"], flash, bool(flash)))

    def do_GET(self):
        tok, s = self.session()
        path = self.path.split("?")[0]
        if path == "/healthz":
            return self.send(200, "ok")
        if not s:
            return self.login_page()
        if must_change() and not allowed_while_must_change(path):
            return self.redirect("/account/password")
        if path == "/account/password":
            return self.password_page(s["csrf"])
        if path == "/account/2fa":
            return self.twostep_page(s)
        q = parse_qs(self.path.partition("?")[2])
        try:
            title, body = view(path, s["csrf"], {k: v[0] for k, v in q.items()})
            self.send(200, page(title, body, s["csrf"], q.get("msg", [None])[0], q.get("err") == ["1"]))
        except LookupError:
            self.send(404, page("Not found", "", s["csrf"]))
        except RuntimeError as err:
            self.send(400, page("Error", "", s["csrf"], str(err), True))

    def do_POST(self):
        global PASSWORD_HASH
        n = int(self.headers.get("Content-Length") or 0)
        path = self.path.split("?")[0]
        ctype, files = self.headers.get("Content-Type", ""), {}
        if ctype.startswith("multipart/form-data") and re.fullmatch(r"/sites/[a-z][a-z0-9-]{1,30}/upload", path):
            if n > SITE_UPLOAD_MAX:
                return self.redirect("/sites?err=1&msg=" + quote("Upload is larger than 10 MB."))
            f, files = parse_multipart(ctype, self.rfile.read(n))
        else:
            f = {k: v[0] for k, v in parse_qs(self.rfile.read(min(n, 100000)).decode()).items()}
        if path == "/login":
            ip = client_ip(self.headers.get("X-Forwarded-For"), self.client_address[0])
            if rate_limited(ip):
                return self.login_page("Too many attempts. Wait 5 minutes.")
            if account_limited():
                audit("login", ip, outcome="account-limited")
                return self.login_page("Too many failed sign-ins on this account. Wait 15 minutes.")
            # One form, both factors: there is no half-signed-in state. The code is checked only after the password.
            if not verify_password(f.get("password", ""), PASSWORD_HASH) or not second_factor_ok(f.get("code")):
                attempts.setdefault(ip, []).append(time.time())
                account_failures.append(time.time())
                audit("login", ip, outcome="failed")
                return self.login_page("Wrong password or code.")
            audit("login", ip)
            tok = secrets.token_urlsafe(32)
            sessions[tok] = {"csrf": secrets.token_urlsafe(32), "expires": time.time() + SESSION_TTL}
            return self.redirect("/", [("Set-Cookie", f"oc_session={tok}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age={SESSION_TTL}")])
        tok, s = self.session()
        if not s or not hmac.compare_digest(f.get("csrf", ""), s["csrf"]):
            return self.send(403, page("Forbidden", "<p>Session expired or invalid form. Sign in again.</p>"))
        ip = client_ip(self.headers.get("X-Forwarded-For"), self.client_address[0])
        if path == "/account/password":
            err = password_problem(f.get("current", ""), f.get("new", ""), f.get("confirm", ""), PASSWORD_HASH)
            if err:
                audit("password-change", ip, outcome="rejected")
                return self.password_page(s["csrf"], err, 400)
            try:
                PASSWORD_HASH = set_password(f["new"])
            except OSError as ex:
                audit("password-change", ip, outcome="error")
                return self.password_page(s["csrf"], f"Couldn't save the password ({ex.__class__.__name__}). Check that the console owns its auth directory.", 500)
            audit("password-change", ip)
            sessions.clear()  # every other session ends; this one is replaced with a fresh token
            new = secrets.token_urlsafe(32)
            sessions[new] = {"csrf": secrets.token_urlsafe(32), "expires": time.time() + SESSION_TTL}
            return self.redirect("/?msg=" + quote("Password changed."), [("Set-Cookie", f"oc_session={new}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age={SESSION_TTL}")])
        if must_change() and not allowed_while_must_change(path):
            return self.redirect("/account/password")
        if path == "/account/2fa":
            pend = s.get("totp_pending")
            if load_totp() or not pend:
                return self.redirect("/account/2fa")
            if rate_limited(ip):
                return self.twostep_page(s, "Too many attempts. Wait 5 minutes.", 429)
            c = verify_totp(pend, (f.get("code") or "").replace(" ", "")) if verify_password(f.get("password", ""), PASSWORD_HASH) else 0
            if not c:
                attempts.setdefault(ip, []).append(time.time())
                audit("2fa-enable", ip, outcome="rejected")
                return self.twostep_page(s, "Wrong password or code. Check the phone's clock if codes keep failing.", 400)
            codes = new_recovery_codes()
            save_totp({"secret": pend, "last": c, "recovery": [recovery_hash(x) for x in codes]})
            s.pop("totp_pending")
            for k in [k for k in sessions if k != tok]:
                sessions.pop(k)
            audit("2fa-enable", ip)
            return self.send(200, page("Two-step login is on", '<div class=card><b>Save these recovery codes now.</b> Each one signs you in once instead of a 6-digit code '
                                       'if you lose your phone. They are not shown again.<pre>' + "\n".join(codes) + '</pre><a href="/">Continue</a></div>', s["csrf"]))
        if path == "/logout":
            audit("logout", ip)
            sessions.pop(tok, None)
            return self.redirect("/", [("Set-Cookie", "oc_session=; Max-Age=0; Path=/; Secure; HttpOnly")])
        dm = re.fullmatch(r"/dns/add|/sites/[a-z][a-z0-9-]{1,30}/(real-cert|www-redirect)", path)
        if dm:
            body = {"target": f.get("target", ""), "domain": f.get("domain", "")} if path == "/dns/add" else {"on": f.get("on") == "1"}
            target = path + " " + " ".join(f"{k}={v}" for k, v in body.items())
            try:
                agent("POST", "/domain-add" if path == "/dns/add" else path, body)
                audit("action", ip, target)
                return self.redirect("/dns?msg=" + quote("Done."))
            except (RuntimeError, OSError) as err:
                audit("action", ip, target, "error: " + str(err)[:200])
                return self.redirect("/dns?err=1&msg=" + quote(str(err)[:500]))
        sm = re.fullmatch(r"/sites(?:/([a-z][a-z0-9-]{1,30})/(upload|domains|delete))?", path)
        if sm:
            target = path + (f" name={f.get('name', '')}" if not sm.group(1) else f" domains={f.get('domains', '')} preview_tls={bool(f.get('tls_internal'))}" if sm.group(2) == "domains"
                             else f" file={files.get('file', ('', b''))[0]} bytes={len(files.get('file', ('', b''))[1])}" if sm.group(2) == "upload" else "")
            try:
                if not sm.group(1):
                    agent("POST", "/sites", {"name": f.get("name", "")})
                elif sm.group(2) == "upload":
                    fn, data = files.get("file", ("", b""))
                    agent("POST", path, {"filename": fn, "data": base64.b64encode(data).decode()})
                elif sm.group(2) == "domains":
                    agent("POST", path, {"domains": f.get("domains", ""), "tls_internal": bool(f.get("tls_internal"))})
                else:
                    agent("POST", path, {})
                audit("action", ip, target)
                return self.redirect("/sites?msg=" + quote("Done."))
            except (RuntimeError, OSError) as err:
                audit("action", ip, target, "error: " + str(err)[:200])
                return self.redirect("/sites?err=1&msg=" + quote(str(err)[:500]))
        m = re.fullmatch(r"/apps/([a-z][a-z0-9-]{1,30})/(redeploy|rollback|db|secrets|ai|buckets|limits|route|api-discover|api-endpoint|api-check|api-probe|provider-key|visibility|delete)", path)
        back = ((f"/loadbalancers/{m.group(1)}" if m.group(2) == "route" else f"/apps/{m.group(1)}") if m else "/models" if path.startswith("/gateway/")
                else "/cloudwatch/notifications" if path.startswith("/cloudwatch/smtp") else "/cloudwatch/events" if path.startswith("/cloudwatch/keys")
                else "/cloudwatch" if path.startswith("/cloudwatch/") else path)
        try:
            # Secret values go to the agent but are never written to the audit log.
            target = path
            if m and m.group(2) == "secrets":
                target += " key=" + f.get("key", "")
            elif m and m.group(2) == "limits":
                target += f" memory_mb={f.get('memory_mb', '')} cpus={f.get('cpus', '')}"
            elif m and m.group(2) == "visibility":
                target += " visibility=" + f.get("visibility", "")
            elif m and m.group(2) == "provider-key":
                target += " env=" + f.get("env", "")
            elif m and m.group(2) == "buckets":
                target += " bucket=" + f.get("bucket", "")
            elif m and m.group(2) == "delete":
                # The confirmation box is not logged: a mistype might be a secret pasted into the field.
                target += " backup=" + ("on" if f.get("backup") else "off")
            elif path == "/apps":
                target += f" name={f.get('name', '')} repo={f.get('repo', '')} folder={f.get('folder', '')} networks={f.get('networks', '')} mounts={len((f.get('secret_mounts', '') + chr(10) + f.get('data_mounts', '')).split())}"
            elif m and m.group(2) in ("api-discover", "api-endpoint", "api-check"):
                target += " " + " ".join(f"{k}={f.get(k)}" for k in ("spec_path", "method", "path", "enabled") if f.get(k))
            elif m and m.group(2) == "route":
                target += f" domains={f.get('domains', '')} redirect={bool(f.get('redirect'))} health={f.get('health_path', '')}/{f.get('health_interval', '')}s canary={f.get('canary_weight', '')}"
            elif path == "/gateway/provider":  # never the key itself
                target += f" provider={f.get('provider', '')} url={f.get('upstream_url', '')} key={'changed' if f.get('key') else 'cleared' if f.get('clear_key') else 'unchanged'}"
            elif path == "/cloudwatch/smtp":  # never the password itself
                target += " " + " ".join(f"{k}={f.get(k, '')}" for k in ("host", "port", "user", "from", "to", "tls")) + f" password={'changed' if f.get('password') else 'cleared' if f.get('clear_password') else 'unchanged'}"
            elif path.startswith("/cloudwatch/"):
                target += " " + " ".join(f"{k}={f.get(k)}" for k in ("name", "kind", "target", "threshold", "minutes", "cooldown", "id", "app") if f.get(k))
            elif path == "/gateway/endpoints":
                target += f" name={f.get('name', '')} model={f.get('model', '')} apps={f.get('apps', '')} rpm={f.get('rpm', '')}" + (" delete" if f.get("delete") else "")
            if m:
                if m.group(2) == "delete" and f.get("confirm", "") != m.group(1):
                    raise RuntimeError("Type the app name to confirm deletion.")
                body = {"secrets": {"key": f.get("key", ""), "value": f.get("value", "")},
                        "route": {k: f.get(k, "") for k in ("domains", "redirect", "health_path", "health_interval", "canary_weight")},
                        "api-discover": {"spec_path": f.get("spec_path", "")},
                        "api-endpoint": {k: f.get(k, "") for k in ("method", "path", "summary")},
                        "api-check": {"path": f.get("path", ""), "enabled": bool(f.get("enabled"))},
                        "api-probe": {},
                        "provider-key": {"env": f.get("env", "")},
                        "visibility": {"visibility": f.get("visibility", "")},
                        "limits": {"memory_mb": f.get("memory_mb"), "cpus": f.get("cpus")},
                        "delete": {"confirm": m.group(1), "backup": bool(f.get("backup"))}}.get(m.group(2), {"bucket": f.get("bucket", "")})
                res = agent("POST", path, body)
                if m.group(2) == "delete":
                    try:
                        watch("POST", "/admin/keys-revoke", {"app": m.group(1)})
                    except (RuntimeError, OSError):
                        res = {**res, "steps": list(res.get("steps") or []) + [{"step": "cloudwatch_key", "status": "kept", "detail": "subscriber key revoke failed"}]}
                    back = "/apps"
            elif path in ACTIONS:
                res = ACTIONS[path](f)
                back = f"/apps/{f.get('name')}" if path == "/apps" else back
            else:
                return self.send(404, page("Not found", "", s["csrf"]))
            audit("action", ip, target)
            if isinstance(res, dict) and res.get("status") == "running":
                return self.redirect(f"/jobs/{res['id']}")
            done = delete_flash(res) if isinstance(res, dict) and res.get("deleted") else "Done."
            self.redirect(back + "?msg=" + quote(done))
        except (RuntimeError, OSError) as err:
            audit("action", ip, target, "error: " + str(err)[:200])
            self.redirect(("/apps" if path == "/apps" else back) + "?err=1&msg=" + quote(str(err)[:500]))

    def log_message(self, fmt, *a):
        print(f"{self.command} {self.path.split('?')[0]} {a[1] if len(a) > 1 else ''}", flush=True)


if __name__ == "__main__":
    TOKEN = Path(os.environ["OC_AGENT_TOKEN_FILE"]).read_text().strip()
    PASSWORD_HASH = HASH_FILE.read_text().strip()
    WATCH_TOKEN = Path(os.environ.get("OC_WATCH_TOKEN_FILE", "/run/oc/watch-token")).read_text().strip()
    ThreadingHTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
