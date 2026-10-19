import json, os, sys, unittest
from pathlib import Path
sys.path[:0] = [str(Path(__file__).parents[1] / d) for d in ("console", "agent", "watch")]
import console, agent, watch


class ConsoleAuth(unittest.TestCase):
    def test_password_hash_roundtrip(self):
        h = console.hash_password("s3cret")
        self.assertTrue(console.verify_password("s3cret", h))
        self.assertFalse(console.verify_password("wrong", h))
        self.assertFalse(console.verify_password("x", "garbage"))

    def test_rate_limit_after_five(self):
        console.attempts["1.2.3.4"] = [100.0] * 5
        self.assertTrue(console.rate_limited("1.2.3.4", now=101))
        self.assertFalse(console.rate_limited("1.2.3.4", now=1000))


class PasswordChange(unittest.TestCase):
    def setUp(self):
        import tempfile
        self.d = Path(tempfile.mkdtemp())
        self.hash, self.flag = self.d / "admin-password.scrypt", self.d / "must-change-password"
        self.hash.write_text(console.hash_password("installer-generated"))
        self.flag.touch()

    def test_flag_detected(self):
        self.assertTrue(console.must_change(self.flag))
        self.flag.unlink()
        self.assertFalse(console.must_change(self.flag))

    def test_rules(self):
        h = self.hash.read_text()
        p = console.password_problem
        self.assertIn("current", p("wrong", "correct horse battery", "correct horse battery", h))
        self.assertIn("12", p("installer-generated", "short", "short", h))
        self.assertIn("match", p("installer-generated", "correct horse battery", "correct horse batterY", h))
        self.assertIn("different", p("installer-generated", "installer-generated", "installer-generated", h))
        self.assertIsNone(p("installer-generated", "correct horse battery", "correct horse battery", h))

    def test_set_password_writes_hash_clears_flag(self):
        new = console.set_password("correct horse battery", self.hash, self.flag)
        self.assertFalse(self.flag.exists())
        self.assertEqual(self.hash.read_text().strip(), new)
        self.assertTrue(console.verify_password("correct horse battery", new))
        self.assertFalse(console.verify_password("installer-generated", new))
        self.assertEqual(self.hash.stat().st_mode & 0o777, 0o600)
        self.assertEqual(sorted(x.name for x in self.d.iterdir()), ["admin-password.scrypt"])  # no temp file left

    def test_gate_allows_only_change_and_logout(self):
        for path in ("/account/password", "/logout"):
            self.assertTrue(console.allowed_while_must_change(path))
        for path in ("/", "/apps", "/status", "/account/password/../apps", "/logout2"):
            self.assertFalse(console.allowed_while_must_change(path))


class Totp(unittest.TestCase):
    SECRET = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"  # RFC 6238 test key "12345678901234567890"

    def test_rfc_vector(self):
        self.assertEqual(console.totp(self.SECRET, 1), "287082")  # T=59s

    def test_accept_once_window_and_reject_wrong(self):
        now = 1_000_000_000
        step = now // 30
        self.assertEqual(console.verify_totp(self.SECRET, "000000", now), 0)
        self.assertEqual(console.verify_totp(self.SECRET, console.totp(self.SECRET, step), now), step)
        self.assertEqual(console.verify_totp(self.SECRET, console.totp(self.SECRET, step), now, last=step), 0)  # replay
        self.assertEqual(console.verify_totp(self.SECRET, console.totp(self.SECRET, step + 1), now), step + 1)  # +1 step ok
        self.assertEqual(console.verify_totp(self.SECRET, console.totp(self.SECRET, step - 2), now), 0)  # too old


class TwoStep(unittest.TestCase):
    SECRET = Totp.SECRET

    def setUp(self):
        import tempfile
        self.f = Path(tempfile.mkdtemp()) / "totp.json"
        self.codes = console.new_recovery_codes()
        console.save_totp({"secret": self.SECRET, "last": 0, "recovery": [console.recovery_hash(c) for c in self.codes]}, self.f)

    def test_off_without_file(self):
        self.assertTrue(console.second_factor_ok("", path=self.f.with_name("none.json")))

    def test_code_once_survives_reload(self):
        now = 1_000_000_000
        code = console.totp(self.SECRET, now // 30)
        self.assertFalse(console.second_factor_ok("", now, self.f))
        self.assertFalse(console.second_factor_ok("123456", now, self.f))
        self.assertTrue(console.second_factor_ok(code, now, self.f))
        self.assertFalse(console.second_factor_ok(code, now, self.f))  # reuse refused, read back from the file
        self.assertEqual(self.f.stat().st_mode & 0o777, 0o600)

    def test_recovery_code_once(self):
        self.assertEqual(len(self.codes), 8)
        self.assertNotIn(self.codes[0], self.f.read_text())  # only hashes stored
        self.assertTrue(console.second_factor_ok(self.codes[0].upper().replace("-", " "), path=self.f))
        self.assertFalse(console.second_factor_ok(self.codes[0], path=self.f))
        self.assertEqual(len(console.load_totp(self.f)["recovery"]), 7)

    def test_qr_is_inline_svg(self):
        self.assertTrue(console.totp_qr("otpauth://totp/OpenCloud:admin?secret=" + self.SECRET).startswith("<svg"))


class TwoStepLogin(unittest.TestCase):
    """Through the real handler: a right password without the code gets no session, and nothing works without one."""
    def setUp(self):
        import tempfile, threading
        from http.server import ThreadingHTTPServer
        d = Path(tempfile.mkdtemp())
        console.TOTP_FILE = d / "totp.json"
        console.save_totp({"secret": Totp.SECRET, "last": 0, "recovery": []})
        console.PASSWORD_HASH = console.hash_password("pw-for-tests")
        console.MUST_CHANGE_FILE = d / "must-change-password"
        console.audit = lambda *a, **k: None
        console.attempts.clear(); console.account_failures.clear(); console.sessions.clear()
        self.srv = ThreadingHTTPServer(("127.0.0.1", 0), console.Handler)
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.url = f"http://127.0.0.1:{self.srv.server_address[1]}"

    def tearDown(self):
        self.srv.shutdown(); self.srv.server_close()

    def req(self, path, data=None, cookie=""):
        import urllib.request, urllib.error
        from urllib.parse import urlencode
        r = urllib.request.Request(self.url + path, data=urlencode(data).encode() if data is not None else None, headers={"Cookie": cookie})
        opener = urllib.request.build_opener(type("NoRedirect", (urllib.request.HTTPRedirectHandler,), {"redirect_request": lambda *a: None}))
        try:
            with opener.open(r) as res:
                return res.status, res.headers, res.read().decode()
        except urllib.error.HTTPError as err:
            return err.code, err.headers, err.read().decode()

    def test_password_alone_gets_no_session(self):
        code, h, body = self.req("/login", {"password": "pw-for-tests"})
        self.assertEqual(code, 401)
        self.assertIsNone(h.get("Set-Cookie"))
        self.assertEqual(console.sessions, {})
        self.assertIn("6-digit code", self.req("/")[2])  # still the sign-in page
        self.assertIn("6-digit code", self.req("/account/2fa")[2])
        self.assertEqual(self.req("/account/2fa", {"code": "1"})[0], 403)

    def test_password_and_code_then_reuse(self):
        import time
        code = console.totp(Totp.SECRET, int(time.time() // 30))
        st, h, _ = self.req("/login", {"password": "pw-for-tests", "code": code})
        self.assertEqual(st, 303)
        cookie = h["Set-Cookie"].split(";")[0]
        self.assertIn("Two-step login is on", self.req("/account/2fa", cookie=cookie)[2])
        self.assertEqual(self.req("/login", {"password": "pw-for-tests", "code": code})[0], 401)  # same code again
        self.assertEqual(self.req("/login", {"password": "wrong", "code": code})[0], 401)

    def test_setup_page_and_enable(self):
        import time
        console.TOTP_FILE.unlink()  # two-step login off: password alone signs in (not enforced before setup)
        st, h, _ = self.req("/login", {"password": "pw-for-tests"})
        self.assertEqual(st, 303)
        cookie = h["Set-Cookie"].split(";")[0]
        s = next(iter(console.sessions.values()))
        page = self.req("/account/2fa", cookie=cookie)[2]
        self.assertIn("<svg", page)
        sec = s["totp_pending"]
        self.assertFalse(console.TOTP_FILE.exists())
        bad = self.req("/account/2fa", {"csrf": s["csrf"], "password": "pw-for-tests", "code": "000000"}, cookie)
        self.assertEqual(bad[0], 400)
        self.assertFalse(console.TOTP_FILE.exists())
        ok = self.req("/account/2fa", {"csrf": s["csrf"], "password": "pw-for-tests", "code": console.totp(sec, int(time.time() // 30))}, cookie)
        self.assertEqual(ok[0], 200)
        self.assertIn("recovery codes", ok[2])
        t = console.load_totp()
        self.assertEqual((t["secret"], len(t["recovery"])), (sec, 8))
        self.assertEqual(console.TOTP_FILE.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.req("/login", {"password": "pw-for-tests"})[0], 401)  # now enforced


class Audit(unittest.TestCase):
    def test_hash_chain_detects_edit(self):
        import tempfile
        agent.ROOT = Path(tempfile.mkdtemp())
        (agent.ROOT / "audit").mkdir()
        for i in range(3):
            agent.audit_append({"event": "action", "target": f"/x{i}", "ip": "1.2.3.4"})
        self.assertEqual(agent.audit_read(), {**agent.audit_read(), "intact": True, "count": 3})
        p = agent.audit_path()
        p.write_text(p.read_text().replace("/x1", "/xx"))
        self.assertFalse(agent.audit_read()["intact"])


class SecretFiles(unittest.TestCase):
    def test_written_0400_and_replaced_atomically(self):
        import tempfile
        p = Path(tempfile.mkdtemp()) / "KEY"
        me = (os.getuid(), os.getgid())
        agent.write_secret(p, "one", me)
        agent.write_secret(p, "two", me)  # overwrite a 0400 file
        self.assertEqual(p.read_text(), "two")
        self.assertEqual(p.stat().st_mode & 0o777, 0o400)


class AgentValidation(unittest.TestCase):
    def test_names(self):
        for bad in ["", "A", "x", "../etc", "a b", "a;rm", "-a"]:
            with self.assertRaises(agent.Bad):
                agent.app_dir(bad)
        agent.app_dir("my-app")
        for reserved in ["s3", "console", "storage"]:
            with self.assertRaises(agent.Bad):
                agent.app_dir(reserved)

    def test_bucket_names(self):
        self.assertTrue(agent.BUCKET.match("my-bucket"))
        for bad in ["ab", "Upper", "a_b", "-x", "a" * 64, "x;y"]:
            self.assertFalse(agent.BUCKET.match(bad), bad)

    def test_repo_urls(self):
        self.assertTrue(agent.REPO.match("https://github.com/org/repo.git"))
        for bad in ["http://x.com/a", "file:///etc", "ssh://git@x/a", "https://x.com/a b", "--upload-pack=x", "https://x.com/a;b"]:
            self.assertFalse(agent.REPO.match(bad), bad)

    def test_compose_has_no_ports_and_is_hardened(self):
        agent.ROOT = Path(os.environ.get("TMPDIR", "/tmp")) / "oc-unit"
        app = {"name": "demo", "port": 8080, "image_tag": "abc", "db": True}
        doc = agent.compose(app)
        for s in doc["services"].values():
            self.assertNotIn("ports", s)
            self.assertEqual(s["cap_drop"], ["ALL"])
        self.assertTrue(doc["networks"]["db"]["internal"])
        self.assertNotIn("edge", doc["services"]["db"]["networks"])


class ManagedDbRoles(unittest.TestCase):
    def setUp(self):
        import tempfile
        agent.ROOT = Path(tempfile.mkdtemp())
        self.app = {"name": "demo", "port": 8080, "image_tag": "abc", "db": True}

    def test_runtime_sql_is_least_privilege(self):
        sql = agent.RUNTIME_ROLE_SQL
        for want in ("NOSUPERUSER", "NOCREATEDB", "NOCREATEROLE", "GRANT CONNECT ON DATABASE app TO app_runtime",
                     "GRANT USAGE ON SCHEMA public TO app_runtime", "SELECT, INSERT, UPDATE, DELETE ON ALL TABLES",
                     "USAGE, SELECT ON ALL SEQUENCES", "ALTER DEFAULT PRIVILEGES FOR ROLE app"):
            self.assertIn(want, sql)
        self.assertNotIn("ALL PRIVILEGES", sql)
        self.assertIn("cat /run/secrets/DB_RUNTIME_PASSWORD", sql)  # password never on a command line

    def test_existing_db_gets_runtime_credential_once(self):
        orig = agent.write_secret
        agent.write_secret = lambda path, value, owner=(0, 0): path.write_text(value)
        try:
            (agent.ROOT / "secrets" / "db").mkdir(parents=True)
            self.assertTrue(agent.ensure_db_runtime(self.app))
            url = (agent.secret_dir("demo") / "DATABASE_URL").read_text()
            self.assertTrue(url.startswith("postgresql://app_runtime:"))
            self.assertFalse(agent.ensure_db_runtime(self.app))  # idempotent
            doc = agent.compose(self.app)
            self.assertIn("DB_RUNTIME_PASSWORD", doc["services"]["db"]["secrets"])
            self.assertNotIn("DB_RUNTIME_PASSWORD", doc["services"]["web"]["secrets"])
        finally:
            agent.write_secret = orig


class AppContainment(unittest.TestCase):
    def setUp(self):
        import tempfile
        agent.ROOT = Path(tempfile.mkdtemp())

    def test_health_readonly_tmpfs_from_app_json(self):
        app = {"name": "demo", "port": 8000, "image_tag": "abc",
               "health": {"path": "/api/health", "tool": "python"}, "read_only": True, "tmpfs": ["/tmp"]}
        web = agent.compose(app)["services"]["web"]
        self.assertIn("http://127.0.0.1:8000/api/health", " ".join(web["healthcheck"]["test"]))
        self.assertTrue(web["read_only"])
        self.assertEqual(web["tmpfs"], ["/tmp:size=64m,mode=1777"])

    def test_manifest_shipped_with_app_and_app_json_wins(self):
        src = agent.app_dir("demo") / "src"
        src.mkdir(parents=True)
        (src / "opencloud.json").write_text('{"health": {"path": "/healthz", "tool": "wget"}, "read_only": true, "privileged": true}')
        web = agent.compose({"name": "demo", "port": 3000, "image_tag": "abc"})["services"]["web"]
        self.assertEqual(web["healthcheck"]["test"][-1], "http://127.0.0.1:3000/healthz")
        self.assertNotIn("privileged", web)
        web = agent.compose({"name": "demo", "port": 3000, "image_tag": "abc", "read_only": False})["services"]["web"]
        self.assertNotIn("read_only", web)

    def test_defaults_unchanged_and_bad_values_refused(self):
        web = agent.compose({"name": "demo", "port": 3000, "image_tag": "abc"})["services"]["web"]
        for k in ("healthcheck", "read_only", "tmpfs"):
            self.assertNotIn(k, web)
        for h in ({"path": "/x'; rm -rf /", "tool": "python"}, {"path": "/ok", "tool": "bash"}, "nope"):
            with self.assertRaises(agent.Bad):
                agent.healthcheck(h, 3000)
        for t in (["/etc"], ["/run/secrets/x"], ["relative"], ["/a/../b"]):
            with self.assertRaises(agent.Bad):
                agent.tmpfs_mounts(t)


class Phase25(unittest.TestCase):
    def test_agent_bind_address(self):
        os.environ.pop("OC_AGENT_BIND", None)
        self.assertEqual(agent.bind_address(), "0.0.0.0")
        os.environ["OC_AGENT_BIND"] = "localhost"
        try:
            self.assertEqual(agent.bind_address(), "127.0.0.1")
            orig = agent.socket.gethostbyname
            agent.socket.gethostbyname = lambda h: (_ for _ in ()).throw(OSError("no such host"))
            try:
                with self.assertRaises(SystemExit):  # fail closed: never fall back to all interfaces
                    agent.bind_address(retries=1)
            finally:
                agent.socket.gethostbyname = orig
        finally:
            os.environ.pop("OC_AGENT_BIND", None)

    def test_generic_gateway_off_refuses_enable(self):
        agent.GENERIC_GATEWAY = False
        with self.assertRaises(agent.Bad):
            agent.enable_ai({}, "demo")

    def test_compose_layout(self):
        doc = (Path(__file__).parents[1] / "compose.yaml").read_text()
        self.assertIn("profiles: [gateway]", doc)              # generic gateway is opt-in
        self.assertIn("OC_AGENT_BIND: oc-agent.oc_control", doc)
        self.assertIn("networks: [console, control]", doc)    # console off the shared app network
        self.assertIn("networks: [edge, console]", doc)       # only the edge shares the console network


class OpenApiSpec(unittest.TestCase):
    def test_hostile_spec_kept_as_capped_plain_text(self):
        import json
        bad = "<script>alert(1)</script>"
        raw = json.dumps({"paths": {"/x" + bad: {"get": {"summary": bad * 50}, "trace": {"summary": "skip"}}, "/y": "junk"}})
        eps = agent.parse_openapi(raw)
        self.assertEqual([e["method"] for e in eps], ["GET"])
        self.assertLessEqual(len(eps[0]["summary"]), 200)
        self.assertNotIn("<script>", console.e(eps[0]["summary"]) + console.e(eps[0]["path"]))

    def test_rejects_non_json_oversize_and_no_paths(self):
        for raw in ["<html>", "[]", "x" * (agent.SPEC_MAX + 1)]:
            with self.assertRaises(agent.Bad):
                agent.parse_openapi(raw)

    def test_app_map_renders_numeric_health(self):
        m = {"app": "a", "commit": "abc", "route": {}, "services": {}, "db": False, "buckets": [], "gateway_key": False, "endpoints": [],
             "api": {"spec_path": "/openapi.json", "source": "openapi", "endpoints": [{"method": "GET", "path": "/health", "summary": "<b>"}],
                     "checks": {"/health": {"code": 200, "ms": 3, "checked": "2026-01-01T00:00:00Z"}}}}
        out = console.render_map(m, "t")
        self.assertIn("<span class=ok>200</span> · 3 ms · 2026", out)
        self.assertNotIn("<b>", out.split("Health (status")[1])


class WatchRedaction(unittest.TestCase):
    def test_secrets_never_survive(self):
        lines = ["connecting to postgresql://app:hunter2pass@db:5432/app",
                 "DATABASE_URL=postgresql://app:pw@db/app", "password=abc123 user=x", "Authorization: Bearer abcdef0123456789abcdef",
                 'got {"api_key": "zz-secret-value-123"}', "token: sk-or-v1-0123456789abcdef0123", "aws AKIAABCDEFGHIJKLMNOP",
                 "S3_SECRET_ACCESS_KEY=Qw3rTy/abc+def", "-----BEGIN PRIVATE KEY-----"]
        for raw in lines:
            out = watch.redact(raw)
            for bad in ("hunter2pass", ":pw@", "abc123", "abcdef0123456789abcdef", "zz-secret-value-123", "sk-or-v1-0123", "AKIAABCDEFGHIJKLMNOP", "Qw3rTy", "BEGIN PRIVATE KEY"):
                self.assertNotIn(bad, out, raw)
        self.assertEqual(watch.redact("GET /health 200 in 3 ms"), "GET /health 200 in 3 ms")

    def test_levels(self):
        self.assertEqual(watch.parse_level("ERROR boom"), "error")
        self.assertEqual(watch.parse_level("Traceback (most recent call last):"), "error")
        self.assertEqual(watch.parse_level("level=warning msg=x"), "warn")
        self.assertEqual(watch.parse_level("INFO: started"), "info")
        self.assertEqual(watch.parse_level("plain line"), "info")


class WatchStore(unittest.TestCase):
    def setUp(self):
        self.db = watch.open_db(":memory:")

    def test_metrics_and_retention(self):
        watch.record_metrics(self.db, 1000, [("app:shop", "cpu", 5.0)])
        watch.record_metrics(self.db, 1000 + 8 * 86400, [("app:shop", "cpu", 7.0)])
        watch.purge(self.db, 1000 + 8 * 86400, metric_days=7, log_days=7)
        self.assertEqual(watch.series(self.db, "app:shop", "cpu", 0), [(1000 + 8 * 86400, 7.0)])

    def test_logs_redacted_searchable_and_filtered(self):
        watch.ingest_logs(self.db, [{"ts": 100, "app": "shop", "container": "oc-app-shop-web-1", "text": "ERROR db postgresql://u:topsecret@db/x down"},
                                    {"ts": 200, "app": "blog", "container": "oc-app-blog-web-1", "text": "INFO ok"}])
        self.assertNotIn("topsecret", str(self.db.execute("select * from logs").fetchall()))
        self.assertEqual(len(watch.query_logs(self.db, app="shop")), 1)
        self.assertEqual(len(watch.query_logs(self.db, level="error")), 1)
        self.assertEqual(len(watch.query_logs(self.db, q="ok", since=150)), 1)
        self.assertEqual(watch.query_logs(self.db, q="ok", until=150), [])
        self.assertEqual(watch.query_logs(self.db, q="%"), [])  # LIKE wildcards are literal


class WatchAlarms(unittest.TestCase):
    def setUp(self):
        self.db = watch.open_db(":memory:")
        self.events, self.mails = [], []
        self.pub = lambda topic, data: self.events.append((topic, data))
        self.mail = lambda subj, body: self.mails.append(subj)

    def snap(self, healthy=True, mem=10.0, restarts=0, disk=50.0):
        return {"apps": {"shop": {"cpu": 1.0, "mem": mem, "healthy": healthy, "restarts": restarts}}, "disk_pct": disk,
                "backup": {"last_success": 0, "last_failure": 0}}

    def run_at(self, t, snap):
        return watch.evaluate(self.db, t, snap, self.pub, self.mail)

    def test_unhealthy_for_n_minutes_then_resolved(self):
        watch.save_rule(self.db, {"name": "down", "kind": "unhealthy", "target": "shop", "minutes": 2, "cooldown": 10})
        self.run_at(0, self.snap(healthy=False))
        self.assertEqual(watch.rules(self.db)[0]["state"], "OK")  # breaching, not long enough
        self.assertEqual(self.events[-1][0], "metrics")
        self.run_at(130, self.snap(healthy=False))
        self.assertEqual(watch.rules(self.db)[0]["state"], "ALARM")
        self.assertEqual(self.mails, ["[ALARM] down"])
        self.run_at(200, self.snap(healthy=True))
        self.assertEqual(watch.rules(self.db)[0]["state"], "OK")
        self.assertEqual(self.mails, ["[ALARM] down", "[RESOLVED] down"])
        self.assertEqual([h["state"] for h in watch.history(self.db)], ["OK", "ALARM"])
        self.assertIn(("alarms", "ALARM"), [(t, d.get("state")) for t, d in self.events])

    def test_cooldown_suppresses_repeat_emails(self):
        watch.save_rule(self.db, {"name": "mem", "kind": "mem", "target": "shop", "threshold": 50, "minutes": 0, "cooldown": 10})
        for t, m in [(0, 90), (60, 10), (120, 90)]:
            self.run_at(t, self.snap(mem=m))
        self.assertEqual(self.mails, ["[ALARM] mem", "[RESOLVED] mem"])  # second ALARM inside cooldown: no email
        self.run_at(180, self.snap(mem=10))
        self.run_at(800, self.snap(mem=90))
        self.assertEqual(self.mails[-1], "[ALARM] mem")

    def test_disk_backup_and_restart_loop(self):
        watch.save_rule(self.db, {"name": "disk", "kind": "disk", "threshold": 85})
        watch.save_rule(self.db, {"name": "bk", "kind": "backup_failed"})
        watch.save_rule(self.db, {"name": "stale", "kind": "backup_stale", "threshold": 26})
        watch.save_rule(self.db, {"name": "loop", "kind": "restart_loop", "target": "shop", "threshold": 3, "minutes": 10})
        s = self.snap(disk=90, restarts=0)
        s["backup"] = {"last_success": 100, "last_failure": 200}
        watch.record_metrics(self.db, 0, [("app:shop", "restarts", 0)])
        s["apps"]["shop"]["restarts"] = 4
        self.run_at(100 + 27 * 3600, s)
        self.assertEqual({r["name"]: r["state"] for r in watch.rules(self.db)}, {"disk": "ALARM", "bk": "ALARM", "stale": "ALARM", "loop": "ALARM"})

    def test_rule_validation(self):
        for bad in [{"name": "x", "kind": "nope"}, {"name": "", "kind": "disk"}, {"name": "x", "kind": "cpu", "target": "a;b"}, {"name": "x", "kind": "disk", "threshold": "abc"}]:
            with self.assertRaises(watch.Bad):
                watch.save_rule(self.db, bad)


class WatchPubSub(unittest.TestCase):
    def setUp(self):
        self.db = watch.open_db(":memory:")

    def test_events_scoped_to_own_app(self):
        watch.publish(self.db, "alarms", {"app": "shop", "state": "ALARM"})
        watch.publish(self.db, "audit", {"app": "blog", "event": "action"})
        watch.publish(self.db, "alarms", {"app": "", "state": "ALARM"})  # host-level: admin only
        self.assertEqual([e["topic"] for e in watch.events_for(self.db, "shop", ["alarms", "audit"], 0)], ["alarms"])
        self.assertEqual(watch.events_for(self.db, "shop", ["audit"], 0), [])

    def test_keys(self):
        k = watch.create_key(self.db, "shop")
        self.assertEqual(watch.key_app(self.db, k), "shop")
        self.assertIsNone(watch.key_app(self.db, "wrong"))
        watch.revoke_key(self.db, "shop")
        self.assertIsNone(watch.key_app(self.db, k))

    def test_webhook_signature_and_url_policy(self):
        sig = watch.sign("k", "1700000000", b'{"x":1}')
        self.assertTrue(watch.verify("k", "1700000000", b'{"x":1}', sig))
        self.assertFalse(watch.verify("k", "1700000000", b'{"x":2}', sig))
        self.assertTrue(watch.webhook_ok("shop", "http://app-shop:8000/hook"))
        for bad in ["http://app-blog:8000/hook", "http://169.254.169.254/", "https://evil.example/x", "http://app-shop:8000/x?y=1", "http://app-shop@evil:1/"]:
            self.assertFalse(watch.webhook_ok("shop", bad), bad)

    def test_webhook_retries_then_gives_up(self):
        watch.create_key(self.db, "shop")
        watch.subscribe(self.db, "shop", "http://app-shop:8000/hook", ["alarms"])
        watch.publish(self.db, "alarms", {"app": "shop", "state": "ALARM"})
        calls = []
        def post(url, body, headers):
            calls.append(headers["X-OC-Signature"])
            return 500
        for t in (0, 10, 100, 1000, 10000, 100000):
            watch.deliver(self.db, t, post)
        self.assertEqual(len(calls), watch.MAX_ATTEMPTS)
        self.assertTrue(all(c.startswith("sha256=") for c in calls))

    def test_sse_format(self):
        self.assertEqual(watch.sse(7, "alarms", {"a": 1}), b'id: 7\nevent: alarms\ndata: {"a": 1}\n\n')

    def test_audit_entry_app(self):
        self.assertEqual(watch.audit_app({"target": "/apps/shop/redeploy"}), "shop")
        self.assertEqual(watch.audit_app({"target": "/apps name=shop repo=https://x/y"}), "shop")
        self.assertEqual(watch.audit_app({"target": "/backups"}), "")


class WatchToken(unittest.TestCase):
    def test_watch_token_is_read_only(self):
        for ok in [("GET", "/watch-stats"), ("POST", "/watch-logs"), ("GET", "/audit"), ("POST", "/audit"), ("GET", "/jobs")]:
            self.assertTrue(agent.watch_allowed(*ok), ok)
        for bad in [("POST", "/apps"), ("POST", "/apps/x/secrets"), ("GET", "/apps/x/logs"), ("POST", "/backup"), ("GET", "/gateway"), ("GET", "/watch-stats/../apps")]:
            self.assertFalse(agent.watch_allowed(*bad), bad)

    def test_log_line_parsing(self):
        ts, text = agent.split_log_line("2026-10-13T20:01:02.123456789Z hello world")
        self.assertAlmostEqual(ts, 1791921662.123, places=2)
        self.assertEqual(text, "hello world")
        self.assertEqual(agent.container_app("oc-app-shop-web-1"), "shop")
        self.assertEqual(agent.container_app("oc-app-my-shop-db-1"), "my-shop")
        self.assertEqual(agent.container_app("oc-console"), "")


class CloudWatchConsole(unittest.TestCase):
    def test_chart_is_flat_svg_and_escaped(self):
        out = console.svg_chart([(0, 1.0), (60, 3.0), (120, 2.0)], "<b>cpu</b>", "%")
        self.assertTrue(out.startswith("<svg") and "polyline" in out)
        self.assertNotIn("<b>", out)
        self.assertIn("no data", console.svg_chart([], "x", "%"))


class ProxyClientIp(unittest.TestCase):
    EDGE = {"10.0.0.2"}

    def test_spoofed_leftmost_hop_ignored(self):
        # Client sent "X-Forwarded-For: 9.9.9.9"; the edge appended the real address.
        self.assertEqual(console.client_ip("9.9.9.9, 5.6.7.8", "10.0.0.2", trusted=1, proxies=self.EDGE), "5.6.7.8")
        self.assertEqual(console.client_ip("9.9.9.9, 1.1.1.1, 5.6.7.8", "10.0.0.2", trusted=2, proxies=self.EDGE), "1.1.1.1")

    def test_no_trusted_proxy_or_too_few_hops_uses_peer(self):
        self.assertEqual(console.client_ip("9.9.9.9", "10.0.0.2", trusted=0, proxies=self.EDGE), "10.0.0.2")
        self.assertEqual(console.client_ip("", "10.0.0.2", trusted=1, proxies=self.EDGE), "10.0.0.2")
        self.assertEqual(console.client_ip("5.6.7.8", "10.0.0.2", trusted=2, proxies=self.EDGE), "10.0.0.2")

    def test_header_from_non_edge_peer_is_ignored(self):
        # An app container (or anything but the edge) talking to the console directly can't pick its key.
        for xff in ("1.2.3.4", "9.9.9.9, 5.6.7.8", ""):
            self.assertEqual(console.client_ip(xff, "10.0.0.77", trusted=1, proxies=self.EDGE), "10.0.0.77")
        self.assertEqual(console.client_ip("1.2.3.4", "10.0.0.77", trusted=1, proxies=set()), "10.0.0.77")

    def test_rotating_spoofed_header_still_rate_limited(self):
        console.attempts.clear()
        for i in range(5):
            console.attempts.setdefault(console.client_ip(f"7.7.7.{i}, 5.6.7.8", "10.0.0.2", trusted=1, proxies=self.EDGE), []).append(100.0)
        self.assertTrue(console.rate_limited("5.6.7.8", now=101))
        console.attempts.clear()
        for i in range(5):  # non-edge peer rotating the header: every attempt lands on the peer
            console.attempts.setdefault(console.client_ip(f"7.7.7.{i}", "10.0.0.77", trusted=1, proxies=self.EDGE), []).append(100.0)
        self.assertTrue(console.rate_limited("10.0.0.77", now=101))

    def test_account_wide_limit_across_ips(self):
        console.account_failures.clear()
        for i in range(console.ACCOUNT_MAX_FAILURES - 1):
            console.account_failures.append(100.0 + i)
        self.assertFalse(console.account_limited(now=200))
        console.account_failures.append(150.0)
        self.assertTrue(console.account_limited(now=200))
        self.assertFalse(console.account_limited(now=100 + console.ACCOUNT_WINDOW + 60))
        console.account_failures.clear()

    def test_proxy_ips_resolve_and_fail_closed(self):
        console._proxy_cache.update(t=0, ips=set())
        orig = console.socket.gethostbyname_ex
        console.socket.gethostbyname_ex = lambda h: (_ for _ in ()).throw(OSError("no such host"))
        try:
            self.assertEqual(console.proxy_ips(now=1000), set())
        finally:
            console.socket.gethostbyname_ex = orig
            console._proxy_cache.update(t=0, ips=set())


class FakeRun:
    """Stands in for subprocess.run inside agent.run; records calls, never runs anything."""
    def __init__(self, out=""):
        self.calls, self.out = [], out

    def __call__(self, args, **kw):
        self.calls.append(args)
        out = self.out(args) if callable(self.out) else self.out
        return agent.subprocess.CompletedProcess(args, 0, out, "")


class ObserveGuard(unittest.TestCase):
    def setUp(self):
        self.real = agent.subprocess.run
        agent.subprocess.run = self.fake = FakeRun()

    def tearDown(self):
        agent.subprocess.run = self.real

    def test_mutating_docker_on_non_oc_container_rejected(self):
        for args in (["docker", "exec", "platform-db-1", "sh"], ["docker", "exec", "-i", "shop-db", "psql"],
                     ["docker", "restart", "wiki"], ["docker", "stop", "oc-x", "wiki"], ["docker", "rm", "-f", "notes"],
                     ["docker", "kill", "caddy"], ["docker", "update", "--memory", "1g", "wiki"], ["docker", "start", "x"]):
            with self.assertRaises(agent.Bad, msg=args):
                agent.run(args)
        self.assertEqual(self.fake.calls, [])

    def test_oc_containers_and_reads_allowed(self):
        agent.run(["docker", "exec", "oc-edge", "caddy", "reload"])
        agent.run(["docker", "restart", "oc-storage"])
        agent.run(["docker", "exec", "-i", "oc-storage", "weed", "shell"])
        agent.run(["docker", "inspect", "wiki"])
        agent.run(["docker", "logs", "--tail", "5", "wiki"])
        self.assertEqual(len(self.fake.calls), 5)

    def test_backup_never_execs_into_foreign_labelled_db(self):
        import tempfile
        agent.ROOT = Path(tempfile.mkdtemp())
        self.fake.out = lambda a: "platform-pg\n" if a[:2] == ["docker", "ps"] else ""
        with self.assertRaises(agent.Bad):
            agent.do_backup()
        self.assertFalse(any(c[:2] == ["docker", "exec"] for c in self.fake.calls))

    def test_observed_lists_only_foreign_containers(self):
        inspect = "\n".join(['"/wiki-web-1"|"wiki"|"img:1"|"running"|"healthy"|0|"256m"', '"/oc-console"|"opencloud"|"c"|"running"|"none"|0|"0"',
                              '"/shop-db"|"shop"|"postgres:17"|"exited"|"none"|3|"512m"'])
        self.fake.out = lambda a: ("id1 id2 id3" if a[:2] == ["docker", "ps"] else inspect if a[:2] == ["docker", "inspect"]
                                   else "wiki-web-1|1.5%|10.0%\n" if a[:2] == ["docker", "stats"] else "")
        out = agent.observed_containers()
        self.assertEqual([c["name"] for c in out], ["shop-db", "wiki-web-1"])
        v = out[1]
        self.assertEqual((v["project"], v["status"], v["health"], v["cpu"], v["mem"]), ("wiki", "running", "healthy", 1.5, 10.0))
        self.assertEqual(out[0]["restarts"], 3)

    def test_observe_routes_off_by_default(self):
        agent.OBSERVE = False
        with self.assertRaises(LookupError):
            agent.dispatch("GET", "/observed", {})
        agent.OBSERVE = True
        try:
            self.fake.out = ""
            self.assertIn("containers", agent.dispatch("GET", "/observed", {}))
        finally:
            agent.OBSERVE = False

    def test_platform_status_reads_only_known_keys(self):
        import tempfile, json as j
        d = Path(tempfile.mkdtemp())
        (d / "status.json").write_text(j.dumps({"backup_last_success": "2026-10-13T07:06:00Z", "warnings": ["w"], "secret": "x"}))
        (d / "backup-last-success").write_text("2026-10-13T07:06:00Z\n")
        agent.OBSERVE_DIR = d
        st = agent.platform_status()
        self.assertEqual(st["status"], {"backup_last_success": "2026-10-13T07:06:00Z", "warnings": ["w"]})
        self.assertEqual(st["markers"], {"backup-last-success": "2026-10-13T07:06:00Z"})
        agent.OBSERVE_DIR = d / "missing"
        self.assertEqual(agent.platform_status(), {"status": None, "markers": {}})


class ExternalEdge(unittest.TestCase):
    def setUp(self):
        import tempfile
        self.real = agent.subprocess.run
        agent.subprocess.run = self.fake = FakeRun()
        agent.ROOT = Path(tempfile.mkdtemp())
        (agent.ROOT / "caddy" / "sites").mkdir(parents=True)
        agent.EDGE_MODE = "external"

    def tearDown(self):
        agent.subprocess.run = self.real
        agent.EDGE_MODE = "internal"

    def test_route_writes_no_caddy_file_and_runs_nothing(self):
        agent.route({"name": "demo", "port": 8080})
        self.assertEqual(list((agent.ROOT / "caddy" / "sites").iterdir()), [])
        self.assertEqual(self.fake.calls, [])

    def test_route_changes_refused(self):
        with self.assertRaises(agent.Bad):
            agent.set_route({}, "demo")

    def test_compose_edge_behind_profile_and_external_override(self):
        root = Path(__file__).parents[1]
        base, ext = (root / "compose.yaml").read_text(), (root / "compose.external.yaml").read_text()
        self.assertRegex(base, r"container_name: oc-edge\n(.*\n)*?    profiles: \[edge\]")
        self.assertIn("console:", ext)
        for svc in ("agent:", "storage:", "watch:", "llm-gateway:", "edge:"):
            self.assertNotIn(svc, ext)
        self.assertNotIn("ports:", ext)


class WatchObserved(unittest.TestCase):
    def test_observed_samples(self):
        s = {"observed": [{"name": "wiki-web-1", "status": "running", "health": "healthy", "restarts": 2, "cpu": 1.5, "mem": 10.0},
                          {"name": "shop-db", "status": "exited", "health": "none", "restarts": 0, "cpu": 0.0, "mem": 0.0}]}
        got = watch.observed_samples(s)
        self.assertIn(("observed:wiki-web-1", "cpu", 1.5), got)
        self.assertIn(("observed:wiki-web-1", "healthy", 1.0), got)
        self.assertIn(("observed:shop-db", "healthy", 0.0), got)
        self.assertEqual(watch.observed_samples({}), [])

    def test_console_card_escaped_and_hidden_when_empty(self):
        o = {"snapshot": {"observed": [{"name": "<x>", "status": "running", "health": "none", "restarts": 0, "cpu": 0, "mem": 0}]}, "observed": {}}
        card = console.observed_card(o)
        self.assertIn("&lt;x&gt;", card)
        self.assertIn("read-only", card)
        self.assertNotIn("<form", card)
        self.assertEqual(console.observed_card({"snapshot": {}, "observed": {}}), "")




class HostSourcesAndMounts(unittest.TestCase):
    """Server-folder source, allowlisted external networks, secret-file and data-folder mounts."""
    def setUp(self):
        import tempfile
        self.t = Path(tempfile.mkdtemp())
        agent.ROOT = self.t / "oc"
        (agent.ROOT / "apps").mkdir(parents=True)
        self.apps, self.data, self.sec = self.t / "srv-apps", self.t / "srv-data", self.t / "secrets"
        for d in (self.apps / "notes" / "backend", self.data / "notes" / "draft", self.sec):
            d.mkdir(parents=True)
        (self.apps / "notes" / "backend" / "Dockerfile").write_text("FROM scratch\n")
        (self.apps / "notes" / "app.py").write_text("x")
        (self.sec / "notes-owner").write_text("never-read")
        (self.sec / "other-app-key").write_text("never-read")
        (self.t / "outside").mkdir()
        (self.apps / "escape").symlink_to(self.t / "outside")
        self.env = {"OC_LOCAL_SOURCES": str(self.apps), "OC_ALLOWED_DATA_ROOTS": str(self.data / "notes"),
                    "OC_ALLOWED_SECRET_PATHS": str(self.sec / "notes-owner"), "OC_ALLOWED_EXTERNAL_NETWORKS": "notes_app platform_llm"}
        self.old = {k: os.environ.get(k) for k in self.env}
        os.environ.update(self.env)

    def tearDown(self):
        for k, v in self.old.items():
            os.environ.pop(k, None) if v is None else os.environ.__setitem__(k, v)

    def test_under_root(self):
        roots = agent.allow("OC_LOCAL_SOURCES")
        self.assertEqual(agent.under_root(str(self.apps / "notes"), roots, "folder"), (self.apps / "notes").resolve())
        for bad in [str(self.apps / ".." / "outside"), str(self.apps / "escape"), "/etc", "relative/path", str(self.apps) + "/notes;x", ""]:
            with self.assertRaises(agent.Bad, msg=bad):
                agent.under_root(bad, roots, "folder")

    def test_allow_empty_means_nothing_allowed(self):
        os.environ["OC_LOCAL_SOURCES"] = ""
        with self.assertRaises(agent.Bad):
            agent.under_root(str(self.apps / "notes"), agent.allow("OC_LOCAL_SOURCES"), "folder")

    def test_settings_parse_and_validate(self):
        s = agent.parse_settings({
            "networks": "notes_app, platform_llm",
            "secret_mounts": f"{self.sec / 'notes-owner'}=owner",
            "data_mounts": f"{self.data / 'notes'}:/data\n{self.data / 'notes' / 'draft'}:/data/original-draft:ro",
            "env": "LLM_GATEWAY_URL=http://llm-gateway:8000\nNOTES_MODE=prod"})
        self.assertEqual(s["networks"], ["notes_app", "platform_llm"])
        self.assertEqual(s["secret_mounts"], [{"source": str((self.sec / "notes-owner").resolve()), "target": "owner"}])
        self.assertEqual(s["data_mounts"][1], {"source": str((self.data / "notes" / "draft").resolve()), "target": "/data/original-draft", "ro": True})
        self.assertFalse(s["data_mounts"][0]["ro"])
        self.assertEqual(s["env"], {"LLM_GATEWAY_URL": "http://llm-gateway:8000", "NOTES_MODE": "prod"})

    def test_settings_refusals(self):
        bad = [{"networks": "host"}, {"networks": "bridge"}, {"networks": "not_listed"},
               {"secret_mounts": f"{self.sec / 'other-app-key'}=key"},          # file not allowlisted
               {"secret_mounts": f"{self.sec / 'notes-owner'}=../x"},           # bad target
               {"secret_mounts": f"{self.sec}=dir"},                             # a directory, not a file
               {"data_mounts": f"{self.data}:/data"},                            # above the allowed root
               {"data_mounts": f"{self.data / 'notes'}:/run/secrets/x"},         # can't shadow secrets
               {"data_mounts": f"{self.data / 'notes'}:relative"},
               {"data_mounts": f"{self.data / 'notes'}:/data:rw-weird"},
               {"env": "PORT=1"}, {"env": "lower=x"}, {"env": "K=$(id)"}, {"env": "K=a\"b"}]
        for b in bad:
            with self.assertRaises(agent.Bad, msg=str(b)):
                agent.parse_settings(b)

    def test_compose_with_settings(self):
        app = {"name": "notes", "port": 8000, "image_tag": "t", "db": False,
               "networks": ["notes_app"], "env": {"LLM_GATEWAY_URL": "http://llm-gateway:8000"},
               "secret_mounts": [{"source": "/s/notes-owner", "target": "owner"}],
               "data_mounts": [{"source": "/d/notes", "target": "/data", "ro": False},
                               {"source": "/d/notes/draft", "target": "/data/original-draft", "ro": True}]}
        doc = agent.compose(app)
        web = doc["services"]["web"]
        self.assertNotIn("ports", web)
        self.assertEqual(web["environment"]["PORT"], "8000")
        self.assertEqual(web["environment"]["LLM_GATEWAY_URL"], "http://llm-gateway:8000")
        self.assertIn("/s/notes-owner:/run/secrets/owner:ro", web["volumes"])
        self.assertIn("/d/notes:/data", web["volumes"])
        self.assertIn("/d/notes/draft:/data/original-draft:ro", web["volumes"])
        self.assertNotIn(f"{agent.ROOT}/data/notes:/data", web["volumes"])  # replaced, not doubled
        key = [k for k, v in doc["networks"].items() if v.get("name") == "notes_app"][0]
        self.assertEqual(doc["networks"][key], {"external": True, "name": "notes_app"})
        self.assertEqual(web["networks"][key], {"aliases": ["app-notes"]})
        self.assertIn("edge", web["networks"])

    def test_folder_source_deploy_validation(self):
        real = agent.start_job
        agent.start_job = lambda kind, name, fn, app: app
        try:
            app = agent.deploy({"name": "notes", "source": "folder", "folder": str(self.apps / "notes"), "dockerfile": "backend/Dockerfile", "port": "8000"})
            self.assertEqual(app["folder"], str((self.apps / "notes").resolve()))
            self.assertEqual(app["repo"], "")
            for b in [{"name": "b2", "source": "folder", "folder": str(self.apps / "escape")},
                      {"name": "b3", "source": "folder", "folder": "/etc"},
                      {"name": "b4", "source": "folder", "folder": str(self.apps / "notes"), "dockerfile": "../x/Dockerfile"},
                      {"name": "b5", "source": "folder", "folder": str(self.apps / "notes"), "networks": "host"}]:
                with self.assertRaises(agent.Bad, msg=str(b)):
                    agent.deploy(b)
        finally:
            agent.start_job = real

    def test_snapshot_copies_folder_without_following_symlinks(self):
        (self.apps / "notes" / "link-out").symlink_to(self.t / "outside")
        dst = self.t / "snap"
        agent.snapshot_folder(self.apps / "notes", dst)
        self.assertTrue((dst / "backend" / "Dockerfile").exists())
        self.assertTrue((dst / "link-out").is_symlink())  # copied as a link, target not copied in

    def test_dockerfile_must_stay_in_source(self):
        src = self.apps / "notes"
        self.assertEqual(agent.dockerfile_path(src, "backend/Dockerfile"), src / "backend" / "Dockerfile")
        for bad in ["../Dockerfile", "/etc/passwd", "backend/../../x", "a b"]:
            with self.assertRaises(agent.Bad, msg=bad):
                agent.dockerfile_path(src, bad)


class HostSettingsRecheck(HostSourcesAndMounts):
    def test_shrunk_allowlist_blocks_restart(self):
        app = {"name": "notes", "networks": ["notes_app"], "secret_mounts": [{"source": str(self.sec / "notes-owner"), "target": "owner"}]}
        agent.recheck_host_settings(app)
        os.environ["OC_ALLOWED_EXTERNAL_NETWORKS"] = "platform_llm"
        with self.assertRaises(agent.Bad):
            agent.recheck_host_settings(app)
        os.environ["OC_ALLOWED_EXTERNAL_NETWORKS"] = "notes_app"; os.environ["OC_ALLOWED_SECRET_PATHS"] = ""
        with self.assertRaises(agent.Bad):
            agent.recheck_host_settings(app)


class AppRunnerForm(unittest.TestCase):
    def test_host_options_only_when_allowlisted(self):
        bare = console.app_runner_form("t", {})
        self.assertNotIn("Server folder", bare)
        self.assertNotIn("secret_mounts", bare)
        full = console.app_runner_form("t", {"local_sources": ["/srv/apps"], "networks": ["n1"], "secret_paths": ["/s/a"], "data_roots": ["/d"]})
        for x in ("Server folder", "name=folder", "name=networks", "name=secret_mounts", "name=data_mounts", "name=dockerfile", "/srv/apps"):
            self.assertIn(x, full)
        self.assertIn("folder", console.APP_FIELDS)

    def test_form_escapes_options(self):
        self.assertNotIn("<x>", console.app_runner_form("t", {"networks": ["<x>"]}))


class BuilderAppArmor(unittest.TestCase):
    def test_profile_grants_only_userns_and_is_named(self):
        p = (Path(__file__).parents[1] / "deploy" / "apparmor" / "opencloud-builder").read_text()
        self.assertIn("profile opencloud-builder", p)
        self.assertIn("userns,", p)

    def test_compose_builder_uses_profile_variable(self):
        base = (Path(__file__).parents[1] / "compose.yaml").read_text()
        self.assertIn("apparmor=${OC_BUILDER_APPARMOR:-unconfined}", base)


class BedrockProviderKey(unittest.TestCase):
    """Initiate AI: one provider key in Open Bedrock, injected into apps that declare an env name for it."""
    def setUp(self):
        import tempfile, json
        self.json = json
        agent.ROOT = Path(tempfile.mkdtemp())
        for d in ("apps", "gateway", "secrets/platform"):
            (agent.ROOT / d).mkdir(parents=True)
        # Production runs as root and owns these files; as a test user keep them writable.
        self.chown, agent.os.chown = agent.os.chown, lambda *a: None
        self.chmod, agent.os.chmod = agent.os.chmod, lambda *a: None
        agent.upstream_key_file().touch(mode=0o600)
        self.up_calls = []
        self.up, agent.up = agent.up, lambda app, build, recreate=False: self.up_calls.append((app["name"], recreate))
        agent.save({"name": "gw", "port": 8000, "image_tag": "t", "db": False})
        agent.save({"name": "other", "port": 8000, "image_tag": "t", "db": False})

    def tearDown(self):
        agent.os.chown, agent.os.chmod, agent.up = self.chown, self.chmod, self.up

    def test_provider_sets_default_url_and_never_returns_key(self):
        agent.set_provider({"provider": "openrouter", "key": "sk-or-test-123"})
        st = agent.gateway_state()
        self.assertEqual(st["provider"], "openrouter")
        self.assertEqual(st["upstream_url"], agent.PROVIDERS["openrouter"])
        self.assertTrue(st["provider_key_set"])
        self.assertTrue(st["key_updated"])
        self.assertNotIn("sk-or-test-123", self.json.dumps(st))
        agent.set_provider({"provider": "openrouter", "clear_key": True})
        self.assertFalse(agent.gateway_state()["provider_key_set"])

    def test_unknown_provider_rejected(self):
        with self.assertRaises(agent.Bad):
            agent.set_provider({"provider": "acme", "key": "k"})

    def test_app_gets_key_as_secret_file_and_follows_changes(self):
        agent.set_provider({"provider": "openrouter", "key": "sk-1"})
        agent.set_provider_key_env({"env": "OPENROUTER_API_KEY"}, "gw")
        app = agent.load("gw")
        self.assertEqual(app["provider_key_env"], "OPENROUTER_API_KEY")
        agent.inject_provider_key(app)
        f = agent.secret_dir("gw") / "OPENROUTER_API_KEY"
        self.assertEqual(f.read_text(), "sk-1")
        self.up_calls.clear()
        agent.set_provider({"provider": "openrouter", "key": "sk-2"})
        self.assertEqual(self.up_calls, [("gw", True)])  # only consumers, on new containers
        agent.inject_provider_key(app)
        self.assertEqual(f.read_text(), "sk-2")
        agent.set_provider({"provider": "openrouter", "clear_key": True})
        agent.inject_provider_key(app)
        self.assertFalse(f.exists())

    def test_env_name_validated_and_never_overwrites_own_secret(self):
        with self.assertRaises(agent.Bad):
            agent.set_provider_key_env({"env": "bad name"}, "gw")
        agent.write_secret(agent.secret_dir("other") / "MY_KEY", "mine")
        with self.assertRaises(agent.Bad):
            agent.set_provider_key_env({"env": "MY_KEY"}, "other")
        agent.set_provider_key_env({"env": "OPENROUTER_API_KEY"}, "gw")
        agent.set_provider_key_env({"env": ""}, "gw")  # stop consuming: file removed, field cleared
        self.assertNotIn("provider_key_env", agent.load("gw"))
        self.assertFalse((agent.secret_dir("gw") / "OPENROUTER_API_KEY").exists())

    def test_console_page_masks_key(self):
        html = console.provider_form("tok", {"provider": "openrouter", "provider_key_set": True, "key_updated": "2026-10-14T16:00:00Z", "upstream_url": agent.PROVIDERS["openrouter"]})
        self.assertIn("type=password", html)
        self.assertIn("set", html)
        for p in ("openrouter", "openai", "anthropic"):
            self.assertIn(f'value="{p}"', html)


class Visibility(unittest.TestCase):
    """Internal apps get no edge route; external apps keep the default route."""
    def setUp(self):
        import tempfile
        agent.ROOT = Path(tempfile.mkdtemp())
        (agent.ROOT / "caddy" / "sites").mkdir(parents=True)
        (agent.ROOT / "apps").mkdir()
        self.calls = []
        self.run, agent.run = agent.run, lambda args, **kw: self.calls.append(args) or type("R", (), {"returncode": 0, "stdout": "", "stderr": ""})()
        self.mode, agent.EDGE_MODE = agent.EDGE_MODE, "internal"

    def tearDown(self):
        agent.run, agent.EDGE_MODE = self.run, self.mode

    def site(self, n):
        return agent.ROOT / "caddy" / "sites" / f"{n}.caddy"

    def test_new_apps_default_internal(self):
        self.assertEqual(agent.visibility({}), "external")  # apps saved before this setting keep their route
        self.assertEqual(agent.parse_visibility(""), "internal")
        self.assertEqual(agent.parse_visibility("external"), "external")
        with self.assertRaises(agent.Bad):
            agent.parse_visibility("public")

    def test_internal_removes_route_and_reloads(self):
        app = {"name": "gw", "port": 8000, "visibility": "external"}
        agent.route(app)
        self.assertTrue(self.site("gw").exists())
        app["visibility"] = "internal"
        self.calls.clear()
        agent.route(app)
        self.assertFalse(self.site("gw").exists())
        self.assertTrue(any("reload" in a for a in self.calls))
        self.calls.clear()
        agent.route(app)  # already internal: nothing to reload
        self.assertEqual(self.calls, [])

    def test_set_visibility_saves_and_routes(self):
        agent.save({"name": "gw", "port": 8000, "image_tag": "t", "db": False})
        agent.set_visibility({"visibility": "internal"}, "gw")
        self.assertEqual(agent.load("gw")["visibility"], "internal")
        self.assertFalse(self.site("gw").exists())
        with self.assertRaises(agent.Bad):
            agent.set_route({"domains": "x.example.com"}, "gw")

    def test_console_offers_both(self):
        html = console.app_runner_form("tok", {})
        self.assertIn('name=visibility value=internal checked', html)
        self.assertIn('name=visibility value=external', html)


class SiteDomains(unittest.TestCase):
    """Hand-written site files: the console shows the real domain an app is served on."""
    def test_domains_from_site_files(self):
        import tempfile
        agent.ROOT = Path(tempfile.mkdtemp())
        sites = agent.ROOT / "caddy" / "sites"
        sites.mkdir(parents=True)
        (sites / "site-shop.caddy").write_text("# shop\nshop.example.com, www.shop.example.com {\n\timport x\n\treverse_proxy app-shop:3000 {\n\t}\n}\n"
                                              "www.other.example.com {\n\tredir https://other.example.com{uri} 301\n}\n")
        (sites / "00-snippets.caddy").write_text("(snip) {\n\theader X 1\n}\n")
        d = agent.site_domains()
        self.assertEqual(d, {"shop": ["shop.example.com", "www.shop.example.com"]})


class EdgeConfig(unittest.TestCase):
    """Open ELB: internal apps aren't listed; edge files are shown read-only with secrets redacted."""
    CFG = ("app.example.com {\n\tbasic_auth {\n\t\towner $2a$14$abcdefghijklmnopqrstuv\n\t}\n"
           "\tforward_auth app-gate:9000 {\n\t\turi /check\n\t\tcopy_headers X-User\n\t}\n"
           "\treverse_proxy app-notes:8000 {\n\t\theader_up X-Proxy-Token hunter2-peer-value\n\t\theader_up Authorization \"Bearer abc\"\n\t}\n"
           "\theader X-Key {env.NOTES_KEY}\n\trespond /k Zx9QwErTy7UiOpAsDfGhJkLzXcVbNm12 200\n"
           "\troot * /srv/opencloud/sites/shop/releases/current\n}\n")

    def setUp(self):
        import tempfile
        agent.ROOT = Path(tempfile.mkdtemp())
        self.sites = agent.ROOT / "caddy" / "sites"
        self.sites.mkdir(parents=True)
        (agent.ROOT / "apps" / "web").mkdir(parents=True)
        (agent.ROOT / "apps" / "web" / "app.json").write_text("{}")

    def test_redaction(self):
        out = agent.redact_caddy(self.CFG)
        for bad in ("$2a$14$", "owner", "/check", "X-User", "hunter2-peer-value", "Bearer abc", "NOTES_KEY", "Zx9QwErTy7Ui"):
            self.assertNotIn(bad, out)
        self.assertIn("\tbasic_auth [redacted]\n\tforward_auth [redacted]\n\treverse_proxy app-notes:8000 {", out)
        self.assertIn("\t\theader_up [redacted]", out)
        self.assertIn("{env.[redacted]}", out)
        self.assertIn("/srv/opencloud/sites/shop/releases/current", out)  # paths survive
        self.assertTrue(out.rstrip().endswith("}"))

    def test_edge_config_lists_files(self):
        (self.sites / "web.caddy").write_text("web.apps.example.com {\n\treverse_proxy app-web:80\n}\n")
        (self.sites / "site-notes.caddy").write_text(self.CFG)
        (self.sites / "site-static-shop.caddy").write_text("shop.example.com, www.shop.example.com {\n\tfile_server\n}\n")
        got = {c["file"]: c for c in agent.edge_config()}
        self.assertTrue(got["web.caddy"]["managed"])
        self.assertFalse(got["site-notes.caddy"]["managed"])
        self.assertEqual(got["site-notes.caddy"]["hosts"], ["app.example.com"])
        self.assertEqual(got["site-notes.caddy"]["targets"], ["app-notes:8000"])
        self.assertEqual(got["site-static-shop.caddy"]["targets"], ["file_server"])
        self.assertNotIn("hunter2", got["site-notes.caddy"]["config"])

    def test_routes_skip_internal(self):
        run, agent.run = agent.run, lambda args, **kw: type("R", (), {"returncode": 1, "stdout": "", "stderr": ""})()
        mode, agent.EDGE_MODE = agent.EDGE_MODE, "internal"
        try:
            for n, v in (("web", "external"), ("worker", "internal")):
                agent.save({"name": n, "port": 80, "image_tag": "t", "db": False, "visibility": v})
            self.assertEqual([r["app"] for r in agent.routes()], ["web"])
        finally:
            agent.run, agent.EDGE_MODE = run, mode

    def test_console_panels(self):
        cfg = [{"file": "site-notes.caddy", "managed": False, "hosts": ["app.example.com"], "targets": ["app-notes:8000"],
                "config": "app.example.com {\n\tbasic_auth [redacted]\n}\n"}]
        real, console.agent = console.agent, lambda m, p, b=None: [] if p == "/routes" else cfg
        try:
            _, html = console.view("/loadbalancers", "tok")
        finally:
            console.agent = real
        self.assertIn("Hand-managed routes", html)
        self.assertIn("<td>site-notes.caddy</td><td>app.example.com</td><td>app-notes:8000</td>", html)
        self.assertIn("basic_auth [redacted]", html)


class S3PublicToggle(unittest.TestCase):
    def test_template_marks_s3_block(self):
        t = (Path(__file__).parents[1] / "edge" / "Caddyfile.template").read_text()
        self.assertIn("# s3-public-begin", t)
        self.assertIn("# s3-public-end", t)
        i = (Path(__file__).parents[1] / "install.sh").read_text()
        self.assertIn("OC_S3_PUBLIC", i)
        block = t[t.index("# s3-public-begin"):t.index("# s3-public-end")]
        self.assertEqual(block.count("{"), block.count("}"))  # the whole site block, nothing else

    def test_console_link_for_internal_app(self):
        self.assertIn("app-gw:8000", console.link({"name": "gw", "port": 8000, "url": ""}))
        self.assertIn("https://gw.example.com", console.link({"name": "gw", "port": 8000, "url": "https://gw.example.com"}))


class StaticSites(unittest.TestCase):
    def setUp(self):
        import tempfile
        agent.ROOT = Path(tempfile.mkdtemp())
        for d in ("sites", "caddy/sites", "apps", "audit"):
            (agent.ROOT / d).mkdir(parents=True)
        self.pushed, self.removed, self.reloads = [], [], []
        agent.site_s3_push = lambda name, rel, src: self.pushed.append((name, rel))
        agent.site_s3_remove = lambda name, rel=None: self.removed.append((name, rel))
        agent.edge_apply = lambda: self.reloads.append(1)

    @staticmethod
    def zipped(entries, links=()):
        import io, zipfile
        b = io.BytesIO()
        with zipfile.ZipFile(b, "w") as z:
            for n, data in entries.items():
                z.writestr(n, data)
            for n in links:
                i = zipfile.ZipInfo(n)
                i.external_attr = (0o120777 << 16)
                z.writestr(i, "/etc/passwd")
        return b.getvalue()

    def upload(self, name, filename, data):
        import base64
        return agent.site_upload({"filename": filename, "data": base64.b64encode(data).decode()}, name)

    def test_create_validates_and_rejects_duplicates(self):
        agent.site_create({"name": "mysite"})
        with self.assertRaises(agent.Bad):
            agent.site_create({"name": "mysite"})
        for bad in ("../x", "A", "x", "a/b", ""):
            with self.assertRaises(agent.Bad):
                agent.site_create({"name": bad})

    def test_single_html_becomes_index_and_is_world_readable(self):
        agent.site_create({"name": "cc"})
        self.upload("cc", "page.html", b"<title>Hi</title>")
        cur = agent.ROOT / "sites" / "cc" / "current"
        self.assertTrue(cur.is_symlink())
        self.assertFalse(os.path.isabs(os.readlink(cur)))  # relative, so it resolves inside the edge mount
        self.assertEqual((cur / "index.html").read_text(), "<title>Hi</title>")
        self.assertTrue((cur / "404.html").exists())
        self.assertEqual((cur / "index.html").stat().st_mode & 0o777, 0o644)
        self.assertEqual(self.pushed[0][0], "cc")

    def test_zip_replaces_whole_site_atomically_and_strips_top_folder(self):
        agent.site_create({"name": "cc"})
        self.upload("cc", "a.zip", self.zipped({"old.html": "x", "index.html": "v1"}))
        self.upload("cc", "b.zip", self.zipped({"site/index.html": "v2", "site/css/a.css": "b"}))
        cur = agent.ROOT / "sites" / "cc" / "current"
        self.assertEqual((cur / "index.html").read_text(), "v2")
        self.assertTrue((cur / "css" / "a.css").exists())
        self.assertFalse((cur / "old.html").exists())

    def test_zip_traversal_symlink_and_absolute_rejected(self):
        agent.site_create({"name": "cc"})
        for z in (self.zipped({"index.html": "x", "../evil.html": "x"}),
                  self.zipped({"index.html": "x", "/etc/evil": "x"}),
                  self.zipped({"index.html": "x", "a\\..\\evil": "x"}),
                  self.zipped({"index.html": "x"}, links=["link"])):
            with self.assertRaises(agent.Bad):
                self.upload("cc", "x.zip", z)
        self.assertFalse((agent.ROOT / "sites" / "cc" / "current").exists())
        self.assertFalse((agent.ROOT / "evil.html").exists())

    def test_limits_and_index_required(self):
        agent.site_create({"name": "cc"})
        with self.assertRaises(agent.Bad):
            self.upload("cc", "x.zip", self.zipped({"about.html": "x"}))  # no index.html
        with self.assertRaises(agent.Bad):
            self.upload("cc", "x.html", b"x" * (agent.SITE_MAX_UPLOAD + 1))
        with self.assertRaises(agent.Bad):
            self.upload("cc", "x.zip", self.zipped({"index.html": "x", "big.bin": b"\0" * (agent.SITE_MAX_EXTRACTED + 1)}))
        with self.assertRaises(agent.Bad):
            self.upload("cc", "x.exe", b"MZ")

    def test_keeps_three_releases(self):
        agent.site_create({"name": "cc"})
        for i in range(5):
            self.upload("cc", "x.html", f"v{i}".encode())
        rels = list((agent.ROOT / "sites" / "cc" / "releases").iterdir())
        self.assertEqual(len(rels), 3)

    def test_render_is_safe(self):
        out = agent.render_static_site("cc", ["cc.example.com", "www.cc.example.com"], tls_internal=False)
        self.assertIn("cc.example.com, www.cc.example.com {", out)
        self.assertIn("import security_headers", out)
        self.assertIn("root * /srv/sites/cc/current", out)
        self.assertIn("hide .*", out)
        self.assertNotIn("browse", out)
        self.assertNotIn("reverse_proxy", out)
        self.assertIn("handle_errors", out)
        self.assertIn('header Cache-Control "no-cache"\n\t\trewrite * /404.html', out)  # 404s are not cached
        self.assertNotIn("tls internal", out)
        self.assertIn("tls internal", agent.render_static_site("cc", ["cc.example.com"], tls_internal=True))

    def test_domains_write_file_and_reject_taken(self):
        agent.site_create({"name": "cc"})
        self.upload("cc", "x.html", b"x")
        (agent.ROOT / "caddy" / "sites" / "site-shop.caddy").write_text("shop.example.com, www.shop.example.com {\n\treverse_proxy app-r:3000\n}\n")
        with self.assertRaises(agent.Bad):
            agent.site_domains_set({"domains": "www.shop.example.com"}, "cc")
        with self.assertRaises(agent.Bad):
            agent.site_domains_set({"domains": agent.CONSOLE_HOST}, "cc")
        with self.assertRaises(agent.Bad):
            agent.site_domains_set({"domains": "bad_host"}, "cc")
        agent.site_domains_set({"domains": "cc.example.com", "tls_internal": "1"}, "cc")
        f = agent.ROOT / "caddy" / "sites" / "site-static-cc.caddy"
        self.assertIn("cc.example.com {", f.read_text())
        agent.site_create({"name": "dd"})
        with self.assertRaises(agent.Bad):
            agent.site_domains_set({"domains": "cc.example.com"}, "dd")
        agent.site_domains_set({"domains": ""}, "cc")
        self.assertFalse(f.exists())

    def test_domains_need_content(self):
        agent.site_create({"name": "cc"})
        with self.assertRaises(agent.Bad):
            agent.site_domains_set({"domains": "cc.example.com"}, "cc")

    def test_delete_removes_everything(self):
        agent.site_create({"name": "cc"})
        self.upload("cc", "x.html", b"x")
        agent.site_domains_set({"domains": "cc.example.com"}, "cc")
        agent.site_delete({}, "cc")
        self.assertFalse((agent.ROOT / "sites" / "cc").exists())
        self.assertFalse((agent.ROOT / "caddy" / "sites" / "site-static-cc.caddy").exists())
        self.assertIn(("cc", None), self.removed)
        self.assertEqual(agent.site_list(), [])

    def test_list_and_audit(self):
        agent.site_create({"name": "cc"})
        self.upload("cc", "x.html", b"x")
        s = agent.site_list()[0]
        self.assertEqual((s["name"], s["domains"], s["visibility"]), ("cc", [], "external"))
        events = [json.loads(l)["event"] for l in (agent.ROOT / "audit" / "audit.log").read_text().splitlines()]
        self.assertEqual(events, ["site-create", "site-upload"])

    def test_dispatch_and_reserved_bucket(self):
        agent.dispatch("POST", "/sites", {"name": "cc"})
        self.assertEqual(agent.dispatch("GET", "/sites", {})[0]["name"], "cc")
        with self.assertRaises(LookupError):
            agent.dispatch("POST", "/sites/cc/nope", {})
        self.assertEqual(agent.body_limit("/sites/cc/upload"), agent.SITE_BODY_MAX)
        self.assertEqual(agent.body_limit("/apps"), 200000)

    def test_console_multipart(self):
        body = (b"--XX\r\nContent-Disposition: form-data; name=\"csrf\"\r\n\r\ntok\r\n"
                b"--XX\r\nContent-Disposition: form-data; name=\"file\"; filename=\"a.html\"\r\nContent-Type: text/html\r\n\r\n<p>\r\n--XX--\r\n")
        f, files = console.parse_multipart("multipart/form-data; boundary=XX", body)
        self.assertEqual(f["csrf"], "tok")
        self.assertEqual(files["file"], ("a.html", b"<p>"))


class DnsChain(unittest.TestCase):
    """DNS page: one row per domain (DNS, route, certificate, config, problems) and guided edge actions."""
    def setUp(self):
        StaticSites.setUp(self)
        self.ip, agent.PUBLIC_IP = agent.PUBLIC_IP, "203.0.113.5"
        self.dns = {}
        self.resolve, agent.resolve = agent.resolve, lambda h: self.dns.get(h, [])
        self.edge, agent.edge = agent.edge, lambda cmd, timeout=10: type("R", (), {"returncode": 0, "stdout": "a.example.com\n", "stderr": ""})()
        agent.site_create({"name": "cc"})
        StaticSites.upload(self, "cc", "x.html", b"x")
        self.f = agent.ROOT / "caddy" / "sites" / "site-static-cc.caddy"

    def tearDown(self):
        agent.PUBLIC_IP, agent.resolve, agent.edge = self.ip, self.resolve, self.edge

    def rows(self):
        return {r["domain"]: r for r in agent.dns_rows()}

    def test_rows_flag_mismatches(self):
        (agent.ROOT / "caddy" / "sites" / "site-hand.caddy").write_text(
            "a.example.com {\n\treverse_proxy app-x:80\n}\nb.example.com {\n\tbasic_auth {\n\t\tu $2a$14$zzzz\n\t}\n\treverse_proxy app-x:80\n}\n")
        agent.site_domains_set({"domains": "cc.example.com www.cc.example.com", "tls_internal": "1"}, "cc")
        self.dns.update({"a.example.com": ["203.0.113.5"], "b.example.com": ["198.51.100.7"], "cc.example.com": ["203.0.113.5"]})
        r = self.rows()
        self.assertEqual((r["a.example.com"]["cert"], r["a.example.com"]["problems"]), ("issued", []))
        self.assertEqual(r["a.example.com"]["file"], "site-hand.caddy")
        self.assertEqual(r["b.example.com"]["problems"], ["DNS points elsewhere"])
        self.assertNotIn("$2a$", r["b.example.com"]["config"])
        self.assertEqual(r["cc.example.com"]["site"], "cc")
        self.assertEqual((r["cc.example.com"]["cert"], r["cc.example.com"]["problems"]), ("preview", ["preview certificate on, DNS is ready"]))
        self.assertEqual(r["www.cc.example.com"]["problems"], ["no DNS record"])
        agent.site_domains_set({"domains": "cc.example.com"}, "cc")
        self.assertEqual(self.rows()["cc.example.com"]["problems"], ["certificate pending or failed"])
        self.assertIn(agent.CONSOLE_HOST, self.rows())

    def test_real_cert_waits_for_dns(self):
        agent.site_domains_set({"domains": "cc.example.com www.cc.example.com", "tls_internal": "1"}, "cc")
        self.dns["cc.example.com"] = ["203.0.113.5"]
        with self.assertRaisesRegex(agent.Bad, "www.cc.example.com"):
            agent.dispatch("POST", "/sites/cc/real-cert", {})
        self.assertIn("tls internal", self.f.read_text())
        self.dns["www.cc.example.com"] = ["203.0.113.5"]
        agent.dispatch("POST", "/sites/cc/real-cert", {})
        self.assertNotIn("tls internal", self.f.read_text())
        self.assertFalse(agent.site_load("cc")["tls_internal"])

    def test_www_redirect(self):
        agent.site_domains_set({"domains": "cc.example.com"}, "cc")
        with self.assertRaises(agent.Bad):
            agent.dispatch("POST", "/sites/cc/www-redirect", {"on": True})
        agent.domain_add({"target": "site:cc", "domain": "www.cc.example.com"})
        agent.dispatch("POST", "/sites/cc/www-redirect", {"on": True})
        out = self.f.read_text()
        self.assertIn("cc.example.com {\n\timport security_headers", out)
        self.assertIn("www.cc.example.com {\n\tredir https://cc.example.com{uri} 301\n}\n", out)
        self.assertTrue(agent.site_load("cc")["www_redirect"])
        agent.site_domains_set({"domains": "cc.example.com www.cc.example.com", "tls_internal": "1"}, "cc")  # kept on re-save
        self.assertIn("www.cc.example.com {\n\ttls internal\n\tredir", self.f.read_text())
        agent.dispatch("POST", "/sites/cc/www-redirect", {"on": False})
        self.assertIn("cc.example.com, www.cc.example.com {", self.f.read_text())

    def test_failed_reload_restores_file_and_setting(self):
        agent.site_domains_set({"domains": "cc.example.com www.cc.example.com"}, "cc")
        before = self.f.read_text()
        def fail():
            raise agent.Bad("caddy: adapting config: boom")
        run, agent.edge_apply, agent.run = agent.run, fail, lambda args, **kw: None
        try:
            with self.assertRaisesRegex(agent.Bad, "rolled back"):
                agent.site_www_redirect({"on": True}, "cc")
        finally:
            agent.edge_apply, agent.run = (lambda: self.reloads.append(1)), run
        self.assertEqual(self.f.read_text(), before)
        self.assertFalse(agent.site_load("cc").get("www_redirect"))

    def test_domain_add_checks(self):
        with self.assertRaises(agent.Bad):
            agent.domain_add({"target": "nope:x", "domain": "x.example.com"})
        (agent.ROOT / "caddy" / "sites" / "site-hand.caddy").write_text("a.example.com {\n\treverse_proxy app-x:80\n}\n")
        with self.assertRaises(agent.Bad):
            agent.domain_add({"target": "site:cc", "domain": "a.example.com"})  # owned by a hand-managed file
        self.assertEqual((agent.ROOT / "caddy" / "sites" / "site-hand.caddy").read_text(), "a.example.com {\n\treverse_proxy app-x:80\n}\n")

    def test_console_page(self):
        rows = [{"domain": "cc.example.com", "resolves": ["203.0.113.5"], "app": "", "site": "cc", "file": "site-static-cc.caddy",
                 "targets": ["file_server"], "cert": "preview", "problems": ["preview certificate on, DNS is ready"], "config": "cc.example.com {\n}\n"}]
        sites = [{"name": "cc", "domains": ["cc.example.com", "www.cc.example.com"], "tls_internal": True}]
        real, console.agent = console.agent, lambda m, p, b=None: rows if p == "/dns" else sites if p == "/sites" else []
        try:
            _, html = console.view("/dns", "tok")
        finally:
            console.agent = real
        self.assertIn("<span class=bad>preview certificate on, DNS is ready</span>", html)
        self.assertIn('<option value="site:cc">', html)
        self.assertIn('action="/sites/cc/real-cert"', html)
        self.assertIn("Redirect www to the main domain", html)


if __name__ == "__main__":
    unittest.main()
