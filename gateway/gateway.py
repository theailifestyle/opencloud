"""Open Cloud model gateway, shown in the console as "Open Bedrock" (the Bedrock / Vertex AI equivalent).

Apps call one OpenAI-compatible URL with their own key and a named endpoint as the model.
Only this service holds the provider key. Never logs prompts, replies or keys.
Stub mode (echo) when no provider key or URL is configured.
"""
import hmac, json, os, threading, time, urllib.error, urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

CLIENTS = Path(os.environ.get("OC_GATEWAY_CLIENTS", "/run/clients"))
STATE = Path(os.environ.get("OC_GATEWAY_DIR", "/run/gateway"))
UPSTREAM_KEY_FILE = Path(os.environ.get("OC_LLM_UPSTREAM_KEY_FILE", "/run/secrets/upstream_key"))
LOCK = threading.Lock()
hits = {}  # (endpoint, app) -> recent request times


def load_usage():
    p = STATE / "usage.json"
    return json.loads(p.read_text()) if p.exists() else {}


usage = load_usage()


def config():
    p = STATE / "config.json"
    return json.loads(p.read_text()) if p.exists() else {"upstream_url": "", "endpoints": {}}


def client_for(auth):
    for p in CLIENTS.glob("*"):
        if hmac.compare_digest(auth, "Bearer " + p.read_text().strip()):
            return p.name
    return None


def count(endpoint, app, **inc):
    """Per endpoint/app counters: requests, rejected, prompt/completion tokens."""
    with LOCK:
        u = usage.setdefault(f"{endpoint}|{app}", {"requests": 0, "rejected": 0, "prompt_tokens": 0, "completion_tokens": 0})
        for k, v in inc.items():
            u[k] += int(v or 0)
        tmp = STATE / "usage.json.tmp"
        tmp.write_text(json.dumps(usage))
        tmp.replace(STATE / "usage.json")


class Handler(BaseHTTPRequestHandler):
    def reply(self, code, data):
        b = json.dumps(data).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def do_GET(self):
        if self.path == "/healthz":
            return self.reply(200, {"ok": True})
        if self.path == "/v1/models":
            app = client_for(self.headers.get("Authorization", ""))
            if not app:
                return self.reply(401, {"error": "unauthorized"})
            names = [n for n, e in config()["endpoints"].items() if app in e["apps"]]
            return self.reply(200, {"object": "list", "data": [{"id": n, "object": "model"} for n in names]})
        self.reply(404, {"error": "not found"})

    def do_POST(self):
        if self.path != "/v1/chat/completions":
            return self.reply(404, {"error": "not found"})
        app = client_for(self.headers.get("Authorization", ""))
        if not app:
            return self.reply(401, {"error": "unauthorized"})
        try:
            body = json.loads(self.rfile.read(min(int(self.headers.get("Content-Length") or 0), 1_000_000)))
        except ValueError:
            return self.reply(400, {"error": "invalid JSON"})
        cfg = config()
        name = str(body.get("model", ""))
        ep = cfg["endpoints"].get(name)
        if not ep or app not in ep["apps"]:
            return self.reply(404, {"error": "unknown model endpoint, or not enabled for this app"})
        now = time.time()
        with LOCK:
            recent = [t for t in hits.get((name, app), []) if now - t < 60]
            limited = len(recent) >= ep["rpm"]
            hits[(name, app)] = recent if limited else recent + [now]
        if limited:
            count(name, app, rejected=1)
            return self.reply(429, {"error": "rate limited"})
        key = UPSTREAM_KEY_FILE.read_text().strip() if UPSTREAM_KEY_FILE.exists() else ""
        url = cfg.get("upstream_url", "")
        if not (url and key):
            last = (body.get("messages") or [{}])[-1].get("content", "")
            count(name, app, requests=1)
            return self.reply(200, {"object": "chat.completion", "model": "stub", "usage": {"prompt_tokens": 0, "completion_tokens": 0},
                                    "choices": [{"index": 0, "finish_reason": "stop",
                                                 "message": {"role": "assistant", "content": f"[stub] {str(last)[:200]}"}}]})
        body["model"] = ep["model"]
        req = urllib.request.Request(url, data=json.dumps(body).encode(), method="POST",
                                     headers={"Authorization": "Bearer " + key, "Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=120) as r:
                data = json.loads(r.read())
            u = data.get("usage") or {}
            count(name, app, requests=1, prompt_tokens=u.get("prompt_tokens"), completion_tokens=u.get("completion_tokens"))
            data["model"] = name  # apps see the endpoint name, not the provider id
            self.reply(200, data)
        except urllib.error.HTTPError as err:
            count(name, app, requests=1)
            self.reply(502, {"error": f"provider returned {err.code}"})
        except (urllib.error.URLError, TimeoutError, ValueError):
            count(name, app, requests=1)
            self.reply(502, {"error": "provider unreachable"})

    def log_message(self, fmt, *a):  # method, path and status only
        print(f"{self.command} {self.path} {a[1] if len(a) > 1 else ''}", flush=True)


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 8000), Handler).serve_forever()
