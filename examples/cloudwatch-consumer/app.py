"""Open CloudWatch consumer example (Python standard library only).

Deploy it as an app, then on Open CloudWatch > Event feed click "Create subscriber key".
The app then receives /run/secrets/CLOUDWATCH_URL and /run/secrets/CLOUDWATCH_KEY and:
  * follows the Server-Sent Events stream (reconnects with Last-Event-ID), and
  * if you save a secret WEBHOOK_URL (e.g. http://app-<your-app>:8080/webhook), registers a webhook
    and verifies each delivery's HMAC signature.
GET /received shows what arrived. Events only ever concern this app.
"""
import hashlib, hmac, json, os, threading, time, urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


def secret(name, default=""):
    p = Path("/run/secrets") / name
    return p.read_text().strip() if p.exists() else default


URL, KEY = secret("CLOUDWATCH_URL"), secret("CLOUDWATCH_KEY")
received = {"sse": [], "webhook": [], "rejected": 0}


def follow_stream():
    last = "0"
    while True:
        try:
            req = urllib.request.Request(f"{URL}/v1/stream?topics=alarms,deploys,metrics,audit",
                                         headers={"Authorization": f"Bearer {KEY}", "Last-Event-ID": last})
            with urllib.request.urlopen(req, timeout=60) as r:
                event = {}
                for raw in r:
                    line = raw.decode().rstrip("\n")
                    if line.startswith("id: "):
                        event["id"] = last = line[4:]
                    elif line.startswith("event: "):
                        event["topic"] = line[7:]
                    elif line.startswith("data: "):
                        event["data"] = json.loads(line[6:])
                    elif not line and "data" in event:
                        received["sse"] = (received["sse"] + [event])[-50:]
                        print("event", event["topic"], json.dumps(event["data"]), flush=True)
                        event = {}
        except OSError as e:
            print("stream reconnecting:", type(e).__name__, flush=True)
            time.sleep(2)


def register_webhook(url):
    body = json.dumps({"url": url, "topics": ["alarms", "deploys"]}).encode()
    for _ in range(30):
        try:
            req = urllib.request.Request(f"{URL}/v1/subscriptions", data=body, method="POST",
                                         headers={"Authorization": f"Bearer {KEY}", "Content-Type": "application/json"})
            with urllib.request.urlopen(req, timeout=10) as r:
                print("webhook registered", json.loads(r.read()), flush=True)
                return
        except OSError as e:
            print("webhook registration retry:", e, flush=True)
            time.sleep(2)


class Handler(BaseHTTPRequestHandler):
    def reply(self, code, data):
        b = json.dumps(data).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def do_GET(self):
        if self.path == "/health":
            return self.reply(200, {"ok": True, "subscribed": bool(KEY)})
        if self.path == "/received":
            return self.reply(200, received)
        self.reply(404, {"error": "not found"})

    def do_POST(self):
        if self.path != "/webhook":
            return self.reply(404, {"error": "not found"})
        body = self.rfile.read(int(self.headers.get("Content-Length") or 0))
        ts, sig = self.headers.get("X-OC-Timestamp", ""), self.headers.get("X-OC-Signature", "")
        want = "sha256=" + hmac.new(KEY.encode(), ts.encode() + b"." + body, hashlib.sha256).hexdigest()
        if not KEY or not hmac.compare_digest(want, sig) or abs(time.time() - int(ts or 0)) > 300:
            received["rejected"] += 1
            return self.reply(401, {"error": "bad signature"})
        received["webhook"] = (received["webhook"] + [json.loads(body)])[-50:]
        self.reply(200, {"ok": True})

    def log_message(self, *a):
        pass


if __name__ == "__main__":
    if KEY:
        threading.Thread(target=follow_stream, daemon=True).start()
        if secret("WEBHOOK_URL"):
            threading.Thread(target=register_webhook, args=(secret("WEBHOOK_URL"),), daemon=True).start()
    ThreadingHTTPServer(("0.0.0.0", int(os.environ.get("PORT", "8080"))), Handler).serve_forever()
