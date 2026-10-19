"""Tiny OpenAI-compatible mock provider for tests. Requires a fixed test key; echoes the model id."""
import json, os
from http.server import BaseHTTPRequestHandler, HTTPServer

KEY = os.environ.get("MOCK_KEY", "mock-test-key")


class H(BaseHTTPRequestHandler):
    def do_POST(self):
        if self.headers.get("Authorization") != "Bearer " + KEY:
            self.send_response(401); self.end_headers(); return
        body = json.loads(self.rfile.read(int(self.headers.get("Content-Length") or 0)))
        out = json.dumps({"object": "chat.completion", "model": body["model"],
                          "choices": [{"index": 0, "finish_reason": "stop", "message": {"role": "assistant", "content": "mock reply from " + body["model"]}}],
                          "usage": {"prompt_tokens": 7, "completion_tokens": 5, "total_tokens": 12}}).encode()
        self.send_response(200); self.send_header("Content-Type", "application/json"); self.send_header("Content-Length", str(len(out))); self.end_headers(); self.wfile.write(out)

    def log_message(self, *a):
        pass


HTTPServer(("0.0.0.0", 9000), H).serve_forever()
