"""Tiny SMTP sink for tests (no TLS, no auth). Saves each message to <dir>/mail-N.eml."""
import socketserver, sys
from pathlib import Path

OUT = Path(sys.argv[1] if len(sys.argv) > 1 else "/out")


class H(socketserver.StreamRequestHandler):
    def say(self, s):
        self.wfile.write((s + "\r\n").encode())

    def handle(self):
        self.say("220 mock-smtp ready")
        data, rcpt = None, []
        while True:
            line = self.rfile.readline()
            if not line:
                return
            if data is not None:
                if line in (b".\r\n", b".\n"):
                    n = len(list(OUT.glob("mail-*.eml"))) + 1
                    (OUT / f"mail-{n}.eml").write_bytes(b"".join(data))
                    print("stored mail", n, "for", rcpt, flush=True)
                    data = None
                    self.say("250 OK")
                else:
                    data.append(line[1:] if line.startswith(b"..") else line)
                continue
            cmd = line.decode(errors="replace").strip().upper()
            if cmd.startswith(("EHLO", "HELO")):
                self.say("250 mock-smtp")
            elif cmd.startswith("RCPT"):
                rcpt.append(cmd)
                self.say("250 OK")
            elif cmd.startswith(("MAIL", "RSET", "NOOP")):
                self.say("250 OK")
            elif cmd == "DATA":
                data = []
                self.say("354 end with .")
            elif cmd == "QUIT":
                self.say("221 bye")
                return
            else:
                self.say("502 not implemented")


if __name__ == "__main__":
    OUT.mkdir(parents=True, exist_ok=True)
    socketserver.ThreadingTCPServer.allow_reuse_address = True
    socketserver.ThreadingTCPServer(("0.0.0.0", 25), H).serve_forever()
