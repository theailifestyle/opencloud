"""Test-only HTTPS git server (smart HTTP via git http-backend) so e2e can deploy the examples/ apps."""
import http.server, os, ssl, subprocess, sys
root, cert, key = sys.argv[1:4]

class H(http.server.BaseHTTPRequestHandler):
    def run(self):
        path, _, query = self.path.partition("?")
        body = self.rfile.read(int(self.headers.get("Content-Length") or 0))
        env = dict(os.environ, GIT_PROJECT_ROOT=root, GIT_HTTP_EXPORT_ALL="1", PATH_INFO=path, QUERY_STRING=query,
                   REQUEST_METHOD=self.command, CONTENT_TYPE=self.headers.get("Content-Type", ""),
                   HTTP_CONTENT_ENCODING=self.headers.get("Content-Encoding", ""))
        out = subprocess.run(["git", "http-backend"], input=body, env=env, capture_output=True).stdout
        head, _, data = out.partition(b"\r\n\r\n")
        status = 200
        hdrs = []
        for line in head.decode().split("\r\n"):
            k, _, v = line.partition(":")
            if k.lower() == "status":
                status = int(v.split()[0])
            elif k:
                hdrs.append((k, v.strip()))
        self.send_response(status)
        for k, v in hdrs:
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)
    do_GET = do_POST = run

srv = http.server.ThreadingHTTPServer(("0.0.0.0", 443), H)
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain(cert, key)
srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
srv.serve_forever()
