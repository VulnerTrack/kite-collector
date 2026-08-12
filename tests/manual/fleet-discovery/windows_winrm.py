"""Minimal WinRM/WS-Man endpoint used only by the fleet-discovery lab."""

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class WinRMHandler(BaseHTTPRequestHandler):
    server_version = "Microsoft-HTTPAPI/2.0"
    sys_version = ""

    def _reply(self) -> None:
        body = b"<wsmanfault>Authentication required</wsmanfault>"
        self.send_response(401)
        self.send_header("Content-Type", "application/soap+xml;charset=UTF-8")
        self.send_header("WWW-Authenticate", "Negotiate")
        self.send_header("Server", "Microsoft-HTTPAPI/2.0")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    do_GET = _reply
    do_POST = _reply
    do_OPTIONS = _reply

    def log_message(self, message: str, *args: object) -> None:
        print(f"winrm: {self.client_address[0]} - {message % args}", flush=True)


ThreadingHTTPServer(("0.0.0.0", 5985), WinRMHandler).serve_forever()
