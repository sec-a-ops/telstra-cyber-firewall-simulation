# www.theforage.com - Telstra Cyber Task 3
# Firewall Server Handler

from http.server import BaseHTTPRequestHandler, HTTPServer
import urllib.parse

host = "localhost"
port = 8000

# Malicious indicators related to Tomcat WAR/JSP RCE
BLOCKED_PATTERNS = [
    "class.module.classloader",
    "resources.context.parent.pipeline",
    "runtime().exec",
    "tomcatwar",
    "webapps/root",
    "<%",
    "%{",
]

SUSPICIOUS_HEADERS = ["c1", "c2", "suffix"]


def block_request(self):
    print("[!] Blocking malicious request")
    self.send_response(403)
    self.send_header("content-type", "application/json")
    self.end_headers()
    self.wfile.write(b'{"status": "blocked"}')


def handle_request(self):
    content_length = int(self.headers.get("Content-Length", 0))
    body = ""

    if content_length > 0:
        body = self.rfile.read(content_length).decode(errors="ignore")
        body = urllib.parse.unquote(body).lower()

    # Check body for malicious patterns
    for pattern in BLOCKED_PATTERNS:
        if pattern in body:
            return block_request(self)

    # Check headers for suspicious values
    for header in self.headers:
        if header.lower() in SUSPICIOUS_HEADERS:
            return block_request(self)

    # Allow request
    self.send_response(200)
    self.send_header("content-type", "application/json")
    self.end_headers()
    self.wfile.write(b'{"status": "allowed"}')


class ServerHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        handle_request(self)

    def do_POST(self):
        handle_request(self)

    def log_message(self, format, *args):
        # Disable default logging
        return


if __name__ == "__main__":
    server = HTTPServer((host, port), ServerHandler)
    print("[+] Firewall Server")
    print("[+] HTTP Web Server running on: %s:%s" % (host, port))

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass

    server.server_close()
    print("[+] Server terminated. Exiting...")
