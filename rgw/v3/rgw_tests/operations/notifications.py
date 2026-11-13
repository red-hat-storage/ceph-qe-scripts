"""Owned HTTP notification receiver; no external broker is required."""

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class Notifications:
    def __init__(self, bind_host, advertise_host):
        self.records = []
        self.lock = threading.Lock()
        receiver = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                self.connection.settimeout(5)
                try:
                    size = int(self.headers.get("Content-Length", "0"))
                    if not 0 < size <= 1024 * 1024:
                        raise ValueError("invalid payload length")
                    receiver.accept(self.rfile.read(size))
                except (ValueError, OSError, TypeError, KeyError):
                    self.send_error(400)
                    return
                self.send_response(200)
                self.end_headers()

            def log_message(self, *_args):
                pass

        self.server = ThreadingHTTPServer((bind_host, 0), Handler)
        self.server.daemon_threads = True
        self.url = f"http://{advertise_host}:{self.server.server_port}"
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def accept(self, body):
        data = json.loads(body)
        if "Message" in data:
            data = json.loads(data["Message"])
        records = data["Records"]
        if not isinstance(records, list) or not all(
            isinstance(r, dict) for r in records
        ):
            raise ValueError("Records must be a list of objects")
        with self.lock:
            self.records.extend(records)

    def events(self, bucket):
        with self.lock:
            return [
                r
                for r in self.records
                if r.get("s3", {}).get("bucket", {}).get("name") == bucket
            ]

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)
