import json
from http.server import BaseHTTPRequestHandler, HTTPServer

HOST = "0.0.0.0"
PORT = 8000

def _json(handler, status, obj):
    body = json.dumps(obj).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json")
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        # simple health
        if self.path.startswith("/health"):
            return _json(self, 200, {"status": "ok"})
        # allow quick probe
        if self.path.startswith("/v1/embeddings"):
            return _json(self, 200, {"data": [{"embedding": [0.0, 0.1, 0.2], "index": 0}], "model": "mock-embed"})
        return _json(self, 404, {"error": "not found"})

    def do_POST(self):
        # read body but ignore content for deterministic response
        length = int(self.headers.get("Content-Length", "0") or "0")
        _ = self.rfile.read(length) if length > 0 else b"{}"

        if self.path.startswith("/v1/embeddings"):
            return _json(self, 200, {"data": [{"embedding": [0.0, 0.1, 0.2], "index": 0}], "model": "mock-embed"})

        if self.path.startswith("/v1/chat/completions"):
            # Return deterministic SOC-style JSON inside message content
            payload = {
                "risk_level": "medium",
                "mitre_ttps": ["T1078", "T1059"],
                "ai_confidence": 0.82,
                "summary": "Mock analysis output for stable tests."
            }
            return _json(self, 200, {
                "id": "mockchatcmpl-1",
                "object": "chat.completion",
                "choices": [{
                    "index": 0,
                    "message": {"role": "assistant", "content": json.dumps(payload)},
                    "finish_reason": "stop"
                }]
            })

        return _json(self, 404, {"error": "not found"})

    def log_message(self, format, *args):
        # silence default logs
        return

if __name__ == "__main__":
    HTTPServer((HOST, PORT), Handler).serve_forever()
