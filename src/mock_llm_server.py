import json
from http.server import BaseHTTPRequestHandler, HTTPServer


class MockHandler(BaseHTTPRequestHandler):
    def _send(self, payload, status=200):
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        raw_body = self.rfile.read(length) if length else b"{}"
        try:
            req = json.loads(raw_body.decode("utf-8"))
        except json.JSONDecodeError:
            req = {}

        if self.path.endswith("/chat/completions"):
            response_format = req.get("response_format", {})
            wants_json = response_format.get("type") == "json_object"

            if wants_json:
                content = json.dumps(
                    {
                        "summary": "Synthetic SOC alert for staging e2e test.",
                        "confidence": 91,
                        "risk_level": "high",
                        "ai_confidence": 0.91,
                        "mitre_ttps": ["T1190", "T1071"],
                        "attack_type": "Suspicious Activity",
                        "severity": "High",
                        "remediation": "Isolate host and block malicious source.",
                        "indicators": {"ipv4": ["203.0.113.9"], "domains": [], "urls": []},
                        "cve_ids": []
                    }
                )
            else:
                content = "normalized"

            self._send({"choices": [{"message": {"content": content}}]})
            return

        if self.path.endswith("/embeddings"):
            self._send({"data": [{"embedding": [0.0] * 1536}]})
            return

        self._send({"error": "not found"}, status=404)

    def log_message(self, fmt, *args):
        return


if __name__ == "__main__":
    server = HTTPServer(("0.0.0.0", 18000), MockHandler)
    server.serve_forever()
