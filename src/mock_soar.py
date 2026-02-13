from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import sys

class SimpleHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length)
        
        try:
            data = json.loads(post_data)
        except:
            data = {"raw": post_data.decode('utf-8')}
        
        print("\n\n" + "="*50, flush=True)
        print("  [SOAR SYSTEM] RECEIVED ALERT FROM OPENSEARCH!  ", flush=True)
        print(f"  Payload Received: {json.dumps(data, indent=2)}", flush=True)
        print("  Action: Blocking IP address via Firewall API...", flush=True)
        print("="*50 + "\n", flush=True)
        
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"Alert Received")
        
        # 確保 stdout 被清空
        sys.stdout.flush()

    # 把一般的 Access Log 關掉，讓畫面乾淨一點
    def log_message(self, format, *args):
        pass

if __name__ == "__main__":
    server = HTTPServer(('0.0.0.0', 5000), SimpleHandler)
    print("🛡️  Mock SOAR Server listening on port 5000... (Unbuffered Mode)", flush=True)
    server.serve_forever()