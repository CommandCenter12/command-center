#!/usr/bin/env python3
"""Local bridge: the Command Center page asks http://localhost:8765/ for the printer's status.
Only listens on this Mac (127.0.0.1). Caches each reading for 5 seconds."""
import json, sys, os, time
from http.server import BaseHTTPRequestHandler, HTTPServer
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from printer_status import read_printer

PORT = 8765
_cache = {'t': 0, 'body': None}

class H(BaseHTTPRequestHandler):
    def _cors(self):
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Private-Network', 'true')
        self.send_header('Access-Control-Allow-Methods', 'GET, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', '*')

    def do_OPTIONS(self):
        self.send_response(204); self._cors(); self.end_headers()

    def do_GET(self):
        if time.time() - _cache['t'] > 5 or _cache['body'] is None:
            try:
                body = json.dumps(read_printer())
                _cache.update(t=time.time(), body=body)
            except Exception as e:
                body = json.dumps({'error': f'printer did not answer: {e}'})
                self.send_response(503); self.send_header('Content-Type', 'application/json'); self._cors(); self.end_headers()
                self.wfile.write(body.encode()); return
        self.send_response(200); self.send_header('Content-Type', 'application/json'); self._cors(); self.end_headers()
        self.wfile.write(_cache['body'].encode())

    def log_message(self, *a):
        pass

if __name__ == '__main__':
    HTTPServer(('127.0.0.1', PORT), H).serve_forever()
