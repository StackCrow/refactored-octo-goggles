# 密码管理器 - 数据同步服务器
# 用法: python server.py
# 电脑访问 http://localhost:8080
# 手机访问 http://电脑IP:8080

import http.server
import json
import os
import socketserver

PORT = 8080
ROOT = os.path.dirname(os.path.abspath(__file__))
BASE_DIR = ROOT
DATA_FILE = os.path.join(ROOT, 'data.json')

class Handler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=BASE_DIR, **kwargs)

    def do_GET(self):
        if self.path == '/api/data':
            try:
                with open(DATA_FILE, 'r', encoding='utf-8') as f:
                    data = f.read()
            except FileNotFoundError:
                data = '[]'
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            self.wfile.write(data.encode('utf-8'))
        else:
            super().do_GET()

    def do_POST(self):
        if self.path == '/api/data':
            content_length = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(content_length)
            try:
                parsed = json.loads(body)
                with open(DATA_FILE, 'w', encoding='utf-8') as f:
                    json.dump(parsed, f, ensure_ascii=False, indent=2)
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Access-Control-Allow-Origin', '*')
                self.end_headers()
                self.wfile.write(b'{"ok":true}')
            except Exception as e:
                self.send_response(400)
                self.end_headers()
                self.wfile.write(json.dumps({'error': str(e)}).encode())
        else:
            self.send_response(404)
            self.end_headers()

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.end_headers()

if __name__ == '__main__':
    os.chdir(BASE_DIR)
    with socketserver.TCPServer(("", PORT), Handler) as httpd:
        print(f'服务器已启动: http://localhost:{PORT}')
        print(f'手机访问: http://<电脑IP>:{PORT}')
        print('按 Ctrl+C 停止')
        httpd.serve_forever()
